using System;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CloudSoc.Native {
internal static class Program {
    internal const string Help = "Cloud SOC Agent\r\n설치: --install [--bundle <압축을 푼 폴더>]\r\n상태: --status / 시작: --start / 중지: --stop\r\n제거: --uninstall (큐·설정 보존)\r\n자료도 삭제: --uninstall --purge\r\n도움말: --help\r\n관리자 승인은 필요합니다. PowerShell 실행 정책은 변경하지 않습니다.\r\n설치 수신 확인은 일반 로그·탐지 완료와 구분됩니다.\r\n로컬 제거는 서버 키 폐기가 아닙니다. 포털의 장치 종료를 사용하세요.\r\n새 설치: 자료까지 삭제 → 포털에서 기존 장치 접근 차단 → 새 장치 등록 → 새 설치 묶음 실행.\r\n새 설치는 이전 키·큐·읽기 위치를 복원하지 않습니다. 기존 로그를 다시 수집할 수 있습니다.";
    [STAThread] internal static int Main(string[] args) {
        try {
            string action = null, bundle = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\'); bool lab = false, purge = false, quiet = false;
            for (int n = 0; n < args.Length; n++) {
                switch (args[n]) {
                    case "--help": case "/?": MessageBox.Show(Help, "Cloud SOC Agent"); return 0;
                    case "--lab": lab = true; break;
                    case "--quiet": quiet = true; break;
                    case "--purge": purge = true; break;
                    case "--bundle": Contract.Require(++n < args.Length, "bundle_required"); bundle = Path.GetFullPath(args[n]); break;
                    case "--install": case "--status": case "--start": case "--stop": case "--uninstall": case "--refresh": Contract.Require(action == null, "one_action_required"); action = args[n].Substring(2); break;
                    default: throw new ArgumentException("unknown_argument");
                }
            }
            Contract.Require(!purge || action == "uninstall", "purge_requires_uninstall");
            Contract.Require(Environment.Is64BitProcess && Environment.OSVersion.Version.Major >= 10, "windows_x64_required");
            using (var framework = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full")) Contract.Require(framework != null && Convert.ToInt32(framework.GetValue("Release", 0)) >= 528040, "net48_required");
            Contract.Require(new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator), "administrator_required");
#if NATIVE_LAB
            // A separately compiled artifact; a production build cannot enable this option.
            if (action == "refresh") lab = File.Exists(Path.Combine(Installer.StateRoot, "state.json")) && Object.Equals(Installer.Load()["lab"], true);
            Contract.Require(lab, "lab_opt_in_required");
#else
            Contract.Require(!lab, "lab_not_available"); Safe.Signed(typeof(Program).Assembly.Location);
#endif
            System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls12;
            System.Net.ServicePointManager.CheckCertificateRevocationList = true;
            if (action != null) return Execute(action, bundle, lab, purge, quiet ? (Action<string>)(message => Console.WriteLine(message)) : message => MessageBox.Show(message, "Cloud SOC Agent"));
            Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false); Application.Run(new ManagerForm(bundle, lab)); return 0;
        } catch (Exception error) { Error(error, !args.Contains("--quiet")); return 1; }
    }
    internal static int Execute(string action, string bundle, bool lab, bool purge, Action<string> report) {
        using (var mutex = new Mutex(false, @"Global\Cloud-SOC-Bundle-Install")) {
            bool held = false;
            try { try { held = mutex.WaitOne(0); } catch (AbandonedMutexException) { held = true; }
                Contract.Require(held, "another_operation_active"); var installer = new Installer(report);
                if (action == "install") installer.Install(bundle, lab); else installer.Manage(action, purge); return 0;
            } finally { if (held) mutex.ReleaseMutex(); }
        }
    }
    internal static string Error(Exception error, bool show) {
        // Do not print exception bodies, upstream response/config/path/credentials.
        string code = error is System.IO.InvalidDataException || error is System.IO.IOException ? error.Message : error.GetType().Name;
        if (!System.Text.RegularExpressions.Regex.IsMatch(code, @"\A[a-z_0-9]{1,70}\z")) code = error.GetType().Name;
        string message = "작업을 완료하지 못했습니다 (" + code + "). 기존 상태와 큐를 보존합니다. 포털 장치 상태와 관리자용 설치 문서를 확인하세요.";
        if (code == "installation_state_missing") message = "설치 기록을 찾을 수 없습니다. 기존 수집기와 자료를 확인하고 설치 묶음 또는 관리 도구를 사용하세요. 수집기 자료는 변경하지 않았습니다.";
        if (code == "reinstall_preserved_data") message = "보존한 수집기 자료가 있습니다. 자료를 삭제하고 새로 설치하려면 기존 관리 프로그램에서 '수집기 자료까지 삭제'를 선택하세요. 미전송 자료와 읽기 위치는 복원되지 않습니다.";
        if (code == "reinstall_new_registration_required" || code == "reinstall_use_new_bundle") message = "포털에서 새 장치를 등록하고 새로 다운로드한 설치 묶음을 실행하세요. 이전 설치 정보는 재사용하지 않습니다.";
        Console.Error.WriteLine("cloud_soc_error={0} hresult={1}", code, error.HResult);
        try {
            if (Directory.Exists(Installer.StateRoot)) {
                Safe.CheckAcl(Installer.StateRoot);
                Safe.Json(Path.Combine(Installer.StateRoot, "diagnostic.json"), Contract.Map("schema", 1, "error", code, "type", error.GetType().Name, "hresult", error.HResult, "at", DateTime.UtcNow.ToString("o")));
            }
        } catch { /* Diagnostic failure must not turn an unsuccessful operation into success. */ }
        if (show) MessageBox.Show(message, "Cloud SOC Agent", MessageBoxButtons.OK, MessageBoxIcon.Error); return message;
    }
}
internal sealed class ManagerForm : Form {
    private readonly TextBox output = new TextBox { Multiline = true, ReadOnly = true, Dock = DockStyle.Fill, ScrollBars = ScrollBars.Vertical };
    private readonly FlowLayoutPanel commands = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 88, AutoSize = false };
    private readonly string bundle; private readonly bool lab;
    internal ManagerForm(string bundle, bool lab) {
        this.bundle = bundle; this.lab = lab; Text = "Cloud SOC Agent"; Size = new Size(760, 420); MinimumSize = new Size(650, 350); StartPosition = FormStartPosition.CenterScreen;
        Controls.Add(output); Controls.Add(commands);
        foreach (var pair in new[] {new[] {"설치", "install"}, new[] {"상태 확인", "status"}, new[] {"수집 시작", "start"}, new[] {"수집 중지", "stop"}, new[] {"제거", "uninstall"}, new[] {"도움말", "help"}}) {
            var button = new Button { Text = pair[0], Width = 100, Height = 32 }; string action = pair[1]; button.Click += delegate { Run(action); }; commands.Controls.Add(button);
        }
        output.Text = "설치는 수집기 등록과 중앙 수신 확인까지 진행합니다.\r\n제거는 기본적으로 로컬 큐를 보존합니다. 서버 키는 포털에서 별도로 폐기하세요.\r\n";
    }
    private async void Run(string action) {
        if (action == "help") { MessageBox.Show(Program.Help, Text); return; }
        bool purge = false;
        if (action == "uninstall") {
            using (var choice = new RemovalChoice()) {
                if (choice.ShowDialog(this) != DialogResult.OK) return;
                purge = choice.Purge;
            }
            if (purge && MessageBox.Show("설정·키·미전송 자료·읽기 위치를 삭제합니다. 되돌릴 수 없으며 기존 로그를 다시 수집할 수 있습니다. 삭제할까요?\r\n서버 키는 포털에서 별도로 폐기하세요.", Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
        }
        commands.Enabled = false; ControlBox = false;
        try { await Task.Run(() => Program.Execute(action, bundle, lab, purge, message => BeginInvoke((Action)(() => output.AppendText(message + "\r\n"))))); }
        catch (Exception error) { output.AppendText(Program.Error(error, false) + "\r\n"); }
        finally { commands.Enabled = true; ControlBox = true; }
    }
}
internal sealed class RemovalChoice : Form {
    private readonly RadioButton keep = new RadioButton { Text = "자료 보존 후 제거 (기본)", Checked = true, AutoSize = true };
    private readonly RadioButton remove = new RadioButton { Text = "수집기 자료까지 삭제", AutoSize = true };
    internal bool Purge { get { return remove.Checked; } }
    internal RemovalChoice() {
        Text = "에이전트 제거"; ClientSize = new Size(530, 235); FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false; MinimizeBox = false; StartPosition = FormStartPosition.CenterParent;
        var panel = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.TopDown, Padding = new Padding(14), WrapContents = false };
        panel.Controls.Add(keep);
        panel.Controls.Add(new Label { Text = "설정·키·미전송 자료를 보존합니다. 새 설치로 자동 복원하지 않습니다.", AutoSize = true, Margin = new Padding(3, 3, 3, 16) });
        panel.Controls.Add(remove);
        panel.Controls.Add(new Label { Text = "설정·키·큐·읽기 위치를 삭제합니다. 중앙 로그·경보는 유지합니다.", AutoSize = true, Margin = new Padding(3, 3, 3, 16) });
        var buttons = new FlowLayoutPanel { AutoSize = true };
        var apply = new Button { Text = "계속", DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "취소", DialogResult = DialogResult.Cancel };
        buttons.Controls.Add(apply); buttons.Controls.Add(cancel); panel.Controls.Add(buttons); Controls.Add(panel);
        AcceptButton = cancel; CancelButton = cancel;
    }
}
}
