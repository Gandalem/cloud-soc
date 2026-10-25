Unicode true
!include "MUI2.nsh"
!ifndef SOURCE
!error "SOURCE must point to the reviewed deploy/agents directory"
!endif
!ifndef OUTFILE
!error "OUTFILE is required"
!endif
Name "Cloud SOC Agent"
OutFile "${OUTFILE}"
RequestExecutionLevel admin
SetCompressor zlib
InstallDir "$EXEDIR"
!define MUI_DIRECTORYPAGE_TEXT_TOP "포털에서 받은 장치 설치 ZIP을 모두 푼 폴더를 선택하세요. 수집 키를 입력할 필요는 없습니다."
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "Korean"
Section "Register device"
  IfFileExists "$INSTDIR\registration.json" +3 0
  MessageBox MB_ICONSTOP "장치 등록 정보가 없습니다. 포털에서 장치 설치 묶음을 받으세요."
  Abort
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=bootstrap-windows.ps1 "${SOURCE}\bootstrap-windows.ps1"
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -File "$PLUGINSDIR\bootstrap-windows.ps1" -Action install -BundleDirectory "$INSTDIR"' $0
  IntCmp $0 0 +3
  MessageBox MB_ICONSTOP "설치를 완료하지 못했습니다. 기존 자료는 초기화하지 않았습니다."
  Abort
SectionEnd
