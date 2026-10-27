"""Build/run pure native contracts. Never installs on the test runner."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(sys.platform == 'win32', 'Windows inbox Framework compiler/runtime required')
class NativeContracts(unittest.TestCase):
    def test_native_input_archive_binding_and_unsigned_rejection(self):
        script = ROOT / 'deploy/agents/packaging/build.py'
        spec = importlib.util.spec_from_file_location('native_build_recipe', script)
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        compiler = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
        self.assertTrue(compiler.is_file(), 'No native compilation was performed: compiler missing')
        from cloud_soc.portal.windows_native import INPUTS
        with tempfile.TemporaryDirectory(prefix='soc-native-contracts-') as directory:
            executable = Path(directory) / 'native-contracts.exe'
            command = [str(compiler), '/nologo', '/target:exe', '/platform:x64', '/define:NATIVE_INSTALLER',
                       '/main:NativeInstallerTests', '/out:' + str(executable)]
            command += ['/reference:' + name for name in recipe.REFERENCES]
            command += [str(recipe.SOURCE / name) for name in INPUTS if name.endswith('.cs')]
            command.append(str(ROOT / 'deploy/agents/tests/native-installer-tests.cs'))
            result = subprocess.run(command, capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
            result = subprocess.run([str(executable)], capture_output=True, timeout=60)
            self.assertEqual(result.returncode, 0, (result.stdout + result.stderr).decode(errors='replace'))
            self.assertIn(b'native_contracts_passed=', result.stdout)
            print('\n'.join(line for line in result.stdout.decode(errors='replace').splitlines()
                            if line.startswith('native_')))


if __name__ == '__main__':
    unittest.main()
