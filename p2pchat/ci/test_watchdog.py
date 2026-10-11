"""Fast watchdog contract tests. Windows Job branch runs natively in CI."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("watchdog.py")


class WatchdogTests(unittest.TestCase):
    def invoke(self, source, timeout=3):
        return subprocess.run([sys.executable, str(SCRIPT), "--timeout", str(timeout), "--",
                               sys.executable, "-u", "-c", source],
                              text=True, capture_output=True, timeout=12)

    def test_success_output_and_exit(self):
        result = self.invoke("print('LAST_TEST_SUCCESS', flush=True)")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("LAST_TEST_SUCCESS", result.stdout)
        self.assertIn("WATCHDOG_FINISHED exitCode=0", result.stdout)

    def test_failure_preserves_exit(self):
        result = self.invoke("import sys; print('LAST_TEST_FAILURE', flush=True); sys.exit(7)")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("LAST_TEST_FAILURE", result.stdout)
        self.assertIn("WATCHDOG_FINISHED exitCode=7", result.stdout)

    def test_timeout_preserves_dump_and_fails(self):
        before = time.monotonic()
        result = self.invoke("import faulthandler,time; print('LAST_TEST_HUNG', flush=True); "
                             "faulthandler.dump_traceback_later(.15); time.sleep(60)", timeout=2)
        self.assertEqual(result.returncode, 124, result.stderr)
        self.assertIn("LAST_TEST_HUNG", result.stdout)
        self.assertIn("WATCHDOG_TIMEOUT", result.stdout)
        self.assertIn("Timeout", result.stderr)
        self.assertLess(time.monotonic() - before, 8)

    def test_timeout_reaps_descendant_that_inherits_output(self):
        # capture_output cannot finish until descendant dies and closes inherited
        # handles. A leaked grandchild would also create this delayed marker.
        with tempfile.TemporaryDirectory() as folder:
            marker = str(Path(folder) / "escaped")
            child = f"import time,pathlib; time.sleep(3); pathlib.Path({marker!r}).write_text('LEAK'); time.sleep(60)"
            source = (f"import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',{child!r}]); "
                      "print('CHILD_STARTED', flush=True); time.sleep(60)")
            result = self.invoke(source, timeout=2)
            self.assertEqual(result.returncode, 124, result.stderr)
            self.assertIn("CHILD_STARTED", result.stdout)
            time.sleep(3.1)
            self.assertFalse(Path(marker).exists(), "watchdog leaked child process")

    def test_normal_exit_also_reaps_orphan(self):
        source = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print('PARENT_DONE',flush=True)"
        result = self.invoke(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PARENT_DONE", result.stdout)

    def test_bootstrap_fails_closed_without_parent_gate(self):
        result = subprocess.run([sys.executable, str(SCRIPT), "--bootstrap", '["not-a-real-command"]'],
                                input="", text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 125)


if __name__ == "__main__":
    unittest.main()
