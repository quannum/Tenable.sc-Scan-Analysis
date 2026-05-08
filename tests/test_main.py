import logging
import shutil
import unittest
from pathlib import Path

from tenable_scan_analysis import main


class MainTests(unittest.TestCase):
    def test_configure_logging_writes_to_optional_log_file(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "main_logging_case"
        log_file = temp_path / "logs" / "run.log"
        if temp_path.exists():
            shutil.rmtree(temp_path)
        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            main.configure_logging("INFO", log_file=log_file)
            test_logger = main.logging.getLogger("test.logger")
            test_logger.warning("sample warning message")

            self.assertTrue(log_file.exists())
            contents = log_file.read_text(encoding="utf-8")
            self.assertIn("sample warning message", contents)
        finally:
            logging.shutdown()
            if temp_path.exists():
                shutil.rmtree(temp_path)


if __name__ == "__main__":
    unittest.main()
