import importlib
import json
import logging
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

main = importlib.import_module("src.cli.main")


class MainTests(unittest.TestCase):
    def tearDown(self):
        logging.shutdown()
        logging.basicConfig(level=logging.WARNING, force=True)

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

    def test_atomic_save_workbook_writes_final_output(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "atomic_save_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)
        temp_path.mkdir(parents=True, exist_ok=True)

        output_file = temp_path / "output" / "report.xlsx"

        class FakeWorkbook:
            def save(self, path):
                Path(path).write_bytes(b"fake-xlsx-content")

        try:
            main.atomic_save_workbook(FakeWorkbook(), output_file)
            self.assertTrue(output_file.exists())
            self.assertEqual(output_file.read_bytes(), b"fake-xlsx-content")

            temp_candidates = list(output_file.parent.glob("tenable-scan-*.xlsx"))
            self.assertEqual(temp_candidates, [])
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_configure_logging_json_format_writes_json_line(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "json_logging_case"
        log_file = temp_path / "logs" / "run.json.log"
        if temp_path.exists():
            shutil.rmtree(temp_path)
        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            main.configure_logging("INFO", log_file=log_file, log_format="json")
            logger = main.logging.getLogger("test.json")
            logger.info("hello json logging")

            lines = [
                line.strip()
                for line in log_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            payload = json.loads(lines[-1])
            self.assertEqual(payload["level"], "INFO")
            self.assertEqual(payload["logger"], "test.json")
            self.assertEqual(payload["message"], "hello json logging")
        finally:
            logging.shutdown()
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_main_returns_non_zero_on_runtime_failure(self):
        cfg = SimpleNamespace(
            log_level="INFO",
            log_file=None,
            log_format="text",
            mode="offline",
        )
        with (
            patch("src.cli.main.build_config", return_value=cfg),
            patch("src.cli.main.configure_logging"),
            patch(
                "src.cli.main.run_analysis",
                side_effect=RuntimeError("boom"),
            ),
        ):
            code = main.main([])

        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
