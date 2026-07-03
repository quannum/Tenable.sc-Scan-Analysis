import json
import logging
import os
import shutil
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from openpyxl import Workbook

from src.tenable_coverage_workflow.service_config import build_service_config
from src.tenable_coverage_workflow.service_runner import main as service_main


class ServiceConfigTests(unittest.TestCase):
    def _write_xlsx_source(self, path: Path) -> None:
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Networks"
        sheet.append(
            [
                "Site Code",
                "Site Name",
                "Region",
                "Target Type",
                "Scope Item",
                "VLAN Name",
                "VLAN ID",
            ]
        )
        sheet.append(
            ["NYC01", "New York Office", "US East", "PUBLIC", "203.0.113.0/26"]
        )
        sheet.append(
            [
                "NYC01",
                "New York Office",
                "US East",
                "PRIVATE_SUPERNET",
                "10.1.0.0/16",
                None,
                None,
            ]
        )
        sheet.append(
            [
                "NYC01",
                "New York Office",
                "US East",
                "VLAN",
                "10.1.32.0/22",
                "End User",
                130,
            ]
        )
        workbook.save(path)

    def test_service_config_loads_yaml_and_transport_controls(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "service_yaml_config_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)
        temp_path.mkdir(parents=True)
        try:
            config_file = temp_path / "service.yaml"
            config_file.write_text(
                "\n".join(
                    [
                        "tenable_coverage_workflow_service:",
                        "  source_xlsx_file: sites.xlsx",
                        "  mode: offline",
                        "  scan_json_dir: scans",
                        "  asset_json_dir: assets",
                        "  sc_timeout_seconds: 45",
                        "  sc_retries: 4",
                        "  sc_backoff_seconds: 2.0",
                        "  sc_ssl_verify: true",
                    ]
                ),
                encoding="utf-8",
            )

            config = build_service_config(["--config-file", str(config_file)])

            self.assertEqual(config.source_xlsx_file, "sites.xlsx")
            self.assertEqual(str(config.source_config.xlsx_file), "sites.xlsx")
            self.assertEqual(config.sc_timeout_seconds, 45)
            self.assertEqual(config.sc_retries, 4)
            self.assertEqual(config.sc_backoff_seconds, 2.0)
            self.assertTrue(config.sc_ssl_verify)
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_service_config_loads_from_toml(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "service_config_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            config_file = temp_path / "service.toml"
            config_file.write_text(
                (
                    "[tenable_coverage_workflow_service]\n"
                    'job_name = "nightly coverage"\n'
                    'subnet_as_code_method = "get_sites"\n'
                    f'output_dir = "{(temp_path / "output").as_posix()}"\n'
                    'run_id_prefix = "nightly-"\n'
                    'dry_run = true\n'
                    'mode = "offline"\n'
                    'scan_json_dir = "scans"\n'
                    'asset_json_dir = "assets"\n'
                    'include_keywords = "Discovery,Assessment"\n'
                    'exclude_keywords = "Deprecated"\n'
                    'match_all_include = false\n'
                    'case_sensitive = false\n'
                    'filter_disabled_mode = "ALL"\n'
                    'log_level = "INFO"\n'
                ),
                encoding="utf-8",
            )

            config = build_service_config(["--config-file", str(config_file)])

            self.assertEqual(config.job_name, "nightly coverage")
            self.assertEqual(config.subnet_as_code_method, "get_sites")
            self.assertEqual(config.source_config.subnet_as_code_method, "get_sites")
            self.assertEqual(config.run_id_prefix, "nightly-")
            self.assertEqual(config.include_keywords, ["Discovery", "Assessment"])
            self.assertEqual(config.exclude_keywords, ["Deprecated"])
            self.assertEqual(
                config.latest_summary_file,
                temp_path / "output" / "latest_run.json",
            )
            self.assertEqual(config.lock_file, temp_path / "output" / "scheduler.lock")
            self.assertEqual(config.stale_lock_timeout_seconds, 21600)
            self.assertEqual(config.log_format, "text")
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)


class ScheduledServiceTests(unittest.TestCase):
    def test_service_main_writes_latest_summary_and_run_artifacts(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_case"

        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            source_xlsx = temp_path / "expected_ranges.xlsx"
            ServiceConfigTests()._write_xlsx_source(source_xlsx)
            scan_dir = temp_path / "scans"
            asset_dir = temp_path / "assets"
            output_dir = temp_path / "output"
            scan_dir.mkdir()
            asset_dir.mkdir()

            for payload in [
                {
                    "id": 1,
                    "name": "US_East_Discovery",
                    "ipList": "10.1.0.0/16,10.3.0.0/16",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
                {
                    "id": 2,
                    "name": "US_East_Server_Assessment",
                    "ipList": "10.1.16.0/24",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
            ]:
                (scan_dir / f"{payload['id']}_scan.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )

            exit_code = service_main(
                [
                    "--job-name",
                    "nightly-coverage",
                    "--source-xlsx-file",
                    str(source_xlsx),
                    "--output-dir",
                    str(output_dir),
                    "--run-id-prefix",
                    "svc-",
                    "--mode",
                    "offline",
                    "--scan-json-dir",
                    str(scan_dir),
                    "--asset-json-dir",
                    str(asset_dir),
                ]
            )

            self.assertEqual(exit_code, 0)
            latest_summary = json.loads(
                (output_dir / "latest_run.json").read_text(encoding="utf-8")
            )
            self.assertEqual(latest_summary["status"], "SUCCESS")
            self.assertEqual(latest_summary["job_name"], "nightly-coverage")
            run_summary = latest_summary["run_summary"]
            self.assertTrue(run_summary["run_id"].startswith("svc-"))
            self.assertEqual(latest_summary["run_id"], run_summary["run_id"])
            self.assertIn("started_at", latest_summary)
            self.assertIn("completed_at", latest_summary)
            self.assertEqual(run_summary["authoritative_units_processed"], 1)
            self.assertEqual(run_summary["authoritative_units_failed"], 0)
            self.assertIn("duration_seconds", run_summary)

            run_dir = Path(run_summary["output_directory"])
            self.assertTrue((run_dir / "audit.jsonl").exists())
            self.assertTrue((run_dir / "proposed_changes.csv").exists())
            self.assertTrue((run_dir / "proposed_changes.md").exists())
            self.assertTrue((run_dir / "run_summary.json").exists())
            self.assertFalse((output_dir / "scheduler.lock").exists())
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_service_main_returns_lock_conflict_code_when_lock_exists(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_lock_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            output_dir = temp_path / "output"
            output_dir.mkdir()
            lock_file = output_dir / "scheduler.lock"
            lock_file.write_text("locked", encoding="utf-8")

            with patch(
                "src.tenable_coverage_workflow.service_runner.run_detect_and_plan"
            ) as run_mock:
                exit_code = service_main(
                    [
                        "--job-name",
                        "nightly-coverage",
                        "--subnet-as-code-method",
                        "get_sites",
                        "--output-dir",
                        str(output_dir),
                        "--mode",
                        "offline",
                        "--scan-json-dir",
                        "scans",
                        "--asset-json-dir",
                        "assets",
                    ]
                )

            self.assertEqual(exit_code, 2)
            run_mock.assert_not_called()
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_service_main_recovers_stale_lock(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_stale_lock_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            output_dir = temp_path / "output"
            output_dir.mkdir()
            lock_file = output_dir / "scheduler.lock"
            lock_file.write_text(
                "job_name=nightly-coverage\npid=999999\n",
                encoding="utf-8",
            )
            os.utime(lock_file, (1, 1))

            with patch(
                "src.tenable_coverage_workflow.service_runner.run_detect_and_plan",
                return_value={
                    "run_id": "svc-stale",
                    "output_directory": str(output_dir / "runs" / "svc-stale"),
                },
            ) as run_mock:
                exit_code = service_main(
                    [
                        "--job-name",
                        "nightly-coverage",
                        "--subnet-as-code-method",
                        "get_sites",
                        "--output-dir",
                        str(output_dir),
                        "--mode",
                        "offline",
                        "--scan-json-dir",
                        "scans",
                        "--asset-json-dir",
                        "assets",
                    ]
                )

            self.assertEqual(exit_code, 0)
            run_mock.assert_called_once()
            self.assertFalse(lock_file.exists())
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_service_main_writes_running_state_before_work_execution(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_running_state_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            output_dir = temp_path / "output"
            output_dir.mkdir()
            latest_summary_file = output_dir / "latest_run.json"

            def fake_run(config):
                latest_summary = json.loads(
                    latest_summary_file.read_text(encoding="utf-8")
                )
                self.assertEqual(latest_summary["status"], "RUNNING")
                self.assertEqual(latest_summary["job_name"], "nightly-coverage")
                self.assertEqual(
                    latest_summary["output_directory"],
                    str(output_dir / "runs" / latest_summary["run_id"]),
                )
                return {
                    "run_id": latest_summary["run_id"],
                    "output_directory": str(
                        output_dir / "runs" / latest_summary["run_id"]
                    ),
                }

            with patch(
                "src.tenable_coverage_workflow.service_runner.run_detect_and_plan",
                side_effect=fake_run,
            ):
                exit_code = service_main(
                    [
                        "--job-name",
                        "nightly-coverage",
                        "--subnet-as-code-method",
                        "get_sites",
                        "--output-dir",
                        str(output_dir),
                        "--mode",
                        "offline",
                        "--scan-json-dir",
                        "scans",
                        "--asset-json-dir",
                        "assets",
                    ]
                )

            self.assertEqual(exit_code, 0)
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)


class ServiceLoggingTests(unittest.TestCase):
    def test_service_can_emit_json_logs_with_run_context(self):
        from src.tenable_coverage_workflow.run_detect_and_plan import configure_logging

        stream = StringIO()
        with patch("sys.stderr", new=stream):
            configure_logging(
                "INFO",
                log_format="json",
                extra_context={"job_name": "nightly-coverage", "run_id": "svc-123"},
            )
            logging.getLogger("service.test").info("hello service log")

        payload = json.loads(stream.getvalue().strip())
        self.assertEqual(payload["level"], "INFO")
        self.assertEqual(payload["message"], "hello service log")
        self.assertEqual(payload["job_name"], "nightly-coverage")
        self.assertEqual(payload["run_id"], "svc-123")


if __name__ == "__main__":
    unittest.main()
