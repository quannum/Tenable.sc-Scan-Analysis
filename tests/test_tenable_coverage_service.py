import json
import logging
import os
import shutil
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from src.tenable_coverage_workflow.service_config import build_service_config
from src.tenable_coverage_workflow.service_runner import main as service_main


class ServiceConfigTests(unittest.TestCase):
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
                    f'output_dir = "{(temp_path / "output").as_posix()}"\n'
                    'run_id_prefix = "nightly-"\n'
                    "dry_run = true\n"
                    'mode = "offline"\n'
                    'scan_json_dir = "scans"\n'
                    'asset_json_dir = "assets"\n'
                    'include_keywords = "Discovery,Assessment"\n'
                    'exclude_keywords = "Deprecated"\n'
                    "match_all_include = false\n"
                    "case_sensitive = false\n"
                    'filter_disabled_mode = "ALL"\n'
                    'log_level = "INFO"\n'
                ),
                encoding="utf-8",
            )

            config = build_service_config(["--config-file", str(config_file)])

            self.assertEqual(config.job_name, "nightly coverage")
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

    def test_service_config_supports_vlan_tag_grouping(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "service_grouping_config_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            config_file = temp_path / "service.toml"
            config_file.write_text(
                (
                    "[tenable_coverage_workflow_service]\n"
                    'mode = "offline"\n'
                    'scan_json_dir = "scans"\n'
                    'asset_json_dir = "assets"\n'
                    'grouping_mode = "vlan_tag"\n'
                    'grouping_vlan_tag_prefix = "vlan-"\n'
                    'grouping_tag_map = { vlan-mgmt = "NETWORK" }\n'
                ),
                encoding="utf-8",
            )

            config = build_service_config(["--config-file", str(config_file)])

            self.assertEqual(config.grouping_config.mode, "vlan_tag")
            self.assertEqual(config.grouping_config.vlan_tag_prefix, "vlan-")
            self.assertEqual(config.grouping_config.tag_map, {"vlan-mgmt": "NETWORK"})
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_service_config_prefers_tcw_transport_environment(self):
        env = {
            "TCW_SC_URL": "https://tcw.tenable.local",
            "SC_URL": "https://legacy.tenable.local",
            "TCW_SC_ACCESS_KEY": "tcw-access",
            "SC_ACCESS_KEY": "legacy-access",
            "TCW_SC_SECRET_KEY": "tcw-secret",
            "SC_SECRET_KEY": "legacy-secret",
            "TCW_SC_TIMEOUT_SECONDS": "45",
            "SC_TIMEOUT_SECONDS": "60",
        }
        with patch.dict(os.environ, env, clear=True):
            config = build_service_config(
                [
                    "--mode",
                    "live",
                ]
            )

        self.assertEqual(config.sc_url, "https://tcw.tenable.local")
        self.assertEqual(config.sc_access_key, "tcw-access")
        self.assertEqual(config.sc_secret_key, "tcw-secret")
        self.assertEqual(config.sc_timeout_seconds, 45)

    def test_service_config_rejects_no_dry_run(self):
        with self.assertRaises(SystemExit):
            build_service_config(
                [
                    "--mode",
                    "offline",
                    "--scan-json-dir",
                    "scans",
                    "--asset-json-dir",
                    "assets",
                    "--no-dry-run",
                ]
            )

    def test_service_config_help_hides_no_dry_run(self):
        from src.tenable_coverage_workflow.service_config import build_argument_parser

        help_text = build_argument_parser().format_help()

        self.assertIn("--dry-run", help_text)
        self.assertNotIn("--no-dry-run", help_text)
        self.assertNotIn("--subnet-as-code-method", help_text)
        self.assertNotIn("--source-desired-properties", help_text)
        self.assertNotIn("--source-address-type", help_text)

    def test_service_config_ignores_removed_source_environment_settings(self):
        env = {
            "SUBNET_AS_CODE_METHOD": "get_ipaddress",
            "SUBNET_AS_CODE_DESIRED_PROPERTIES": "site_code",
            "SUBNET_AS_CODE_ADDRESS_TYPE": "private",
        }
        with patch.dict(os.environ, env, clear=True):
            config = build_service_config(
                [
                    "--mode",
                    "offline",
                    "--scan-json-dir",
                    "scans",
                    "--asset-json-dir",
                    "assets",
                ]
            )

        self.assertIsNone(config.source_config.reference_id)
        self.assertIsNone(config.source_config.sites)
        self.assertIsNone(config.source_config.tags)


class ScheduledServiceTests(unittest.TestCase):
    @staticmethod
    def _subnet_module():
        class Module:
            @staticmethod
            def get_sites(**kwargs):
                return {
                    "site_definition": [
                        {
                            "site_code": "NYC01",
                            "site_name": "New York Office",
                            "region": "US East",
                            "public_ranges": ["203.0.113.0/26"],
                            "private_ranges": [
                                {
                                    "cidr": "10.1.0.0/16",
                                    "name": "NYC private",
                                    "vlans": [
                                        {
                                            "name": "End User",
                                            "vlan_id": 130,
                                            "cidr": "10.1.32.0/22",
                                        }
                                    ],
                                }
                            ],
                        }
                    ]
                }

        return Module

    def test_service_main_writes_latest_summary_and_run_artifacts(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_case"

        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            scan_dir = temp_path / "scans"
            asset_dir = temp_path / "assets"
            output_dir = temp_path / "output"
            scan_dir.mkdir()
            asset_dir.mkdir()

            for payload in [
                {
                    "id": 1,
                    "name": "US East NYC01 Private Discovery",
                    "ipList": "10.1.0.0/16,10.3.0.0/16",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
                {
                    "id": 2,
                    "name": "US East NYC01 Server Assessment",
                    "ipList": "10.1.16.0/24",
                    "assets": [],
                    "schedule": {"enabled": True},
                },
            ]:
                (scan_dir / f"{payload['id']}_scan.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )

            with patch(
                "src.tenable_coverage_workflow.subnet_source.source_loader."
                "importlib.import_module",
                return_value=self._subnet_module(),
            ):
                exit_code = service_main(
                    [
                        "--job-name",
                        "nightly-coverage",
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

    def test_service_main_writes_failed_state_when_run_fails(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_failed_state_case"
        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            output_dir = temp_path / "output"
            output_dir.mkdir()

            with patch(
                "src.tenable_coverage_workflow.service_runner.run_detect_and_plan",
                side_effect=RuntimeError("simulated run failure"),
            ):
                exit_code = service_main(
                    [
                        "--job-name",
                        "nightly-coverage",
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

            self.assertEqual(exit_code, 1)
            latest_summary = json.loads(
                (output_dir / "latest_run.json").read_text(encoding="utf-8")
            )
            self.assertEqual(latest_summary["status"], "FAILED")
            self.assertEqual(latest_summary["error"], "simulated run failure")
            self.assertIn("completed_at", latest_summary)
            self.assertFalse((output_dir / "scheduler.lock").exists())
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
