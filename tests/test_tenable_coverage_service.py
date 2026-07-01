import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from src.tenable_coverage_workflow.service_config import build_service_config
from src.tenable_coverage_workflow.service_runner import main as service_main


class ServiceConfigTests(unittest.TestCase):
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
                    'subnet_repo_path = "repo"\n'
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
            self.assertEqual(config.subnet_repo_path, "repo")
            self.assertEqual(config.run_id_prefix, "nightly-")
            self.assertEqual(config.include_keywords, ["Discovery", "Assessment"])
            self.assertEqual(config.exclude_keywords, ["Deprecated"])
            self.assertEqual(
                config.latest_summary_file,
                temp_path / "output" / "latest_run.json",
            )
            self.assertEqual(config.lock_file, temp_path / "output" / "scheduler.lock")
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)


class ScheduledServiceTests(unittest.TestCase):
    def test_service_main_writes_latest_summary_and_run_artifacts(self):
        temp_root = Path.cwd() / ".tmp-test-artifacts"
        temp_path = temp_root / "scheduled_service_case"
        fixture_repo = Path("tests") / "fixtures" / "subnet_repo"

        if temp_path.exists():
            shutil.rmtree(temp_path)

        temp_path.mkdir(parents=True, exist_ok=True)

        try:
            subnet_repo = temp_path / "subnet_repo"
            shutil.copytree(fixture_repo, subnet_repo)

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
                    "--subnet-repo-path",
                    str(subnet_repo),
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
            self.assertEqual(run_summary["yaml_files_processed"], 6)
            self.assertEqual(run_summary["yaml_files_failed"], 2)

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
                        "--subnet-repo-path",
                        "repo",
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


if __name__ == "__main__":
    unittest.main()
