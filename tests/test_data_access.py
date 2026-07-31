import json
import shutil
import sys
import tempfile
import types
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.io.data_access import DataAccess, load_json_folder, normalize_resource_list


@dataclass
class TestDataAccessConfig:
    mode: str = "live"
    sc_url: str | None = "https://tenable.local"
    sc_access_key: str | None = "access"
    sc_secret_key: str | None = "secret"
    scan_json_dir: str | None = None
    asset_json_dir: str | None = None
    sc_ssl_verify: str | bool = True


def make_config(**overrides: Any) -> TestDataAccessConfig:
    defaults: dict[str, Any] = {
        "mode": "live",
        "sc_url": "https://tenable.local",
        "sc_access_key": "access",
        "sc_secret_key": "secret",
        "scan_json_dir": None,
        "asset_json_dir": None,
        "sc_ssl_verify": True,
    }
    defaults.update(overrides)
    return TestDataAccessConfig(**defaults)


class FakeScans:
    def __init__(self):
        self._list_payload = {"usable": [{"id": 1, "name": "Scan A"}]}
        self._failures_before_success = 0

    def list(self):
        if self._failures_before_success > 0:
            self._failures_before_success -= 1
            raise TimeoutError("timed out")
        return self._list_payload

    def details(self, scan_id):
        return {"id": scan_id, "name": "Scan Details"}

    def create(self, name, repository_id, **kwargs):
        return {"id": 2, "name": name, "repository_id": repository_id, **kwargs}

    def edit(self, scan_id, **kwargs):
        return {"id": scan_id, **kwargs}


class FakeAssetLists:
    def details(self, asset_id):
        return {"id": asset_id, "name": "Asset Details"}

    def create(self, name, list_type, **kwargs):
        return {"id": 21, "name": name, "type": list_type, **kwargs}

    def edit(self, asset_id, **kwargs):
        return {"id": asset_id, **kwargs}


class FakeTenableSC:
    last_init = None

    def __init__(self, url, access_key, secret_key, **kwargs):
        FakeTenableSC.last_init = {
            "url": url,
            "access_key": access_key,
            "secret_key": secret_key,
            **kwargs,
        }
        self.scans = FakeScans()
        self.asset_lists = FakeAssetLists()


class DataAccessTests(unittest.TestCase):
    def test_resource_payload_normalization_merges_usable_and_manageable(self):
        self.assertEqual(
            normalize_resource_list(
                {
                    "usable": [{"id": 1, "name": "one"}],
                    "manageable": [
                        {"id": 1, "name": "one duplicate"},
                        {"id": 2, "name": "two"},
                    ],
                }
            ),
            [{"id": 1, "name": "one"}, {"id": 2, "name": "two"}],
        )

    def test_resource_payload_normalization_handles_nested_response_results(self):
        self.assertEqual(
            normalize_resource_list(
                {
                    "response": {
                        "results": [
                            {"id": 1, "name": "one"},
                            {"id": 2, "name": "two"},
                        ]
                    }
                }
            ),
            [{"id": 1, "name": "one"}, {"id": 2, "name": "two"}],
        )

    def test_resource_payload_normalization_handles_named_resource_lists(self):
        self.assertEqual(
            normalize_resource_list(
                {
                    "assetLists": [{"id": 1, "name": "assets"}],
                    "policies": [{"id": 2, "name": "policy"}],
                }
            ),
            [{"id": 1, "name": "assets"}, {"id": 2, "name": "policy"}],
        )

    # responses with no asset / scan / policy wrapper
    def test_resource_payload_normalization_handles_a_single_resource(self):
        self.assertEqual(
            normalize_resource_list({"id": 1, "name": "one"}),
            [{"id": 1, "name": "one"}],
        )

    def test_invalid_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "mode must be 'offline' or 'live'"):
            DataAccess(make_config(mode="invalid"))

    def test_live_mode_requires_credentials_and_url(self):
        with self.assertRaises(ValueError) as ctx:
            DataAccess(
                make_config(
                    sc_url=None,
                    sc_access_key=None,
                    sc_secret_key=None,
                )
            )

        error_text = str(ctx.exception)
        self.assertIn("TCW_SC_URL/SC_URL", error_text)
        self.assertIn("TCW_SC_ACCESS_KEY/SC_ACCESS_KEY", error_text)
        self.assertIn("TCW_SC_SECRET_KEY/SC_SECRET_KEY", error_text)

    def test_live_mode_uses_tenable_client_and_methods(self):
        tenable_module = types.ModuleType("tenable")
        tenable_sc_module = types.ModuleType("tenable.sc")
        tenable_sc_module.TenableSC = FakeTenableSC
        tenable_module.sc = tenable_sc_module

        with patch.dict(
            sys.modules,
            {"tenable": tenable_module, "tenable.sc": tenable_sc_module},
            clear=False,
        ):
            access = DataAccess(make_config())

        self.assertEqual(
            FakeTenableSC.last_init,
            {
                "url": "https://tenable.local",
                "access_key": "access",
                "secret_key": "secret",
                "timeout": 60,
                "retries": 3,
                "backoff": 1.5,
                "ssl_verify": True,
            },
        )
        self.assertEqual(access.get_scans(), [{"id": 1, "name": "Scan A"}])
        self.assertEqual(access.get_scan_details(1), {"id": 1, "name": "Scan Details"})
        self.assertEqual(access.get_asset(20), {"id": 20, "name": "Asset Details"})

    def test_live_mode_parses_string_false_ssl_verify(self):
        tenable_module = types.ModuleType("tenable")
        tenable_sc_module = types.ModuleType("tenable.sc")
        tenable_sc_module.TenableSC = FakeTenableSC
        tenable_module.sc = tenable_sc_module

        with patch.dict(
            sys.modules,
            {"tenable": tenable_module, "tenable.sc": tenable_sc_module},
            clear=False,
        ):
            DataAccess(make_config(sc_ssl_verify="false"))

        self.assertFalse(FakeTenableSC.last_init["ssl_verify"])

    def test_live_mode_handles_unexpected_scan_list_shape(self):
        tenable_module = types.ModuleType("tenable")
        tenable_sc_module = types.ModuleType("tenable.sc")
        tenable_sc_module.TenableSC = FakeTenableSC
        tenable_module.sc = tenable_sc_module

        with patch.dict(
            sys.modules,
            {"tenable": tenable_module, "tenable.sc": tenable_sc_module},
            clear=False,
        ):
            access = DataAccess(make_config())
            access.sc.scans._list_payload = {"unexpected": []}

        self.assertEqual(access.get_scans(), [])

    def test_live_mode_normalizes_alternate_scan_list_shapes(self):
        tenable_module = types.ModuleType("tenable")
        tenable_sc_module = types.ModuleType("tenable.sc")
        tenable_sc_module.TenableSC = FakeTenableSC
        tenable_module.sc = tenable_sc_module

        with patch.dict(
            sys.modules,
            {"tenable": tenable_module, "tenable.sc": tenable_sc_module},
            clear=False,
        ):
            access = DataAccess(make_config())
            access.sc.scans._list_payload = {
                "manageable": [{"id": 2, "name": "Manageable Scan"}],
                "response": [{"id": 3, "name": "Response Scan"}],
            }

        self.assertEqual(
            access.get_scans(),
            [
                {"id": 2, "name": "Manageable Scan"},
                {"id": 3, "name": "Response Scan"},
            ],
        )

    def test_live_mutation_methods_use_supported_pytenable_arguments(self):
        tenable_module = types.ModuleType("tenable")
        tenable_sc_module = types.ModuleType("tenable.sc")
        tenable_sc_module.TenableSC = FakeTenableSC
        tenable_module.sc = tenable_sc_module
        with patch.dict(
            sys.modules,
            {"tenable": tenable_module, "tenable.sc": tenable_sc_module},
            clear=False,
        ):
            access = DataAccess(make_config())

        asset = access.create_static_asset("Asset", ["10.0.0.0/24"], "managed")
        scan = access.create_scan("Scan", 7, [21], 30)
        updated = access.update_scan_configuration(2, [21, 22], 7, 30)

        self.assertEqual(asset["type"], "static")
        self.assertEqual(asset["ips"], ["10.0.0.0/24"])
        self.assertEqual(scan["asset_lists"], [21])
        self.assertEqual(updated["repo"], 7)
        self.assertEqual(updated["policy_id"], 30)

    def test_live_mode_retries_retryable_errors(self):
        tenable_module = types.ModuleType("tenable")
        tenable_sc_module = types.ModuleType("tenable.sc")
        tenable_sc_module.TenableSC = FakeTenableSC
        tenable_module.sc = tenable_sc_module

        with (
            patch.dict(
                sys.modules,
                {"tenable": tenable_module, "tenable.sc": tenable_sc_module},
                clear=False,
            ),
            patch("src.io.data_access.time.sleep") as sleep_mock,
        ):
            access = DataAccess(make_config())
            access.sc.scans._failures_before_success = 2
            scans = access.get_scans()

        self.assertEqual(scans, [{"id": 1, "name": "Scan A"}])
        self.assertEqual(sleep_mock.call_count, 2)

    def test_offline_duplicate_ids_replace_previous_object(self):
        temp_path = Path(tempfile.mkdtemp(prefix="tenable-data-access-"))

        scan_dir = temp_path / "scans"
        asset_dir = temp_path / "assets"
        scan_dir.mkdir()
        asset_dir.mkdir()

        try:
            (scan_dir / "first.json").write_text(
                json.dumps({"id": 1, "name": "Scan A"}),
                encoding="utf-8",
            )
            (scan_dir / "second.json").write_text(
                json.dumps({"id": 1, "name": "Scan B"}),
                encoding="utf-8",
            )

            cfg = make_config(
                mode="offline",
                scan_json_dir=str(scan_dir),
                asset_json_dir=str(asset_dir),
            )
            with self.assertLogs("src.io.data_access", level="WARNING") as logs:
                access = DataAccess(cfg)

            self.assertTrue(
                any("Duplicate object id '1'" in line for line in logs.output)
            )
            self.assertIn("Scan B", str(access.offline_scans.get("1")))
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)

    def test_load_json_folder_skips_non_object_json_roots(self):
        temp_path = Path(tempfile.mkdtemp(prefix="tenable-data-access-"))

        try:
            (temp_path / "array.json").write_text(
                json.dumps([{"id": 1}]),
                encoding="utf-8",
            )
            (temp_path / "object.json").write_text(
                json.dumps({"id": 2, "name": "Scan"}),
                encoding="utf-8",
            )

            with self.assertLogs("src.io.data_access", level="WARNING") as logs:
                payload = load_json_folder(str(temp_path))

            self.assertEqual(payload, {"2": {"id": 2, "name": "Scan"}})
            self.assertTrue(
                any("root is not an object" in line for line in logs.output)
            )
        finally:
            if temp_path.exists():
                shutil.rmtree(temp_path)


if __name__ == "__main__":
    unittest.main()
