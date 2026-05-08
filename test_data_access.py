import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from data_access import DataAccess


def make_config(**overrides):
    defaults = {
        "mode": "live",
        "sc_url": "https://tenable.local",
        "sc_access_key": "access",
        "sc_secret_key": "secret",
        "scan_json_dir": None,
        "asset_json_dir": None,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class FakeScans:
    def __init__(self):
        self._list_payload = {"usable": [{"id": 1, "name": "Scan A"}]}

    def list(self):
        return self._list_payload

    def details(self, scan_id):
        return {"id": scan_id, "name": "Scan Details"}


class FakeAssetLists:
    def details(self, asset_id):
        return {"id": asset_id, "name": "Asset Details"}


class FakeTenableSC:
    last_init = None

    def __init__(self, url, access_key, secret_key):
        FakeTenableSC.last_init = {
            "url": url,
            "access_key": access_key,
            "secret_key": secret_key,
        }
        self.scans = FakeScans()
        self.asset_lists = FakeAssetLists()


class DataAccessTests(unittest.TestCase):
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
        self.assertIn("SC_URL", error_text)
        self.assertIn("SC_ACCESS_KEY", error_text)
        self.assertIn("SC_SECRET_KEY", error_text)

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
            },
        )
        self.assertEqual(access.get_scans(), [{"id": 1, "name": "Scan A"}])
        self.assertEqual(access.get_scan_details(1), {"id": 1, "name": "Scan Details"})
        self.assertEqual(access.get_asset(20), {"id": 20, "name": "Asset Details"})

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


if __name__ == "__main__":
    unittest.main()
