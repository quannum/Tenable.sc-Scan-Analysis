import glob
import json
import logging
import os

LOGGER = logging.getLogger(__name__)


def load_json_folder(folder_path):
    data = {}
    if not folder_path:
        return data

    file_paths = glob.glob(os.path.join(folder_path, "*.json"))
    for file_path in file_paths:
        try:
            with open(file_path, "r", encoding="utf-8") as handle:
                obj = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            LOGGER.warning("Skipping unreadable JSON file '%s': %s", file_path, exc)
            continue

        object_id = obj.get("id")
        if object_id in (None, ""):
            LOGGER.warning("Skipping JSON file without an 'id': %s", file_path)
            continue

        data[str(object_id)] = obj

    LOGGER.info("Loaded %s JSON objects from %s", len(data), folder_path)
    return data


class DataAccess:
    def __init__(self, config):
        self.config = config
        self.sc = None
        self.offline_scans = {}
        self.offline_assets = {}

        if config.mode == "live":
            try:
                from tenable.sc import TenableSC
            except ImportError as exc:
                raise RuntimeError("pyTenable is required for live mode") from exc

            self.sc = TenableSC(
                url=config.sc_url,
                access_key=config.sc_access_key,
                secret_key=config.sc_secret_key,
            )
        else:
            self.offline_scans = load_json_folder(config.scan_json_dir)
            self.offline_assets = load_json_folder(config.asset_json_dir)

    def get_scans(self):
        if self.config.mode == "live":
            return self.sc.scans.list()["usable"]
        return list(self.offline_scans.values())

    def get_scan_details(self, scan_id):
        if self.config.mode == "live":
            return self.sc.scans.details(scan_id)
        return self.offline_scans[str(scan_id)]

    def get_asset(self, asset_id):
        if self.config.mode == "live":
            return self.sc.asset_lists.details(asset_id)
        return self.offline_assets.get(str(asset_id), {})
