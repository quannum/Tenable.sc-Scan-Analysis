from typing import Any


def parse_csv_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, tuple):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def parse_string_mapping(value: Any) -> dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return {
            str(key).strip(): str(item).strip()
            for key, item in value.items()
            if str(key).strip() and str(item).strip()
        }

    text = str(value).strip()
    if not text:
        return {}

    pairs: list[str]
    if text.startswith("{") and text.endswith("}"):
        import json

        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise ValueError("Mapping JSON must decode to an object.")
        return {
            str(key).strip(): str(item).strip()
            for key, item in parsed.items()
            if str(key).strip() and str(item).strip()
        }

    pairs = [item.strip() for item in text.split(",") if item.strip()]
    mapping: dict[str, str] = {}
    for pair in pairs:
        if "=" not in pair:
            raise ValueError(
                "Mapping values must use key=value pairs separated by commas"
            )
        key, item = pair.split("=", 1)
        key = key.strip()
        item = item.strip()
        if key and item:
            mapping[key] = item
    return mapping
