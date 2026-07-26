import json
import tempfile
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast


class AuditLogger:
    def __init__(self, run_id: str, run_dir: str | Path) -> None:
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "audit.jsonl"

    def emit(self, event_type: str, **fields: Any) -> None:
        """Write one audit event"""
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
        }
        payload.update(_serialize_value(fields))
        self._append_jsonl(payload)

    def _append_jsonl(self, payload: dict[str, Any]) -> None:
        """Add one JSON line to the audit log"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True, sort_keys=True))
            handle.write("\n")


def atomic_write_text(path: str | Path, content: str) -> Path:
    """Write text"""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    temp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            delete=False,
            dir=destination.parent,
            suffix=destination.suffix,
            prefix="audit-",
        ) as handle:
            temp_name = handle.name
            handle.write(content)
        Path(temp_name).replace(destination)
    finally:
        if temp_name:
            temp_path = Path(temp_name)
            if temp_path.exists():
                temp_path.unlink()

    return destination


def atomic_write_json(path: str | Path, payload: dict[str, Any]) -> Path:
    """Write json"""
    return atomic_write_text(
        path,
        json.dumps(
            _serialize_value(payload),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )


def _serialize_value(value: Any) -> Any:
    """Serialize value"""
    if is_dataclass(value):
        return {
            key: _serialize_value(item)
            for key, item in asdict(cast(Any, value)).items()
        }
    if isinstance(value, dict):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_serialize_value(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value
