import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
SRC_PATH = REPO_ROOT / "src"


def _run() -> int:
    if str(SRC_PATH) not in sys.path:
        sys.path.insert(0, str(SRC_PATH))

    from tenable_scan_analysis.cli.main import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_run())
