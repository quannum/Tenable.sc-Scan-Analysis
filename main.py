import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent


def _run() -> int:
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    from src.tenable_coverage_workflow.application_cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(_run())
