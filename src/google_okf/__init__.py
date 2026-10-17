import os
import sys
from pathlib import Path


def main() -> None:
    """Run the OKF bundle MCP server over stdio.

    Bundle directory: first CLI argument, else $OKF_BUNDLE_DIR, else ./shieldpulse-okf.
    """
    from google_okf.server import create_server

    root = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OKF_BUNDLE_DIR", "shieldpulse-okf"))
    if not (root / "index.md").is_file():
        sys.exit(f"No OKF bundle at '{root}' (index.md not found).")
    create_server(root).run()
