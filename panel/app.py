#!/usr/bin/env python3
"""Compatibility entrypoint for the node-local Unified VPS panel.

Production deployments keep this filename at /opt/unified-vps/panel.py.
The implementation lives in the importable uvps_panel package beside it.
"""
from pathlib import Path
import sys

APP_ROOT = Path(__file__).resolve().parent
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))

from uvps_panel.main import main  # noqa: E402

if __name__ == "__main__":
    main()
