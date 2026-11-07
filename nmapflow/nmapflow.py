#!/usr/bin/env python3
"""Launcher: python3 nmapflow.py  (run with sudo for raw-socket scan types)."""

import sys

if sys.version_info < (3, 10):
    sys.exit("nmapflow requires Python 3.10 or newer (found %s)." % sys.version.split()[0])

from nmapflow.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
