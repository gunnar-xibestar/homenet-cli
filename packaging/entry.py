"""PyInstaller entry point for the homenet onefile binary."""

import sys

from homenet.cli import main

if __name__ == "__main__":
    sys.exit(main())
