"""Точка входа f2b-manager: python -m f2b_manager."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
