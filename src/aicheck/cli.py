"""Console-script entrypoint: the `aicheck` command.

Thin wrapper over aicheck.scan.main so the installed package, the GitHub
Action and the Docker image all drive the exact same engine path as
`python -m aicheck.scan`.
"""

from __future__ import annotations

import sys

from . import scan


def main() -> int:
    return scan.main()


if __name__ == "__main__":
    sys.exit(main())
