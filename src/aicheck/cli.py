"""Console-script entrypoint: the `aicheck` command.

One binary, two modes (same engine, same probe model):

  aicheck <target> ...              # CI / single-host scan (legacy shape)
  aicheck scan <target> ...         # explicit scan
  aicheck inventory --targets ...   # local continuous estate inventory

GitHub Action, PyPI, and Docker all drive this entrypoint.
"""

from __future__ import annotations

import sys


_SUBCOMMANDS = {"scan", "inventory", "inv", "template"}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-V", "--version"):
        from . import __version__
        print(f"aicheck {__version__}")
        return 0
    if argv and argv[0] in ("-h", "--help"):
        print(
            "usage: aicheck <target> [scan flags]\n"
            "       aicheck scan <target> [scan flags]\n"
            "       aicheck inventory --targets FILE --state-dir DIR [flags]\n"
            "       aicheck template <file|https-url> [...] [--format text|json]\n"
            "\n"
            "Same engine for CI (scan) and local continuous inventory.\n"
            "Probe contract: docs/PROBES.md · https://unauth.dev"
        )
        return 0
    if argv and argv[0] in ("inventory", "inv"):
        from .inventory import main as inventory_main
        return inventory_main(argv[1:])
    if argv and argv[0] == "scan":
        from .scan import main as scan_main
        return scan_main(argv[1:])
    if argv and argv[0] == "template":
        from .workflow_templates import main as template_main
        return template_main(argv[1:])
    # Legacy: `aicheck <target> [flags]` — keep Action/docs working.
    from .scan import main as scan_main
    return scan_main(argv)


if __name__ == "__main__":
    sys.exit(main())
