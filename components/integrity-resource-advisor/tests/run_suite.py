"""Source suite; --installed refuses to replace the installed runtime import."""
import argparse
from pathlib import Path
import sys
import unittest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installed", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if not args.installed:
        sys.path.insert(0, str(root / "src"))
    import integrity_resource_advisor
    origin = Path(integrity_resource_advisor.__file__).resolve()
    if args.installed and root in origin.parents:
        raise SystemExit("installed-origin-is-source")
    suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern="test_*.py")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())


if __name__ == "__main__":
    main()
