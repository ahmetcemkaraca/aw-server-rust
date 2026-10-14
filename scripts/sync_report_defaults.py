"""Copy the authoritative free UI category defaults into the native model source."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate default-category field")
        result[key] = value
    return result


def validate(raw):
    if len(raw) > 1024 * 1024:
        raise ValueError("Default categories exceed the source limit")
    value = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(value, list) or not 1 <= len(value) <= 1000:
        raise ValueError("Default categories must be a bounded array")
    for category in value:
        if not isinstance(category, dict) or set(category) - {"name", "rule", "data", "id"}:
            raise ValueError("Invalid default category")
        name, rule = category.get("name"), category.get("rule")
        if not isinstance(name, list) or not 1 <= len(name) <= 8 or any(
            not isinstance(segment, str) or not segment or len(segment.encode("utf-8")) > 128
            for segment in name
        ):
            raise ValueError("Invalid default category name")
        if not isinstance(rule, dict) or set(rule) - {"type", "regex", "ignore_case"}:
            raise ValueError("Invalid default category rule")
        if rule.get("type") not in (None, "none", "regex"):
            raise ValueError("Unsupported default category rule")
        if rule.get("type") == "regex" and (
            not isinstance(rule.get("regex"), str) or len(rule["regex"].encode("utf-8")) > 4096
        ):
            raise ValueError("Invalid default regex")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ui-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parents[1] / "aw-models/src/generated/report-default-categories-v1.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    source = args.ui_root / "src/util/defaultCategories.json"
    try:
        raw = source.read_bytes()
        validate(raw)
        if args.check:
            if not args.output.is_file() or args.output.read_bytes() != raw:
                raise ValueError("Native defaults are stale; run the source copier")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=args.output.parent, prefix=".report-defaults-", delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(raw)
                os.replace(temporary, args.output)
                temporary = None
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    except (OSError, UnicodeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    print("Free UI and native report defaults match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
