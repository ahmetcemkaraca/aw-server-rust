import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "sync_report_defaults.py"
ORIGINAL_SHA = "afc8df601391ccc4baca3690ed099ce79d1aa2c6e743648f2515d3c270d4eed4"


class ReportDefaultsTest(unittest.TestCase):
    def invoke(self, source, destination, check=False):
        args = [sys.executable, str(SCRIPT), "--ui-root", str(source), "--output", str(destination)]
        if check:
            args.append("--check")
        return subprocess.run(args, capture_output=True, text=True)

    def test_shipped_defaults_preserve_the_original_free_rules(self):
        core = SCRIPT.parent.parent
        original = core / "aw-webui/src/util/defaultCategories.json"
        generated = core / "aw-models/src/generated/report-default-categories-v1.json"
        self.assertEqual(hashlib.sha256(original.read_bytes()).hexdigest(), ORIGINAL_SHA)
        self.assertEqual(generated.read_bytes(), original.read_bytes())
        self.assertEqual(len(json.loads(original.read_text())), 16)

    def test_check_detects_stale_copy_without_rewriting_it(self):
        with tempfile.TemporaryDirectory(prefix="peak-report-defaults-") as directory:
            root = Path(directory)
            ui = root / "ui"
            source = ui / "src/util/defaultCategories.json"
            source.parent.mkdir(parents=True)
            source.write_text('[{"name":["Work"],"rule":{"type":"none"}}]\n')
            output = root / "generated.json"
            self.assertEqual(self.invoke(ui, output).returncode, 0)
            self.assertEqual(output.read_bytes(), source.read_bytes())
            output.write_text("[]\n")
            stale = output.read_bytes()
            self.assertNotEqual(self.invoke(ui, output, check=True).returncode, 0)
            self.assertEqual(output.read_bytes(), stale)

    def test_invalid_source_preserves_existing_generated_copy(self):
        with tempfile.TemporaryDirectory(prefix="peak-report-defaults-") as directory:
            root = Path(directory)
            ui = root / "ui"
            source = ui / "src/util/defaultCategories.json"
            source.parent.mkdir(parents=True)
            source.write_text('{"not":"category array"}')
            output = root / "generated.json"
            output.write_text("preserve me\n")
            self.assertNotEqual(self.invoke(ui, output).returncode, 0)
            self.assertEqual(output.read_text(), "preserve me\n")


if __name__ == "__main__":
    unittest.main()
