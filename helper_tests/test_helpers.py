import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPERS = ROOT / "mobiledestro-v1" / "helpers"
sys.path.insert(0, str(HELPERS))
import scope_check as scope
import triage_inputs as triage
from _common import read_json

spec = importlib.util.spec_from_file_location("installer", ROOT / "tools" / "install_skill.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class HelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix=".tmp-", dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        self.scope = {"schema_version": 1, "authorization": {"status": "approved", "reference": "synthetic fixture"},
                      "active_allowlist": {"packages": ["com.example.lab"], "origins": ["https://api.example.test"]}}

    def tearDown(self):
        self.temp.cleanup()

    def write_json(self, name, value):
        p = self.root / name
        p.write_text(json.dumps(value), encoding="utf-8")
        return p

    def test_exact_package_only(self):
        self.assertTrue(scope.decide(self.scope, "package", "com.example.lab")[0])
        for target in ("com.example.lab.child", "com.example.other", "com.Example.lab"):
            self.assertFalse(scope.decide(self.scope, "package", target)[0])

    def test_origin_normalization_preserves_boundary(self):
        self.assertTrue(scope.decide(self.scope, "origin", "https://API.EXAMPLE.TEST:443/v1/me?q=1")[0])
        for target in ("http://api.example.test", "https://api.example.test:8443", "https://sub.api.example.test", "https://api.example.test.evil.test"):
            self.assertFalse(scope.decide(self.scope, "origin", target)[0])

    def test_ambiguous_origins_rejected(self):
        for target in ("api.example.test", "https:///api.example.test", "https://api.example.test:0",
                       "https://api.example.test:", "https://api.example.test.", "https://api.example.test/#f",
                       "https://user:pw@api.example.test", "https://api.example.test\\@evil.test", "https://api.example.test%2eevil.test",
                       "https://*.example.test", "https://api.example.test\n", "https://api.example.test:99999"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                scope.origin(target)

    def test_allowlist_paths_fail_instead_of_widening(self):
        self.scope["active_allowlist"]["origins"] = ["https://api.example.test/private"]
        with self.assertRaises(ValueError):
            scope.decide(self.scope, "origin", "https://api.example.test/public")

    def test_pending_or_missing_authority_denied(self):
        self.scope["authorization"]["status"] = "pending"
        self.assertFalse(scope.decide(self.scope, "package", "com.example.lab")[0])
        self.scope["authorization"] = {"status": "approved", "reference": ""}
        self.assertFalse(scope.decide(self.scope, "package", "com.example.lab")[0])

    def test_bad_allowlist_schema_rejected(self):
        self.scope["active_allowlist"]["packages"] = "com.example.lab"
        with self.assertRaises(ValueError):
            scope.decide(self.scope, "package", "com.example.lab")

    def test_version_boolean_is_not_integer_version(self):
        self.scope["schema_version"] = True
        with self.assertRaises(ValueError):
            scope.decide(self.scope, "package", "com.example.lab")

    def test_duplicate_scope_keys_rejected(self):
        p = self.root / "scope.json"
        p.write_text('{"authorization":{},"authorization":{"status":"approved"}}', encoding="utf-8")
        with self.assertRaises(ValueError):
            read_json(p, 1024)

    def test_scope_cli_denies_without_executing(self):
        p = self.write_json("scope.json", self.scope)
        result = subprocess.run([sys.executable, "-B", str(HELPERS / "scope_check.py"), "--scope", str(p),
                                 "--kind", "origin", "--target", "https://unapproved.test"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(json.loads(result.stdout)["network_or_device_action_executed"])

    def test_source_no_raw_secret_or_snippet(self):
        (self.root / "Main.java").write_text('String access_token = "SYNTHETIC_SECRET_DO_NOT_EMIT";\nweb.loadUrl(input);', encoding="utf-8")
        result = triage.scan(self.root)
        self.assertNotIn("SYNTHETIC_SECRET_DO_NOT_EMIT", json.dumps(result))
        self.assertEqual(result["files_scanned"], 1)
        self.assertTrue(any(x["category"] == "webview-routing" for x in result["leads"]))
        self.assertTrue(all(x["status"] == "hypothesis" for x in result["leads"]))

    def test_source_limits_are_visible(self):
        (self.root / "Main.java").write_text('loadUrl(a);\nloadUrl(b);', encoding="utf-8")
        result = triage.scan(self.root, max_hits=1)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["leads"]), 1)

    def test_source_non_utf8_is_skipped(self):
        (self.root / "Main.java").write_bytes(b"\xff\xfe\xff")
        result = triage.scan(self.root)
        self.assertEqual(result["files_scanned"], 0)
        self.assertEqual(len(result["skipped"]), 1)

    def test_source_large_file_is_skipped(self):
        (self.root / "Main.java").write_text("loadUrl(a);", encoding="utf-8")
        result = triage.scan(self.root, max_bytes=5)
        self.assertEqual(result["leads"], [])
        self.assertEqual(result["skipped"][0]["reason"], "file-size limit")

    def test_dependency_directory_exclusion_visible(self):
        d = self.root / "node_modules"
        d.mkdir()
        (d / "main.js").write_text("loadUrl(input)", encoding="utf-8")
        result = triage.scan(self.root)
        self.assertEqual(result["leads"], [])
        self.assertEqual(result["ignored_directories"], 1)

    def test_semgrep_import_does_not_promote_or_copy_raw_message(self):
        p = self.write_json("scan.json", {"results": [{"check_id": "rule", "path": "Main.java", "start": {"line": 7},
                                                     "extra": {"severity": "ERROR", "message": "RAW_SECRET", "lines": "RAW_SECRET"}}]})
        result = triage.import_report(p, "semgrep")
        self.assertNotIn("RAW_SECRET", json.dumps(result))
        self.assertEqual(result["leads"][0]["status"], "hypothesis")
        self.assertEqual(result["leads"][0]["line"], 7)

    def test_mobsf_supported_sections(self):
        p = self.write_json("scan.json", {"code_analysis": {"findings": {"r": {"metadata": {"severity": "high"}, "files": {"A.java": "2"}}}},
                                          "manifest_analysis": {"manifest_findings": [{"rule": "export", "severity": "warning"}]}})
        result = triage.import_report(p, "mobsf")
        self.assertEqual(len(result["leads"]), 2)
        self.assertEqual(result["leads"][0]["files"], ["A.java"])

    def test_unrecognized_scanner_schema_is_error(self):
        p = self.write_json("scan.json", {"moved_schema": []})
        for fmt in ("mobsf", "semgrep"):
            with self.assertRaises(ValueError):
                triage.import_report(p, fmt)

    def test_empty_recognized_report_is_not_security_claim(self):
        p = self.write_json("scan.json", {"results": []})
        result = triage.import_report(p, "semgrep")
        self.assertEqual(result["leads"], [])
        self.assertTrue(any("zero count" in s for s in result["limitations"]))

    def test_json_limits_and_nonfinite_rejected(self):
        p = self.root / "bad.json"
        p.write_text('{"a": NaN}', encoding="utf-8")
        with self.assertRaises(ValueError):
            read_json(p, 1024)
        p.write_text("x" * 2000, encoding="utf-8")
        with self.assertRaises(ValueError):
            read_json(p, 1024)

    def test_write_does_not_overwrite(self):
        p = self.write_json("out.json", {"original": True})
        with self.assertRaises(FileExistsError):
            triage.write_new(p, {})
        self.assertEqual(json.loads(p.read_text()), {"original": True})

    def test_installer_copies_supporting_files_and_refuses_overwrite(self):
        dest = installer.install(self.root)
        self.assertTrue((dest / "SKILL.md").is_file())
        self.assertTrue((dest / "helpers" / "_common.py").is_file())
        self.assertTrue((dest / "references" / "engines" / "06-native-jni-fuzzing.md").is_file())
        with self.assertRaises(FileExistsError):
            installer.install(self.root)

    def test_installer_requires_existing_project(self):
        with self.assertRaises(ValueError):
            installer.install(self.root / "missing")


if __name__ == "__main__":
    unittest.main()
