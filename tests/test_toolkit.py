"""Offline regression tests; synthetic inputs only, no installed-tool execution."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "mobiledestro-v1" / "scripts" / "mobiledestro.py"
spec = importlib.util.spec_from_file_location("mobiledestro", SCRIPT)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ToolkitCase(unittest.TestCase):
    def setUp(self):
        # Keep disposable fixtures in this repository, including on sandboxed Windows.
        self.temp = tempfile.TemporaryDirectory(prefix="mobiledestro-test-", dir=Path(__file__).resolve().parent)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.root.resolve().relative_to(Path(__file__).resolve().parent)
        self.temp.cleanup()

    def json_file(self, name, data):
        path = self.root / name
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def manifest(self, body, sdk="30", app="", device=None, minimum="21"):
        target = f'android:targetSdkVersion="{sdk}"' if sdk is not None else ""
        xml = (f'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.app">'
               f'<uses-sdk android:minSdkVersion="{minimum}" {target}/>'
               f'<application {app}>{body}</application></manifest>')
        path = self.root / "manifest.xml"
        path.write_text(xml, encoding="utf-8")
        return tool.manifest(path, device)

    def archive(self, members, compression=zipfile.ZIP_STORED):
        path = self.root / "sample.apk"
        with zipfile.ZipFile(path, "w", compression=compression) as archive:
            for name, body in members:
                archive.writestr(name, body)
        return path

    def engagement(self):
        path = self.root / "engagement"
        tool.init_engagement(path)
        scope = tool.read_json(path / "scope.json")
        scope["authorization"] = {"status": "approved", "reference": "Lab ticket 42"}
        scope["targets"] = ["test.app / lab only"]
        scope["attacker_models"] = ["unprivileged companion app"]
        (path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        evidence = []
        for role in ("positive", "negative_control", "clean_replay"):
            payload = (role + " synthetic observation").encode()
            relative = "evidence/" + role + ".txt"
            (path / relative).write_bytes(payload)
            evidence.append({"role": role, "path": relative, "sha256": hashlib.sha256(payload).hexdigest()})
        ledger = {"schema_version": 1, "findings": [{
            "id": "F-001", "title": "Synthetic evidence demonstration", "severity": "unrated",
            "status": "dynamic-confirmed", "attacker_model": "unprivileged companion app",
            "description": "Fixture only; no actual vulnerability asserted.",
            "evidence": evidence, "coverage_ids": ["ipc"],
        }]}
        (path / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
        return path, ledger

    def save_ledger(self, root, ledger):
        (root / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")


class ArchiveTests(ToolkitCase):
    def test_inventory_hash_without_extraction_or_signature_claim(self):
        path = self.archive([("AndroidManifest.xml", b"fixture"), ("classes.dex", b"not a dex")])
        result = tool.intake(path)
        self.assertEqual(result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertTrue(result["apk_structure_hint"])
        self.assertFalse(result["signature_verified"])
        self.assertFalse(result["member_contents_verified"])
        self.assertFalse((self.root / "classes.dex").exists())

    def test_paths_rejected(self):
        for name in ("../escape", "/absolute", "C:/drive", "a/../../x", "a\\..\\x", "file:stream", "NUL.txt", "a./b"):
            with self.subTest(name=name):
                path = self.archive([(name, b"x")])
                with self.assertRaises(tool.InputError):
                    tool.intake(path)

    def test_symlink_member_rejected(self):
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(tool.InputError):
            tool.intake(self.archive([(info, b"../elsewhere")]))

    def test_case_collisions_rejected(self):
        with self.assertRaises(tool.InputError):
            tool.intake(self.archive([("file", b"one"), ("FILE", b"two")]))

    def test_compression_bomb_metadata_rejected(self):
        with self.assertRaises(tool.InputError):
            tool.intake(self.archive([("bomb", b"0" * 100000)], zipfile.ZIP_DEFLATED))

    def test_size_bound_before_extraction(self):
        path = self.archive([("part", b"123456789")])
        with mock.patch.object(tool, "MAX_MEMBER", 4), self.assertRaises(tool.InputError):
            tool.intake(path)

    def test_entry_bound(self):
        path = self.archive([("a", b"a"), ("b", b"b")])
        with mock.patch.object(tool, "MAX_ENTRIES", 1), self.assertRaises(tool.InputError):
            tool.intake(path)

    def test_zip64_explicitly_unsupported(self):
        path = self.archive([("a", b"a")])
        data = bytearray(path.read_bytes())
        end = data.rfind(b"PK\x05\x06")
        data[end + 10:end + 12] = b"\xff\xff"
        data[end + 8:end + 10] = b"\xff\xff"
        path.write_bytes(data)
        with self.assertRaisesRegex(tool.InputError, "ZIP64"):
            tool.intake(path)


class ManifestTests(ToolkitCase):
    FILTER = '<intent-filter><action android:name="test.ACTION"/></intent-filter>'

    def test_implicit_activity_defaults(self):
        result = self.manifest('<activity android:name=".A">' + self.FILTER + '</activity><service android:name="Service"/>')
        self.assertTrue(result["components"][0]["exported"])
        self.assertEqual(result["components"][0]["name"], "test.app.A")
        self.assertFalse(result["components"][1]["exported"])

    def test_api31_requires_explicit_for_activity_service_receiver_alias(self):
        for kind in ("activity", "service", "receiver", "activity-alias"):
            with self.subTest(kind=kind):
                component = self.manifest(f'<{kind} android:name=".A">{self.FILTER}</{kind}>', sdk="31")["components"][0]
                self.assertTrue(component["invalid_missing_exported"])
                self.assertIsNone(component["exported"])

    def test_api31_provider_does_not_use_filter_export_requirement(self):
        component = self.manifest(f'<provider android:name=".P">{self.FILTER}</provider>', sdk="31", device=31)["components"][0]
        self.assertFalse(component["invalid_missing_exported"])
        self.assertFalse(component["exported"])

    def test_provider_target_and_device_defaults(self):
        for target, device, expected in (("16", None, True), ("17", 16, True), ("17", 17, False), ("35", None, None)):
            with self.subTest(target=target, device=device):
                self.assertIs(self.manifest('<provider android:name=".P"/>', sdk=target, device=device)["components"][0]["exported"], expected)

    def test_target_omitted_defaults_to_minimum(self):
        result = self.manifest('<provider android:name=".P"/>', sdk=None, minimum="16")
        self.assertEqual(result["target_sdk"], 16)
        self.assertTrue(result["components"][0]["exported"])

    def test_disabled_application_blocks_declared_components(self):
        result = self.manifest('<activity android:name=".A" android:exported="true"/><provider android:name=".P" android:exported="true"/>', app='android:enabled="false"')
        for component in result["components"]:
            self.assertFalse(component["enabled"])
            self.assertFalse(component["manifest_external_candidate"])

    def test_permission_inheritance_and_clear(self):
        result = self.manifest('<activity android:name=".A"/><service android:name=".S" android:permission=""/>', app='android:permission="test.PRIVATE"')
        self.assertEqual(result["components"][0]["permission"]["name"], "test.PRIVATE")
        self.assertIsNone(result["components"][1]["permission"]["name"])

    def test_provider_read_and_write_permissions_override(self):
        result = self.manifest('<provider android:name=".P" android:readPermission="test.READ" android:writePermission=""/>', app='android:permission="test.PRIVATE"')
        provider = result["components"][0]
        self.assertEqual(provider["read_permission"]["name"], "test.READ")
        self.assertIsNone(provider["write_permission"]["name"])
        self.assertEqual(provider["permission"]["name"], "test.PRIVATE")

    def test_alias_resolves_preceding_target_with_independent_enabled_and_permission(self):
        result = self.manifest('<activity android:name=".Target" android:enabled="false"/><activity-alias android:name=".Alias" android:targetActivity=".Target" android:exported="true"/>', app='android:permission="test.PRIVATE"')
        alias = result["components"][1]
        self.assertTrue(alias["alias_target_resolved"])
        self.assertFalse(alias["alias_target_component_enabled"])
        self.assertTrue(alias["enabled"])
        self.assertIsNone(alias["permission"]["name"])

    def test_alias_target_must_precede(self):
        alias = self.manifest('<activity-alias android:name=".Alias" android:targetActivity=".Target" android:exported="true"/><activity android:name=".Target"/>')["components"][0]
        self.assertFalse(alias["alias_target_resolved"])
        self.assertIsNone(alias["manifest_external_candidate"])

    def test_unresolved_values_do_not_become_safe(self):
        component = self.manifest('<service android:name=".S" android:exported="@bool/export" android:permission="${permission}"/>', sdk="@integer/target", app='android:enabled="@bool/enabled"')["components"][0]
        self.assertIsNone(component["exported"])
        self.assertIsNone(component["enabled"])
        self.assertFalse(component["permission"]["resolved"])

    def test_separate_data_elements_aggregate_in_one_filter(self):
        body = '<activity android:name=".A"><intent-filter><action android:name="android.intent.action.VIEW"/><data android:scheme="https"/><data android:host="example.test"/><data android:pathPrefix="/item"/></intent-filter></activity>'
        values = self.manifest(body)["components"][0]["intent_filters"][0]["data_declarations_aggregated"]
        self.assertEqual(values, {"scheme": ["https"], "host": ["example.test"], "pathPrefix": ["/item"]})

    def test_dtd_entity_and_binary_xml_are_rejected(self):
        path = self.root / "bad.xml"
        for data in (b'<!DOCTYPE manifest [<!ENTITY x "xx">]><manifest>&x;</manifest>', '<manifest/>'.encode("utf-16"), b"\x03\x00\x08\x00"):
            path.write_bytes(data)
            with self.assertRaises(tool.InputError):
                tool.manifest(path)


class GraphTests(ToolkitCase):
    def graph(self):
        return {"schema_version": 1, "nodes": [{"id": n} for n in ("external", "entry", "sink", "unrelated")],
                "initial_facts": ["attacker-can-start"], "context": {}, "edges": [
                    {"id": "e1", "from": "external", "to": "entry", "type": "entry", "status": "confirmed",
                     "prerequisites": ["attacker-can-start"], "establishes": ["input-controlled"], "bindings": {"principal": "attacker", "session": "s1"}},
                    {"id": "e2", "from": "entry", "to": "sink", "type": "data-flow", "status": "candidate",
                     "prerequisites": ["input-controlled"], "establishes": [], "bindings": {"session": "s1"}},
                ]}

    def test_connected_prerequisite_satisfied_candidate(self):
        chains = tool.chain(self.graph())["chains"]
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["edges"], ["e1", "e2"])
        self.assertEqual(chains[0]["status"], "candidate")

    def test_disconnected_cooccurrence_does_not_chain(self):
        graph = self.graph()
        graph["edges"][1]["from"] = "unrelated"
        graph["edges"][1]["prerequisites"] = []
        self.assertEqual(tool.chain(graph)["chains"], [])

    def test_missing_fact_does_not_chain(self):
        graph = self.graph()
        graph["initial_facts"] = []
        result = tool.chain(graph)
        self.assertEqual(result["chains"], [])
        self.assertGreater(result["skipped"]["unsatisfied_prerequisites"], 0)

    def test_incompatible_context_does_not_chain(self):
        graph = self.graph()
        graph["edges"][1]["bindings"]["principal"] = "victim"
        result = tool.chain(graph)
        self.assertEqual(result["chains"], [])
        self.assertGreater(result["skipped"]["incompatible_context"], 0)

    def test_initial_context_constrains_edges(self):
        graph = self.graph()
        graph["context"] = {"session": "different"}
        self.assertEqual(tool.chain(graph)["chains"], [])

    def test_confirmed_edges_not_dynamic_confirmation(self):
        graph = self.graph()
        graph["edges"][1]["status"] = "confirmed"
        result = tool.chain(graph)
        self.assertEqual(result["chains"][0]["status"], "confirmed-edges")
        self.assertIn("does not confirm", " ".join(result["limitations"]))

    def test_cycles_skipped_and_results_bounded(self):
        graph = self.graph()
        graph["edges"].append({"id": "back", "from": "sink", "to": "external", "type": "control-flow", "status": "candidate"})
        result = tool.chain(graph)
        self.assertGreater(result["skipped"]["cycle"], 0)
        bounded = tool.chain(graph, max_results=1)
        self.assertEqual(len(bounded["chains"]), 1)
        self.assertTrue(bounded["truncated"])

    def test_bad_edge_reference_and_duplicate_id_rejected(self):
        graph = self.graph()
        graph["edges"][0]["from"] = ["not-a-string"]
        with self.assertRaises(tool.InputError):
            tool.chain(graph)
        graph = self.graph()
        graph["nodes"].append({"id": "entry"})
        with self.assertRaises(tool.InputError):
            tool.chain(graph)


class EvidenceTests(ToolkitCase):
    def test_dynamic_status_retained_only_with_integrity_complete_triplet(self):
        path, _ = self.engagement()
        result = tool.inspect_engagement(path)
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["findings"][0]["effective_status"], "dynamic-confirmed")
        report = tool.render_report(result)
        for state in tool.STATES:
            self.assertIn("## " + state, report)
        self.assertIn("does not judge", report)

    def test_missing_artifact_downgrades_and_verify_fails(self):
        path, _ = self.engagement()
        (path / "evidence/clean_replay.txt").unlink()
        result = tool.inspect_engagement(path)
        self.assertEqual(result["findings"][0]["effective_status"], "hypothesis")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(tool.main(["verify", "--engagement", str(path)]), 1)

    def test_changed_hash_downgrades(self):
        path, _ = self.engagement()
        (path / "evidence/positive.txt").write_text("changed", encoding="utf-8")
        result = tool.inspect_engagement(path)
        self.assertEqual(result["findings"][0]["effective_status"], "hypothesis")
        self.assertIn("SHA256 mismatch", str(result["issues"]))

    def test_no_attacker_model_downgrades(self):
        path, ledger = self.engagement()
        ledger["findings"][0]["attacker_model"] = ""
        self.save_ledger(path, ledger)
        self.assertEqual(tool.inspect_engagement(path)["findings"][0]["effective_status"], "hypothesis")

    def test_pending_scope_downgrades(self):
        path, _ = self.engagement()
        scope = tool.read_json(path / "scope.json")
        scope["authorization"]["status"] = "pending"
        (path / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
        self.assertEqual(tool.inspect_engagement(path)["findings"][0]["effective_status"], "hypothesis")

    def test_same_artifact_cannot_fill_control_and_replay(self):
        path, ledger = self.engagement()
        evidence = ledger["findings"][0]["evidence"]
        evidence[2] = {**evidence[1], "role": "clean_replay"}
        # Extra positive artifact must not defeat per-role independence check.
        (path / "evidence/extra.txt").write_bytes(b"another positive")
        evidence.append({"role": "positive", "path": "evidence/extra.txt", "sha256": hashlib.sha256(b"another positive").hexdigest()})
        self.save_ledger(path, ledger)
        self.assertEqual(tool.inspect_engagement(path)["findings"][0]["effective_status"], "hypothesis")

    def test_traversal_artifact_is_never_read(self):
        path, ledger = self.engagement()
        (self.root / "outside.txt").write_text("outside", encoding="utf-8")
        ledger["findings"][0]["evidence"][0]["path"] = "../outside.txt"
        ledger["findings"][0]["evidence"][0]["sha256"] = hashlib.sha256(b"outside").hexdigest()
        self.save_ledger(path, ledger)
        with mock.patch.object(tool, "sha256_file", wraps=tool.sha256_file) as hashing:
            result = tool.inspect_engagement(path)
        self.assertFalse(any(Path(call.args[0]).name == "outside.txt" for call in hashing.call_args_list))
        self.assertEqual(result["findings"][0]["effective_status"], "hypothesis")

    def test_symlink_artifact_is_rejected_when_supported(self):
        path, ledger = self.engagement()
        target = path / "evidence/positive.txt"
        link = path / "evidence/link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("Host does not permit creating symlinks")
        ledger["findings"][0]["evidence"][0]["path"] = "evidence/link.txt"
        self.save_ledger(path, ledger)
        self.assertEqual(tool.inspect_engagement(path)["findings"][0]["effective_status"], "hypothesis")

    def test_static_supported_missing_evidence_downgrades(self):
        path, ledger = self.engagement()
        ledger["findings"][0]["status"] = "static-supported"
        ledger["findings"][0]["evidence"] = []
        self.save_ledger(path, ledger)
        self.assertEqual(tool.inspect_engagement(path)["findings"][0]["effective_status"], "hypothesis")

    def test_hypothesis_is_never_upgraded_by_complete_evidence(self):
        path, ledger = self.engagement()
        ledger["findings"][0]["status"] = "hypothesis"
        self.save_ledger(path, ledger)
        self.assertEqual(tool.inspect_engagement(path)["findings"][0]["effective_status"], "hypothesis")

    def test_untrusted_markdown_not_active(self):
        path, ledger = self.engagement()
        ledger["findings"][0]["title"] = '<script>x</script> ![beacon](https://example.test)\n# Fake heading'
        self.save_ledger(path, ledger)
        report = tool.render_report(tool.inspect_engagement(path))
        self.assertNotIn("<script>", report)
        self.assertNotIn("![beacon]", report)
        self.assertNotIn("\n# Fake heading", report)


class UtilityTests(ToolkitCase):
    def test_no_overwrite(self):
        path = self.root / "existing.txt"
        path.write_text("original", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            tool.write_new(path, "replacement")
        self.assertEqual(path.read_text(encoding="utf-8"), "original")

    def test_init_refuses_existing_directory(self):
        with self.assertRaises(FileExistsError):
            tool.init_engagement(self.root)

    def test_duplicate_json_keys_and_nan_rejected(self):
        path = self.root / "input.json"
        for data in ('{"schema_version":1,"schema_version":2}', '{"value": NaN}'):
            path.write_text(data, encoding="utf-8")
            with self.assertRaises(tool.InputError):
                tool.read_json(path)

    def test_doctor_discovers_without_execution(self):
        with mock.patch.object(tool.shutil, "which", return_value="/fixture/path/tool") as discovery:
            result = tool.doctor()
        self.assertEqual(discovery.call_count, len(result["tools"]))
        self.assertTrue(all(not entry["executed"] and not entry["version_verified"] for entry in result["tools"].values()))

    def test_bad_schema_cli_returns_two_without_traceback(self):
        graph = self.json_file("graph.json", {"schema_version": 2})
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = tool.main(["chain", "--graph", str(graph), "--out", str(self.root / "out.json")])
        self.assertEqual(status, 2)
        self.assertIn("ERROR:", error.getvalue())
        self.assertNotIn("Traceback", error.getvalue())
        self.assertFalse((self.root / "out.json").exists())


if __name__ == "__main__":
    unittest.main()
