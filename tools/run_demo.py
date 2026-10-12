#!/usr/bin/env python3
"""Create and analyze synthetic local fixtures. Never tests a real Android target."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / "mobiledestro-v1" / "scripts" / "mobiledestro.py"
TRIAGE = ROOT / "mobiledestro-v1" / "helpers" / "triage_inputs.py"


def call(script, *args):
    subprocess.run([sys.executable, "-B", str(script), *map(str, args)], check=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", required=True, type=Path)
    a = p.parse_args()
    call(CORE, "init", "--out", a.out)
    fixture = a.out / "inputs" / "decoded"
    fixture.mkdir()
    manifest = fixture / "AndroidManifest.xml"
    manifest.write_text('''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.synthetic">
<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="33"/>
<application android:permission="com.example.synthetic.PRIVATE">
<activity android:name=".Entry" android:exported="true"/>
<provider android:name=".SafeProvider" android:authorities="com.example.synthetic.data"/>
</application></manifest>''', encoding="utf-8")
    (fixture / "Example.java").write_text('// Synthetic API marker only; not an executable target.\nwebView.loadUrl(candidate);\n', encoding="utf-8")
    archive = a.out / "inputs" / "synthetic-container.zip"
    with zipfile.ZipFile(archive, "x") as z:
        z.write(manifest, "AndroidManifest.xml")
        z.writestr("NOTICE.txt", "Synthetic container; not an installable or signed APK.")
    graph = {"schema_version": 1, "nodes": [{"id": x} for x in ("caller", "entry", "operation")],
             "initial_facts": ["synthetic-fixture"], "context": {"build": "SYNTHETIC-NOT-A-TARGET"}, "edges": [
                 {"id": "E1", "from": "caller", "to": "entry", "type": "entry", "status": "candidate",
                  "prerequisites": ["synthetic-fixture"], "establishes": ["input-at-entry"], "bindings": {"principal": "test-A"}},
                 {"id": "E2", "from": "entry", "to": "operation", "type": "data-flow", "status": "candidate",
                  "prerequisites": ["input-at-entry"], "bindings": {"principal": "test-A"}}]}
    (a.out / "graph.json").write_text(json.dumps(graph, indent=2), encoding="utf-8")
    ledger = {"schema_version": 1, "findings": [{"id": "DEMO-ONLY", "title": "Synthetic unverified hypothesis",
              "status": "hypothesis", "severity": "unrated", "description": "This demonstrates report structure only. No real application or runtime was tested.",
              "coverage_ids": ["webview"], "evidence": []}]}
    (a.out / "ledger.json").write_text(json.dumps(ledger, indent=2), encoding="utf-8")
    call(CORE, "intake", "--input", archive, "--out", a.out / "analysis" / "intake.json")
    call(CORE, "manifest", "--input", manifest, "--device-api", "35", "--out", a.out / "analysis" / "manifest.json")
    call(CORE, "chain", "--graph", a.out / "graph.json", "--out", a.out / "analysis" / "chains.json")
    call(TRIAGE, "scan", "--source", fixture, "--out", a.out / "analysis" / "source-index.json")
    call(CORE, "verify", "--engagement", a.out, "--out", a.out / "analysis" / "verification.json")
    call(CORE, "report", "--engagement", a.out, "--out", a.out / "reports" / "demo-report.md")
    print("Synthetic demo complete. No device, network, real APK, or credentials were used.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"Demo failed: {e}", file=sys.stderr)
        sys.exit(2)
