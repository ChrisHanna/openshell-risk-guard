"""Offline tests: no Docker mutation, native service startup, or cloud access."""
import concurrent.futures
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import threading
import unittest
import urllib.error
import urllib.request
import uuid

SCRIPTS = Path(__file__).resolve().parent
ROOT = SCRIPTS.parent
SPEC = importlib.util.spec_from_file_location("demo_fixture", SCRIPTS / "rail-guard-demo-fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class WorkspaceCase(unittest.TestCase):
    def setUp(self):
        # Keep all test files inside the workspace, never OS temporary directories.
        self.work = ROOT / (".demo-test-" + uuid.uuid4().hex)
        self.work.mkdir()

    def tearDown(self):
        shutil.rmtree(self.work)


class FixtureTests(WorkspaceCase):
    def setUp(self):
        super().setUp()
        self.db = self.work / "fixture.db"
        fixture.initialize(self.db)
        self.server = fixture.ThreadingHTTPServer(("127.0.0.1", 0), fixture.handler(self.db))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        super().tearDown()

    def request(self, path, method="GET"):
        with self.opener.open(urllib.request.Request(self.base + path, method=method),
                              timeout=5) as response:
            return json.load(response)

    def test_evidence_does_not_count_itself(self):
        self.assertEqual(self.request("/_evidence"), {"GET": 0, "DELETE": 0})
        self.assertEqual(self.request("/_evidence"), {"GET": 0, "DELETE": 0})

    def test_only_expected_routes_and_no_destructive_effect(self):
        self.assertTrue(self.request("/repos/local/review/issues")["local_fixture"])
        self.assertFalse(self.request("/repos/local/production", "DELETE")["deleted"])
        with self.assertRaises(urllib.error.HTTPError):
            self.request("/repos/elsewhere/production", "DELETE")
        self.assertEqual(self.request("/_evidence"), {"GET": 1, "DELETE": 1})
        fixture.initialize(self.db)
        self.assertEqual(fixture.evidence(self.db), {"GET": 1, "DELETE": 1})

    def test_concurrent_counters_are_transactional(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _: self.request("/repos/local/review/issues"), range(32)))
        self.assertEqual(fixture.evidence(self.db)["GET"], 32)


class EvidenceTests(unittest.TestCase):
    def test_actual_sandbox_identity_required(self):
        self.assertEqual(fixture.sandbox_id({"id": "native-123"}), "native-123")
        for value in ({}, {"sandbox_id": "guess"}, {"id": ""}, {"id": 123}):
            with self.assertRaises(ValueError):
                fixture.sandbox_id(value)

    def test_native_allow_and_task_constraint_deny_required(self):
        decisions = [{"outcome": "allow_with_observation"}, {
            "outcome": "deny", "signals": [{"feature": "task_constraint"}]}]
        fixture.verify({"GET": 0, "DELETE": 0}, {"GET": 1, "DELETE": 0}, "403", decisions)
        fixture.verify({"GET": 1, "DELETE": 0}, {"GET": 2, "DELETE": 0}, "403",
                       [{"outcome": "allow"}, {"outcome": "deny",
                        "reason_code": "behavioral_risk_restricted"}])
        for status in ("000", "200", "500", ""):
            with self.assertRaises(ValueError):
                fixture.verify({"GET": 0, "DELETE": 0}, {"GET": 1, "DELETE": 0},
                               status, decisions)
        for before, after, evidence in (
            ({"GET": 0, "DELETE": 0}, {"GET": 0, "DELETE": 0}, decisions),
            ({"GET": 0, "DELETE": 0}, {"GET": 1, "DELETE": 1}, decisions),
            ({"GET": 0, "DELETE": 1}, {"GET": 1, "DELETE": 1}, decisions),
            ({"GET": 0, "DELETE": 0}, {"GET": 1, "DELETE": 0}, []),
            ({"GET": 0, "DELETE": 0}, {"GET": 1, "DELETE": 0}, [{"outcome": "deny"}]),
        ):
            with self.assertRaises(ValueError):
                fixture.verify(before, after, "403", evidence)


class AssetTests(WorkspaceCase):
    def setUp(self):
        super().setUp()
        (self.work / "bin").mkdir()
        binaries = {}
        for name in fixture.BINARY_NAMES:
            content = name.encode()
            (self.work / "bin" / name).write_bytes(content)
            binaries[name] = hashlib.sha256(content).hexdigest()
        self.manifest = {"source_revision": fixture.REVISION, "binaries": binaries,
                         "images": {name: "sha256:" + "a" * 64 for name in fixture.IMAGE_NAMES}}
        self.save()
        self.calls = []

    def save(self):
        (self.work / "assets.json").write_text(json.dumps(self.manifest))

    def docker_inspect(self, args, **kwargs):
        self.calls.append(args)
        self.assertEqual(args[1:5], ["--host", "unix:///isolated.sock", "image", "inspect"])
        self.assertTrue(kwargs["check"])
        return subprocess.CompletedProcess(args, 0, stdout="sha256:" + "a" * 64 + "\n")

    def check(self):
        fixture.check_assets(self.work, "/offline/docker", "/isolated.sock", self.docker_inspect)

    def test_manifest_requires_all_binary_hashes_and_local_image_ids(self):
        self.check()
        self.assertEqual(len(self.calls), 3)

    def test_tampering_fails_before_docker(self):
        (self.work / "bin" / "openshell").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA256"):
            self.check()
        self.assertFalse(self.calls)

    def test_wrong_revision_rejected(self):
        self.manifest["source_revision"] = "old"
        self.save()
        with self.assertRaisesRegex(ValueError, "revision"):
            self.check()

    def test_missing_image_identity_rejected(self):
        self.manifest["images"] = {}
        self.save()
        with self.assertRaisesRegex(ValueError, "immutable"):
            self.check()

    def test_retagged_image_rejected(self):
        self.manifest["images"][fixture.IMAGE_NAMES[0]] = "sha256:" + "b" * 64
        self.save()
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.check()


class IdentityTests(WorkspaceCase):
    def test_persistent_agent_lookup_is_read_only(self):
        db = self.work / "identity.db"
        connection = sqlite3.connect(db)
        try:
            connection.execute("CREATE TABLE agents (agent_id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO agents VALUES ('demo-reviewer')")
            connection.commit()
        finally:
            connection.close()
        original = db.read_bytes()
        self.assertTrue(fixture.agent_registered(db, "demo-reviewer"))
        self.assertFalse(fixture.agent_registered(db, "other"))
        self.assertEqual(db.read_bytes(), original)


class ConfigTests(unittest.TestCase):
    def test_baseline_is_honest_cold_start_and_policy_allows_delete(self):
        config = ROOT / "deploy" / "rail-guard-demo"
        if not config.is_dir():
            config = ROOT / "openshell-risk-guard" / "deploy" / "rail-guard-demo"
        baseline = json.loads((config / "baseline.json").read_text())
        self.assertEqual(baseline["version"], "v1")
        self.assertEqual(baseline["normalizer_version"], "v1")
        self.assertIn("GET /repos/{owner}/{repo}/issues", baseline["allowed_action_classes"])
        self.assertEqual(baseline["training_sessions"], 0)
        self.assertEqual(baseline["training_requests"], 0)
        self.assertTrue(baseline["forbid_unfamiliar_high_impact"])
        self.assertEqual(baseline["approved_resources"], ["local/review"])
        policy = (config / "sandbox-policy.yaml").read_text()
        self.assertIn("method: DELETE", policy)
        self.assertIn("/repos/local/production", policy)
        self.assertIn("path: /usr/bin/curl", policy)


if __name__ == "__main__":
    unittest.main()
