"""The hardened-profile check must fail when it should, not only pass on the repository as it is.

Each case copies the files the check reads into a temporary tree, breaks one thing, and expects the check to refuse it.
"""

import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent


def load_checker():
    spec = importlib.util.spec_from_file_location("check_deployment", HERE / "check-risk-guard-deployment.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HardenedProfileCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "deploy").mkdir()
        shutil.copytree(REPO / "deploy" / "aks", self.tmp / "deploy" / "aks")
        (self.tmp / "scripts").mkdir()
        shutil.copytree(REPO / "scripts" / "aks", self.tmp / "scripts" / "aks")
        shutil.copytree(REPO / "scripts" / "conformance", self.tmp / "scripts" / "conformance")
        shutil.copy(REPO / "Dockerfile", self.tmp / "Dockerfile")
        self.checker = load_checker()
        self.checker.ROOT = self.tmp
        self.checker.DEPLOY = self.tmp / "deploy"
        self.aks = self.tmp / "deploy" / "aks"

    def test_the_repository_as_it_is_passes(self):
        self.checker.check_aks_hardened()

    def test_a_file_in_neither_list_is_refused(self):
        (self.aks / "new-thing.yaml").write_text("kind: ConfigMap\n")
        with self.assertRaisesRegex(AssertionError, "neither list"):
            self.checker.check_aks_hardened()

    def test_a_placeholder_no_script_fills_is_refused(self):
        path = self.aks / "supervisor-fence.yaml"
        path.write_text(path.read_text() + "\n# __NOBODY_FILLS_THIS__\n")
        with self.assertRaisesRegex(AssertionError, "placeholders"):
            self.checker.check_aks_hardened()

    def test_a_local_test_flag_in_a_supported_manifest_is_refused(self):
        path = self.aks / "risk-guard.yaml"
        path.write_text(path.read_text().replace("            - --svid-listen", "            - --allow-insecure-local-test\n            - --svid-listen", 1)
                        if "--svid-listen" in path.read_text() else path.read_text() + "\n# --allow-insecure-local-test\n")
        with self.assertRaisesRegex(AssertionError, "local testing"):
            self.checker.check_aks_hardened()

    def test_a_latest_tag_is_refused(self):
        path = self.aks / "sandbox-egress.yaml"
        path.write_text(path.read_text() + "\n# image: envoy:latest\n")
        with self.assertRaisesRegex(AssertionError, "local testing"):
            self.checker.check_aks_hardened()

    def test_two_writers_are_refused(self):
        path = self.aks / "risk-guard.yaml"
        text = path.read_text()
        self.assertIn("replicas: 1", text)
        path.write_text(text.replace("replicas: 1", "replicas: 2", 1))
        with self.assertRaises(AssertionError):
            self.checker.check_aks_hardened()

    def test_a_base_image_without_a_digest_is_refused(self):
        path = self.tmp / "Dockerfile"
        import re
        path.write_text(re.sub(r"@sha256:[0-9a-f]{64}", "", path.read_text(), count=1))
        with self.assertRaisesRegex(AssertionError, "digest"):
            self.checker.check_aks_hardened()

    def test_a_container_that_runs_as_root_is_refused_by_the_baseline(self):
        path = self.aks / "sandbox-egress.yaml"
        text = path.read_text()
        self.assertIn("runAsNonRoot: true", text)
        path.write_text(text.replace("runAsNonRoot: true", "runAsNonRoot: false").replace("runAsUser: 101", "runAsUser: 0"))
        with self.assertRaisesRegex(AssertionError, "baseline"):
            self.checker.check_aks_hardened()


if __name__ == "__main__":
    unittest.main()
