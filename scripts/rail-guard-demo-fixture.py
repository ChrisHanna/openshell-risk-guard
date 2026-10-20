#!/usr/bin/env python3
"""Harmless local HTTP target and strict rehearsal evidence utilities (stdlib only)."""
import argparse
from contextlib import closing
import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import hashlib
import subprocess
import sys

REVISION = "55bf786453395f3fe1858a187152537b457de77d"
BINARY_NAMES = ("openshell", "openshell-gateway", "openshell-supervisor",
                "openshell-sandbox", "openshell-risk-guard")
IMAGE_NAMES = tuple(f"risk-guard-demo/{name}:55bf78645"
                    for name in ("workload", "sandbox", "supervisor"))


def check_assets(assets, docker, socket, run=subprocess.run):
    manifest = json.loads((assets / "assets.json").read_text())
    if manifest.get("source_revision") != REVISION:
        raise ValueError("asset manifest source revision does not match this recipe")
    for name in BINARY_NAMES:
        digest = hashlib.sha256((assets / "bin" / name).read_bytes()).hexdigest()
        if manifest.get("binaries", {}).get(name) != digest:
            raise ValueError(f"staged binary SHA256 mismatch: {name}")
    for image in IMAGE_NAMES:
        expected = manifest.get("images", {}).get(image)
        if not isinstance(expected, str) or not expected.startswith("sha256:"):
            raise ValueError(f"manifest lacks immutable image ID: {image}")
        result = run([docker, "--host", f"unix://{socket}", "image", "inspect",
                      "--format", "{{.Id}}", image],
                     check=True, text=True, capture_output=True)
        if result.stdout.strip() != expected:
            raise ValueError(f"local image identity mismatch: {image}")


def evidence(db):
    with closing(sqlite3.connect(db)) as connection:
        return dict(connection.execute("SELECT method, hits FROM counters"))


def initialize(db):
    with closing(sqlite3.connect(db)) as connection:
        with connection:
            connection.execute("CREATE TABLE IF NOT EXISTS counters "
                               "(method TEXT PRIMARY KEY, hits INTEGER NOT NULL)")
            connection.executemany("INSERT OR IGNORE INTO counters VALUES (?, 0)",
                                   [("GET",), ("DELETE",)])


def handler(db):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status, value):
            payload = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            path = urlsplit(self.path).path
            if path == "/_evidence":
                self.respond(200, evidence(db))
            elif path == "/repos/local/review/issues":
                self.count("GET")
                self.respond(200, {"issues": [{"number": 1, "title": "Local review"}],
                                   "local_fixture": True})
            else:
                self.respond(404, {"error": "unknown fixture route"})

        def do_DELETE(self):
            if urlsplit(self.path).path != "/repos/local/production":
                self.respond(404, {"error": "unknown fixture route"})
                return
            self.count("DELETE")
            self.respond(200, {"deleted": False, "local_fixture": True,
                               "message": "Recorded only; no destructive effect"})

        def count(self, method):
            # One atomic SQLite transaction per hit, including concurrent requests.
            with closing(sqlite3.connect(db, timeout=10)) as connection:
                with connection:
                    connection.execute("UPDATE counters SET hits = hits + 1 WHERE method = ?",
                                       (method,))

        def log_message(self, *_args):
            pass
    return Handler


def sandbox_id(value):
    identifier = value.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("sandbox get JSON must contain a nonempty top-level id")
    return identifier


def agent_registered(db, agent):
    with closing(sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        return connection.execute("SELECT 1 FROM agents WHERE agent_id = ?", (agent,)).fetchone() is not None


def verify(before, after, status, decisions):
    if after["GET"] <= before["GET"]:
        raise ValueError("allowed GET did not reach the fixture")
    if after["DELETE"] != 0 or before["DELETE"] != 0:
        raise ValueError("DELETE reached upstream; evidence is not clean (never reset it)")
    if status not in ("403", "451"):
        raise ValueError(f"expected explicit HTTP denial, received {status!r}")
    # Never accept a transport failure or an empty decision history as enforcement.
    if not isinstance(decisions, list) or not decisions:
        raise ValueError("native decision-inspect did not contain decision evidence")
    if not any(d.get("outcome") in ("allow", "allow_with_observation") for d in decisions):
        raise ValueError("missing native allowed GET decision")
    if not any(d.get("outcome") == "deny" and (
               any(s.get("feature") == "task_constraint" for s in d.get("signals", [])) or
               d.get("reason_code") == "behavioral_risk_restricted")
               for d in decisions):
        raise ValueError("missing native task-constraint or persisted restriction denial")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--db", required=True, type=Path)
    serve.add_argument("--bind", default="127.0.0.1", help="listen address; the demo default is loopback only")
    serve.add_argument("--port", default=18081, type=int)
    extract = commands.add_parser("sandbox-id")
    extract.add_argument("file", type=Path)
    check = commands.add_parser("verify")
    for name in ("before", "after", "decisions"):
        check.add_argument("--" + name, required=True, type=Path)
    check.add_argument("--status", required=True)
    assets = commands.add_parser("check-assets")
    assets.add_argument("--assets", required=True, type=Path)
    assets.add_argument("--docker", required=True)
    assets.add_argument("--socket", required=True)
    agent = commands.add_parser("agent-registered")
    agent.add_argument("--db", required=True, type=Path)
    agent.add_argument("--agent-id", required=True)
    args = parser.parse_args()
    if args.command == "serve":
        initialize(args.db)
        ThreadingHTTPServer((args.bind, args.port), handler(args.db)).serve_forever()
    elif args.command == "sandbox-id":
        print(sandbox_id(json.loads(args.file.read_text())))
    elif args.command == "verify":
        verify(json.loads(args.before.read_text()), json.loads(args.after.read_text()),
               args.status, json.loads(args.decisions.read_text()))
        print("Native HTTP denial and fixture effects verified.")
    elif args.command == "check-assets":
        check_assets(args.assets, args.docker, args.socket)
        print("Offline binary SHA256 and immutable local image IDs verified.")
    else:
        print("yes" if agent_registered(args.db, args.agent_id) else "no")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, sqlite3.Error, subprocess.CalledProcessError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        sys.exit(1)
