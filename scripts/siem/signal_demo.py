#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Send Risk Guard a signal the way the SIEM does, or list what it has received.

    python scripts/siem/signal_demo.py --list
    python scripts/siem/signal_demo.py --sandbox <sandbox id> [--ttl 120] [--dry-run]

The request is made from the OpenSearch pod (the only place the network policy lets reach Risk Guard's signals port), with the token read from its Secret and
handed to curl on standard input, so it is never in a command line or printed.
"""
import argparse
import base64
import json
import subprocess
import sys
import uuid

sys.path.insert(0, __import__("os").path.dirname(__file__))
import install_content as siem  # noqa: E402  (finds where the alert's webhook goes: the SIEM-side forwarder, or Risk Guard directly)

URL, _ = siem.signals_target()


def token():
    return siem.signals_target()[1]


def call(method, url, body=None):
    # curl reads its configuration (including the secret header) from stdin; the body goes in a second pass through --data-binary @file inside the pod.
    config = f'header = "Authorization: Bearer {token()}"\nheader = "Content-Type: application/json"\nurl = "{url}"\nrequest = "{method}"\nsilent\nwrite-out = "\\n%{{http_code}}"\n'
    if body is not None:
        config += "data-binary = " + json.dumps(json.dumps(body)) + "\n"
    out = subprocess.run(["kubectl", "exec", "-i", "-n", "siem", "opensearch-cluster-master-0", "--", "curl", "-K", "-"], input=config.encode(), capture_output=True)
    text = out.stdout.decode()
    payload, _, code = text.rpartition("\n")
    return int(code or 0), (json.loads(payload) if payload.strip() else {})


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--sandbox")
    parser.add_argument("--agent")
    parser.add_argument("--ttl", type=int, default=120)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.list:
        if URL.endswith("/webhook"):
            sys.exit("With the forwarder in front of Risk Guard there is no list endpoint on this path (the forwarder only forwards). See the API Activity events in the SIEM, or Risk Guard's logs.")
        code, body = call("GET", URL + "?limit=20")
        print(code)
        for row in body.get("signals", []):
            print(f"  {row['signal_id']:44s} {row['outcome']:20s} {row.get('agent_id')}  ttl={row['ttl_seconds']}s  {row['source']}")
        return
    if not (args.sandbox or args.agent):
        sys.exit("give --sandbox or --agent")
    body = {"signal_id": "demo-" + uuid.uuid4().hex[:12], "source": "signal-demo", "action": "quarantine", "ttl_seconds": args.ttl,
            "reason": "manual demonstration signal", "dry_run": args.dry_run}
    body["sandbox_id" if args.sandbox else "agent_id"] = args.sandbox or args.agent
    code, answer = call("POST", URL, body)
    print(code, json.dumps(answer))


if __name__ == "__main__":
    main()
