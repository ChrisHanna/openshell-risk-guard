#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""The end-state demo: OpenShell enforces the approved routes, Risk Guard decides what a path rule cannot. Driven against the real deployment; nothing here is simulated.

    scripts/demo/end_state.py --prepare        once, before the meeting: create the standing sandbox with the enforce + demo-exceptions policy (about a minute)
    scripts/demo/end_state.py [--pause]        the five acts (about two minutes plus the SIEM check); --pause waits for Enter between acts
    scripts/demo/end_state.py --cleanup        remove the sandbox and the workload's restrictions

  A  A routine allowed call passes both layers.
  B  A destructive call that is NOT an exception is refused by OpenShell's policy (policy_denied). Risk Guard never saw it. OpenShell's own event is shown, then found in the SIEM.
  C  A call the demo exception lets through OpenShell reaches Risk Guard, which refuses it (the rule is named) and latches a lock on that route and resource for the workload.
  D  The same approved route on a resource the profile does not approve is refused by Risk Guard's resource rule (the rule is enforcing for this profile only).
  E  The agreement tool's numbers for the fleet's audit run, which is the evidence for enforcing the fleet.

DEMO DISCLOSURE. The sandbox runs deploy/aks/agents/<profile>/policy.enforce.demo.yaml. That policy is deliberately WEAKER than the profile's baseline: it also allows the calls in
demo-exceptions.json so that they reach Risk Guard. The weakening is stated in the policy's rule name, in the line printed before every run, and again in act C. The fleet never runs it.

The default profile, demo-end-state, needs its baseline imported into the Risk Guard deployment (deploy/aks/risk-guard.yaml has the init container; scripts/aks/04-deploy-risk-guard.ps1
applies it). Until that is done --prepare says so and stops. `--profile release` runs the same acts against the live release-ops profile, where act D is shown honestly as the rule
only watching (shadow), not refusing.
"""
import argparse
import base64
import json
import os
import re
import subprocess
import sys
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "scripts", "policy"))
sys.path.insert(0, os.path.join(ROOT, "scripts", "siem"))
import run_demo as rd  # noqa: E402  (kubectl, fleet and Risk Guard helpers shared with the partner demo)

SANDBOX = "demo-endstate"
HOST = "deploy-api.openshell.svc.cluster.local"
DB = rd.DB
IMAGE_TAG = os.environ.get("END_STATE_IMAGE_TAG", "3")
BOLD, DIM, GREEN, RED, AMBER, RESET = rd.BOLD, rd.DIM, rd.GREEN, rd.RED, rd.AMBER, rd.RESET
# The calls of each act. `resource_rule_enforcing` is what the profile's baseline says; the script also reads the answer from Risk Guard and reports what it saw.
PROFILES = {
    "demo-end-state": {"workload": "demo-end-state", "dir": "demo-end-state", "task_profile": "demo-end-state", "resource_rule_enforcing": True},
    "release": {"workload": "endstate-release", "dir": "release", "task_profile": "release-ops", "resource_rule_enforcing": False},
}
ACT_A = ("GET", "/services")
ACT_B = ("POST", "/services/payments/rollback")   # destructive; the profile approves no POST, and it is not an exception
ACT_C = ("DELETE", "/services/worker")            # the reviewed exception: passes OpenShell, reaches Risk Guard
ACT_D = ("GET", "/services/payments")             # an approved route shape on a resource the profile does not approve
ACT_FOLLOWUP = ("GET", "/services")

CALL = r'''
import http.client, json, sys
method, path = sys.argv[1], sys.argv[2]
out = {"status": None, "body": "", "error": None}
try:
    c = http.client.HTTPConnection("%s", 18081, timeout=20)
    c.request(method, path)
    r = c.getresponse()
    out["status"], out["body"] = r.status, r.read(600).decode("utf-8", "replace")
except Exception as e:
    out["error"] = type(e).__name__ + ": " + str(e)[:100]
print("RESULT " + json.dumps(out))
''' % HOST


def say(text="", style=""):
    print(f"{style}{text}{RESET}", flush=True)


def act(letter, title, pause):
    if pause:
        input(f"\n{DIM}[Enter] to start act {letter}{RESET}")
    say(f"\nAct {letter}  {title}", BOLD)


def profile_files(cfg):
    base = os.path.join(ROOT, "deploy", "aks", "agents", cfg["dir"])
    return os.path.join(base, "policy.enforce.demo.yaml"), os.path.join(base, "demo-exceptions.json")


def exceptions_of(cfg):
    with open(profile_files(cfg)[1], encoding="utf-8") as f:
        return json.load(f)["exceptions"]


def disclosure(cfg, effective_rule_name=None):
    ex = exceptions_of(cfg)
    listed = "; ".join(f"{e['method']} {e['path']}" for e in ex)
    say("  ┌" + "─" * 118, AMBER)
    say(f"  │ DEMO NOTICE: this sandbox's OpenShell policy is deliberately WEAKER than the {cfg['task_profile']} baseline.", AMBER)
    say(f"  │ It also allows: {listed}. Those calls reach Risk Guard on purpose; every other rule is the baseline's.", AMBER)
    if effective_rule_name:
        say(f"  │ Read back from the gateway: the sandbox's policy rule is named \"{effective_rule_name}\".", AMBER)
    say("  └" + "─" * 118, AMBER)


def sandbox_json():
    out = rd.fleet("openshell", "sandbox", "get", SANDBOX, "--output", "json", check=False)
    try:
        return json.loads(out)
    except ValueError:
        return None


def effective_rule_name():
    out = rd.fleet("openshell", "policy", "get", SANDBOX, "--full", check=False)
    match = re.search(r"name:\s*\"?([^\n\"]*DEMO EXCEPTIONS: \d+\))", out)
    return match.group(1) if match else None


def call(method, path):
    script = base64.b64encode(CALL.encode()).decode()
    out = rd.fleet("openshell", "sandbox", "exec", "--name", SANDBOX, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c",
                   f"echo {script} | base64 -d > /tmp/c.py; /opt/agent/bin/python3.12 /tmp/c.py {method} '{path}'", check=False, timeout=90)
    for line in out.splitlines():
        if line.startswith("RESULT "):
            return json.loads(line[7:])
    return {"status": None, "body": "", "error": "no answer: " + out.strip()[-120:]}


def body_json(result):
    try:
        return json.loads(result.get("body") or "")
    except ValueError:
        return {}


def ocsf(sandbox_id, since):
    """OpenShell's own security events for the sandbox since `since` (epoch seconds), from its supervisor's log: what a SIEM receives."""
    lines = []
    for line in rd.kubectl("logs", f"pod/os-supervisor-{sandbox_id}", f"--since={max(10, int(time.time() - since) + 5)}s", check=False).splitlines():
        if "OCSF-JSON " not in line:
            continue
        try:
            r = json.loads(line.split("OCSF-JSON ", 1)[1])
        except ValueError:
            continue
        message = r.get("message") or ""
        if r.get("time", 0) < int(since * 1000) - 300:
            continue
        if r.get("class_uid") == 4002 and (message.startswith("L7_REQUEST") or message.startswith("MIDDLEWARE")):
            lines.append(f"  OCSF  HTTP Activity   {str(r.get('action')):8} {message[:130]}" + (f"   [{r['status_detail']}]" if r.get("status_detail") else ""))
    return lines


def show_events(sandbox_id, started):
    time.sleep(3)
    shown = ocsf(sandbox_id, started)
    for line in shown:
        say(line, DIM)
    if not shown:
        say("  (no OCSF records found: is ocsf_json_enabled set? `openshell settings set --global --key ocsf_json_enabled --value true --yes`)", AMBER)
    return shown


def decisions(sandbox_id, limit=500):  # decision-inspect returns the oldest first, so ask for all and read the last
    out = rd.risk_guard("decision-inspect", "--db", DB, "--sandbox-id", sandbox_id, "--limit", str(limit), check=False)
    try:
        return json.loads(out)
    except ValueError:
        return []


def rules_of(decision):
    """The rules behind a Risk Guard decision, from its own signals: (enforced, watching). The deny path records `rules=a,b; ...`; a shadow hit records `rule=x; mode=shadow`."""
    enforced, watching = [], []
    for signal in decision.get("signals", []):
        text = signal.get("baseline_summary") or ""
        if text.startswith("rules="):
            enforced += [r for r in text[6:].split(";")[0].split(",") if r]
        elif text.startswith("rule=") and "mode=shadow" in text:
            watching.append(text[5:].split(";")[0])
    return enforced, watching


def say_decision(decision_list, leading):
    if not decision_list:
        say("  Risk Guard: no decision recorded for this call", AMBER)
        return None
    d = decision_list[-1]
    enforced, watching = rules_of(d)
    ratchet = d.get("ratchet_action") or {}
    say(f"  {leading}: outcome {d.get('outcome')}, reason {d.get('reason_code')}, score {d.get('risk_score')} of {d.get('threshold')}", DIM)
    if enforced:
        say(f"    rule(s) that refused it: {', '.join(enforced)}", RED)
    if watching:
        say(f"    rule(s) only watching (shadow, did not block): {', '.join(watching)}", AMBER)
    if ratchet.get("type", "none") != "none":
        say(f"    ratchet: {ratchet.get('type')} on scope '{ratchet.get('scope')}'", RED)
    return d


def siem_signal(decision):
    """The `siem_context` signal of a Risk Guard decision, or None: what OpenSearch's features added to this call's score."""
    for signal in (decision or {}).get("signals", []):
        if signal.get("feature") == "siem_context":
            return signal
    return None


def restrictions(workload):
    out = rd.risk_guard("restriction-list", "--db", DB, "--agent-id", workload, check=False)
    try:
        return json.loads(out).get("restrictions", [])
    except ValueError:
        return []


def clear_restrictions(workload, why):
    cleared = []
    for r in restrictions(workload):
        scope = r.get("scope")
        if scope:
            rd.risk_guard("restriction-clear", "--db", DB, "--agent-id", workload, "--scope", scope, "--operator", "end-state-demo", "--reason", why, "--break-glass", check=False)
            cleared.append(scope)
    return cleared


def prepare(cfg):
    policy_file, _ = profile_files(cfg)
    if not os.path.exists(policy_file):
        sys.exit(f"{policy_file} does not exist; run scripts/policy/generate_audit_policies.py")
    acr = rd.kubectl("get", "deploy/agent-fleet", "-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ACR_SERVER\")].value}").strip()
    policy = open(policy_file, "rb").read()
    say("Preparing the end-state demo sandbox", BOLD)
    disclosure(cfg)
    rd.risk_guard("agent-register", "--db", DB, "--agent-id", cfg["workload"], "--display-name", f"End-state demo ({cfg['task_profile']})", check=False)
    rd.fleet("sh", "-c", f"echo {base64.b64encode(policy).decode()} | base64 -d > /tmp/end-state-policy.yaml")
    say(f"creating sandbox {SANDBOX} (about a minute)...")
    rd.fleet("openshell", "sandbox", "create", "--name", SANDBOX, "--from", f"{acr}/openshell-demo/nat-agent:{IMAGE_TAG}", "--policy", "/tmp/end-state-policy.yaml",
             "--provider", "nvidia-nat", "--annotation", f"openshell.nvidia.com/agent-id={cfg['workload']}", "--annotation", "openshell.nvidia.com/agent-name=end-state-demo",
             "--no-tty", "--detach", "--", "/usr/bin/sleep", "infinity", timeout=240, check=False)
    for _ in range(40):
        if '"Ready"' in rd.fleet("openshell", "sandbox", "get", SANDBOX, "--output", "json", check=False).replace('": "', '":"'):
            break
        time.sleep(6)
    else:
        sys.exit("the sandbox did not become ready")
    result = call(*ACT_A)
    code = body_json(result).get("error")
    if result["status"] == 200:
        say(f"ready. first call GET /services -> 200 through OpenShell and Risk Guard. Policy rule on the gateway: {effective_rule_name()}", GREEN)
    elif code == "middleware_failed":
        rd.fleet("openshell", "sandbox", "delete", SANDBOX, check=False)
        sys.exit(f"Risk Guard could not evaluate the call (middleware_failed). For profile {cfg['task_profile']} the usual cause is that its baseline is not imported into the running Risk Guard: "
                 "deploy/aks/risk-guard.yaml has the init container baseline-import-demo-end-state and scripts/aks/04-deploy-risk-guard.ps1 applies it (a Risk Guard redeploy, not done by this script). "
                 "The sandbox was removed.")
    else:
        say(f"ready, but the first call answered {result['status']} {code or result['error']}: check the sandbox before the meeting", AMBER)


def cleanup(cfg):
    cleared = clear_restrictions(cfg["workload"], "end-state demo cleanup")
    rd.fleet("openshell", "sandbox", "delete", SANDBOX, check=False)
    say(f"sandbox removed; {len(cleared)} restriction(s) of workload {cfg['workload']} cleared" + (" (recorded in Risk Guard's audit trail as break-glass by end-state-demo)" if cleared else ""))


def siem_check(sandbox_id, started, expected, wait):
    """Find OpenShell's records of the calls in the SIEM (OpenSearch). Ingestion usually takes seconds (measured 5 to 8 s), so poll."""
    import install_content as siem
    say("\nThe same events in the SIEM (OpenSearch, index ocsf-openshell)", BOLD)
    deadline = time.time() + wait
    rows, found = [], set()
    while True:
        result = siem.opensearch("POST", "/ocsf-openshell*/_search", {"size": 200, "sort": [{"time": "asc"}], "query": {"bool": {"filter": [
            {"term": {"container.name.keyword": SANDBOX}}, {"range": {"time": {"gte": int(started * 1000) - 5000}}}, {"exists": {"field": "http_request.url.path"}}]}}})
        rows = [h["_source"] for h in result.get("hits", {}).get("hits", [])]
        found = {(str((r.get("http_request") or {}).get("http_method")).upper(), str(((r.get("http_request") or {}).get("url") or {}).get("path"))) for r in rows}
        if all(e in found for e in expected) or time.time() > deadline:
            break
        say(f"  waiting for ingestion... ({len(found & set(expected))} of {len(expected)} calls seen)", DIM)
        time.sleep(15)
    for r in rows:
        req = r.get("http_request") or {}
        say(f"  {str(req.get('http_method')):6} {str((req.get('url') or {}).get('path')):32} {str(r.get('action')):8} {str(r.get('message'))[:110]}" + (f"  [{r['status_detail']}]" if r.get("status_detail") else ""), DIM)
    missing = [e for e in expected if e not in found]
    if missing:
        say(f"  not yet in the SIEM after {wait} s: {', '.join(m + ' ' + p for m, p in missing)}", AMBER)
    else:
        say(f"  all {len(expected)} calls are in the SIEM", GREEN)


def agreement_numbers(hours):
    import agreement
    audit, refusals, failures = agreement.fetch(hours, set())
    r = agreement.compare(audit, refusals, failures=failures)
    say(f"  the fleet's last {hours} h in audit mode: OpenShell would have refused {len(audit)} calls", DIM)
    say(f"    both layers refused:                     {len(r['both'])}", GREEN)
    say(f"    OpenShell only (enforcing would add):    {len(r['openshell_only'])}", GREEN if not r["openshell_only"] else RED)
    say(f"    OpenShell only, Risk Guard errored:      {len(r['errored_closed'])}", AMBER if r["errored_closed"] else GREEN)
    say(f"    Risk Guard only (rate, resource, rules): {len(r['risk_guard_only'])}", DIM)
    say("  The gate for enforcing the fleet is 'OpenShell only' = 0 (docs/fleet-policy-modes.md). Probe sandboxes are excluded.", DIM)


def act_f(sid, calls, score_a, carried, wait):
    """Send the same routine call as act A until Risk Guard's decision carries the `siem_context` signal. The path is: OpenShell denies (act B) -> the supervisor's OCSF
    event -> the collector -> OpenSearch (5 to 8 s measured) -> the feature publisher (every 30 s) -> Risk Guard's /features -> the next score. Nothing is injected."""
    say("  Three calls were denied by OpenShell in act B. OpenSearch counts them (openshell_denials_5m); the feature publisher hands the count to Risk Guard.", DIM)
    deadline = time.time() + wait
    last = None
    while True:
        r = call(*ACT_FOLLOWUP)
        calls.append(ACT_FOLLOWUP)
        last = (decisions(sid) or [None])[-1]
        signal = siem_signal(last)
        if signal or time.time() > deadline:
            break
        say(f"  {ACT_FOLLOWUP[0]} {ACT_FOLLOWUP[1]} -> {r['status']}, score {last.get('risk_score') if last else '?'}: the count has not reached Risk Guard yet, trying again in 20 s", DIM)
        time.sleep(20)
    if not signal:
        say(f"  The features had not arrived after {wait} s. Nothing was changed by the SIEM; this is the pipeline's delay, not a decision. Run the act again in a minute.", AMBER)
        return False
    score = last.get("risk_score")
    say(f"  {ACT_FOLLOWUP[0]} {ACT_FOLLOWUP[1]}  ->  {r['status']}   score {score_a} in act A  ->  {score} now", GREEN)
    if carried:
        say("  (act A already carried features from an earlier run, so the before/after is not clean: wait 10 minutes between runs for a clean comparison)", AMBER)
    say(f"    what OpenSearch told Risk Guard: {signal.get('observed_summary')}", DIM)
    say(f"    the rule: {signal.get('baseline_summary')}", DIM)
    say("  Risk Guard added the points because this profile enforces the siem_context rule. It only ever adds, it is capped, and it did not change the outcome here "
        "(see changes_outcome); in the fleet the rule is only watching.", DIM)
    return True


def run(cfg, pause, siem_wait, no_siem, feature_wait=300):
    started = time.time()
    sandbox = sandbox_json()
    if not sandbox:
        sys.exit(f"no sandbox {SANDBOX}: run --prepare first (it is not faked)")
    sid = sandbox["id"]
    workload = cfg["workload"]
    say("OpenShell enforces the approved routes; Risk Guard decides what a path rule cannot", BOLD)
    say(f"profile {cfg['task_profile']}, live cluster, sandbox {SANDBOX}", DIM)
    disclosure(cfg, effective_rule_name())
    clear_restrictions(workload, "end-state demo start: judge each act on its own")
    calls = []

    act("A", "A routine call passes both layers", pause)
    t = time.time()
    r = call(*ACT_A)
    calls.append(ACT_A)
    say(f"  {ACT_A[0]} {ACT_A[1]}  ->  {r['status']}", GREEN if r["status"] == 200 else RED)
    show_events(sid, t)
    say("  OpenShell's rule allowed it, then Risk Guard allowed it; the service answered.", DIM)
    first = (decisions(sid) or [None])[-1]
    score_a = first.get("risk_score") if first else None
    carried = siem_signal(first) is not None
    say(f"  Risk Guard scored it {score_a} of {first.get('threshold') if first else '?'}" + ("  (OpenSearch features from a run in the last 10 minutes are still in force)" if carried else "  (no OpenSearch features yet)"), DIM)

    act("B", "A destructive call that is not an exception is refused by OpenShell; Risk Guard never sees it", pause)
    t = time.time()
    r = call(*ACT_B)
    calls.append(ACT_B)
    b = body_json(r)
    say(f"  {ACT_B[0]} {ACT_B[1]}  ->  {r['status']} {b.get('error')} (rule: {b.get('rule')})", RED if b.get("error") == "policy_denied" else AMBER)
    shown = show_events(sid, t)
    for _ in range(2):  # three denials in all: the SIEM counts them, and act F shows what that count does to a score
        again_b = call(*ACT_B)
        calls.append(ACT_B)
        say(f"  {ACT_B[0]} {ACT_B[1]}  ->  {again_b['status']} {body_json(again_b).get('error')}   (denial {len(calls) - 1} of 3, for act F)", DIM)
    saw_middleware = any("MIDDLEWARE" in s for s in shown)
    say("  Risk Guard was not consulted: no MIDDLEWARE record for this call." if not saw_middleware else "  UNEXPECTED: Risk Guard was consulted for this call.", GREEN if not saw_middleware else RED)

    act("C", "An exception passes OpenShell; Risk Guard refuses it (naming the rule) and locks that route for the workload", pause)
    disclosure(cfg)
    before = rd.destination_deletes()
    t = time.time()
    r = call(*ACT_C)
    calls.append(ACT_C)
    c = body_json(r)
    say(f"  {ACT_C[0]} {ACT_C[1]}  ->  {r['status']} {c.get('error')} (middleware {c.get('middleware')}, reason_code {c.get('reason_code')})", RED if c.get("error") == "middleware_denied" else AMBER)
    show_events(sid, t)
    say_decision(decisions(sid), "Risk Guard's own record of this call")
    after = rd.destination_deletes()
    say(f"  destination's own DELETE /services/worker counter: {before} before, {after} after  ->  {'no effect at the destination' if after == before else 'EFFECT AT DESTINATION'}", GREEN if after == before else RED)
    held = restrictions(workload)
    say(f"  restrictions now held on workload {workload}: {len(held)}" + ("  (locked)" if held else "  (none: this refusal did not latch)"), RED if held else AMBER)
    for h in held[:3]:
        say(f"    scope: {h.get('scope')}", DIM)
    again = call(*ACT_C)
    calls.append(ACT_C)
    ab = body_json(again)
    say(f"  the same call again  ->  {again['status']} {ab.get('reason_code') or ab.get('error')}   (the lock: that route on that resource stays refused for this workload)", RED if again["status"] == 403 else AMBER)
    r2 = call(*ACT_FOLLOWUP)
    calls.append(ACT_FOLLOWUP)
    say(f"  a routine {ACT_FOLLOWUP[0]} {ACT_FOLLOWUP[1]} straight afterwards  ->  {r2['status']}   (the lock is narrow: approved work continues)", GREEN if r2["status"] == 200 else AMBER)
    cleared = clear_restrictions(workload, "end-state demo: act D must be judged on its own")
    if cleared:
        say(f"  operator step: {len(cleared)} restriction(s) cleared with break-glass so that act D shows the resource rule alone (recorded in the audit trail).", AMBER)

    act("D", "The same approved route on an unapproved resource is refused by Risk Guard's resource rule", pause)
    t = time.time()
    r = call(*ACT_D)
    calls.append(ACT_D)
    d = body_json(r)
    refused = r["status"] == 403 and d.get("middleware") == "risk-guard"
    say(f"  {ACT_D[0]} {ACT_D[1]}  ->  {r['status']} {d.get('error') or ''} {d.get('reason_code') or ''}".rstrip(), RED if refused else AMBER)
    show_events(sid, t)
    say_decision(decisions(sid), "Risk Guard's own record of this call")
    if refused:
        say("  The route is approved and OpenShell allowed it: only a rule that knows the resource can refuse this one. That is the unapproved_resource rule, enforcing for this profile.", GREEN)
    elif not cfg["resource_rule_enforcing"]:
        say(f"  The resource rule is only watching (shadow) in the {cfg['task_profile']} profile, so Risk Guard allowed this and logged it. It refuses only in demo-end-state.", AMBER)
    else:
        say("  EXPECTED a refusal by the resource rule. Check that the demo-end-state baseline with unapproved_resource=enforce is the one imported.", RED)
    clear_restrictions(workload, "end-state demo: leave the workload clean")

    act("E", "The agreement tool: what enforcing the fleet would change", pause)
    try:
        agreement_numbers(24)
    except Exception as error:  # noqa: BLE001
        say(f"  could not read the SIEM: {type(error).__name__}: {error}", AMBER)

    act("F", "OpenSearch remembers: the denials from act B raise the score of the next routine call", pause)
    act_f(sid, calls, score_a, carried, feature_wait)

    if not no_siem:
        siem_check(sid, started, [c for c in calls], siem_wait)
    say(f"\nTotal: {round(time.time() - started)} s", DIM)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--pause", action="store_true")
    parser.add_argument("--profile", choices=sorted(PROFILES), default="demo-end-state")
    parser.add_argument("--siem-wait", type=int, default=150, help="seconds to wait for the events to reach OpenSearch")
    parser.add_argument("--no-siem", action="store_true")
    parser.add_argument("--feature-wait", type=int, default=300, help="seconds act F waits for the OpenSearch features to reach Risk Guard")
    args = parser.parse_args()
    cfg = PROFILES[args.profile]
    if args.prepare:
        prepare(cfg)
    elif args.cleanup:
        cleanup(cfg)
    else:
        run(cfg, args.pause, args.siem_wait, args.no_siem, args.feature_wait)


if __name__ == "__main__":
    main()
