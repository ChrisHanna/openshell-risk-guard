#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Path edge cases on the real OpenShell: what does the policy engine do with evasive spellings of a refused call, in audit and in enforce mode?

    python scripts/policy/path_probe.py [--smoke] [--out conformance/policy-export/path-edge-cases.json]

For the release and cloud profiles it takes the generated OpenShell policy (policy.audit.yaml, and the same file in enforce mode), registers one throwaway workload per run, creates one
throwaway sandbox per profile and mode (names start `epprobe-`; always deleted), and sends raw HTTP requests from inside each sandbox so that nothing normalizes the path
on the way: the catalog's evasion attacks (RT-007, RT-008, RT-010, RT-011, RT-012), the mutation kinds of tests/red_team_fuzz.rs applied to a destructive release call (RT-001)
and a secrets read (RT-003), and a few traversals through an approved route. For each request it records what OpenShell did (allowed by rule, would block in audit, denied in enforce,
dropped, malformed), the path OpenShell logged, what Risk Guard then did, and what the service received. Needs kubectl access and the cluster's agent-fleet pod. It changes no running sandbox, policy or repository file other than --out.
It does register throwaway workloads (epprobe-*) in Risk Guard, which has no delete command; they are inert once their sandboxes are gone.
"""
import argparse
import base64
import concurrent.futures
import json
import os
import subprocess
import sys
import time

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import audit_probe as ap  # noqa: E402  (shared cluster helpers)

DB = "/var/lib/openshell-risk-guard/risk-guard.db"
HOSTS = {"release": "deploy-api.openshell.svc.cluster.local", "cloud": "cloud-api.openshell.svc.cluster.local"}
# profile -> (catalog seed id for the fuzzing, a route its policy allows (control), traversals through an approved route)
SEEDS = {"release": "RT-001", "cloud": "RT-003"}
CONTROL_ALLOWED = {"release": "/services", "cloud": "/buckets"}
TRAVERSALS = {
    "release": ["/services/..%2fcustomers%2fc-1", "/services/%2e%2e%2fcustomers%2fc-1", "/services/..%5ccustomers", "/services/..;/customers", "/services/%2e%2e", "/services/./", "/services/.."],
    "cloud": ["/buckets/..%2fsecrets%2fbackup-encryption-key", "/buckets/%2e%2e%2fsecrets", "/buckets/..%5csecrets", "/buckets/..;/secrets", "/buckets/%2e%2e", "/buckets/./", "/buckets/.."],
}
CATALOG_IDS = ["RT-007", "RT-008", "RT-010", "RT-011", "RT-012"]

RUNNER = r'''
import base64, json, socket, sys
spec = json.loads(base64.b64decode(sys.argv[1]))
raw_target = base64.b64decode(spec["target"])
head = spec["method"].encode() + b" " + raw_target + b" HTTP/1.1\r\nHost: " + spec["host_header"].encode() + b"\r\nConnection: close\r\n\r\n"
out = {"status_line": None, "headers": [], "body": "", "error": None}
try:
    s = socket.create_connection((spec["connect_host"], 18081), timeout=10)
    s.settimeout(15)
    s.sendall(head)
    data = b""
    while True:
        try:
            chunk = s.recv(65536)
        except Exception as e:
            out["error"] = type(e).__name__
            break
        if not chunk:
            break
        data += chunk
    text = data.decode("latin-1")
    if text:
        h, _, b = text.partition("\r\n\r\n")
        lines = h.split("\r\n")
        out["status_line"], out["headers"], out["body"] = lines[0], lines[1:], b[:400]
    elif not out["error"]:
        out["error"] = "closed_without_response"
except Exception as e:
    out["error"] = type(e).__name__ + ": " + str(e)[:100]
print("RESULT " + json.dumps(out))
'''
RUNNER_B64 = base64.b64encode(RUNNER.encode()).decode()


def path_variants(path):
    """The mutations of tests/red_team_fuzz.rs::path_variants, in the same order and with the same names."""
    out = []

    def add(kind, value):
        if value != path:
            out.append((kind, value))

    add("trailing slash", path + "/")
    add("double trailing slash", path + "//")
    add("leading double slash", "/" + path)
    add("doubled separators", path.replace("/", "//"))
    add("dot segment", path.replace("/", "/./", 1))
    add("parent segment", "/x/.." + path)
    add("upper case", path.upper())
    add("lower case", path.lower())
    add("title case", "/".join(s[:1].upper() + s[1:] for s in path.split("/")))
    add("query string", path + "?force=true")
    add("query with encoded question", path + "%3fforce=true")
    add("fragment", path + "#x")
    add("matrix parameter", path + ";x=1")
    add("encoded slash at the end", path + "%2f")
    add("null byte", path + "%00")
    add("null byte then more", path + "%00/ok")
    add("tab", path + "%09")
    add("newline", path + "%0a")
    add("space", path + "%20")
    add("backslash separators", path.replace("/", "\\"))
    add("encoded backslash", path.replace("/", "%5c"))
    add("overlong slash", path.replace("/", "%c0%af", 1))
    add("double encoding", path.replace("/", "%252f"))
    add("encoded slash separators", path.replace("/", "%2f"))
    head, _, last = path.rpartition("/")
    for index, ch in enumerate(last):
        if ch.isascii() and ch.isalpha():
            add(f"encoded letter {index}", f"{head}/{last[:index]}%{ord(ch):02x}{last[index + 1:]}")
            break
    look = last.replace("a", "а", 1).replace("e", "е", 1).replace("o", "о", 1)
    add("unicode look-alike", f"{head}/{look}")
    add("trailing dot in last segment", path + ".")
    add("trailing space segment", f"{head}/{last} ")
    return out


def build_cases(profile, smoke):
    catalog = json.load(open(os.path.join(ROOT, "conformance", "red-team", "catalog.json"), encoding="utf-8"))
    by_id = {a["id"]: a for a in catalog["attacks"]}
    host = HOSTS[profile]
    cases = []

    def case(cid, kind, method, path, expect, source, connect_host=None, note=""):
        cases.append({"id": cid, "kind": kind, "profile": profile, "method": method, "path": path, "connect_host": connect_host or host, "expect": expect, "source": source, "note": note})

    seed = by_id[SEEDS[profile]]["steps"][0]
    case("control-allowed", "control: a route the profile approves", "GET", CONTROL_ALLOWED[profile], "allowed", "control")
    case(SEEDS[profile], "seed: the plain refused call", seed["method"], seed["path"], "refused", "catalog")
    for cid in CATALOG_IDS:
        a = by_id[cid]
        if a["profile"] == profile:
            case(cid, a["title"], a["steps"][0]["method"], a["steps"][0]["path"], a["expect"], "catalog")
    for n, path in enumerate(TRAVERSALS[profile]):
        case(f"traverse-{n + 1}", "traversal through an approved route", "GET", path, "refused" if "secrets" in path or "customers" in path else "n/a", "traversal",
             note="the service would see a path outside the approved routes if anything decodes or resolves it")
    if smoke:
        return cases
    for kind, p in path_variants(seed["path"]):
        case(f"{SEEDS[profile]}~{kind}", kind, seed["method"], p, "refused", "fuzz")
    case(f"{SEEDS[profile]}~host upper case", "host upper case", seed["method"], seed["path"], "refused", "fuzz", connect_host=host.upper())
    case(f"{SEEDS[profile]}~host trailing dot", "host trailing dot", seed["method"], seed["path"], "refused", "fuzz", connect_host=host + ".")
    case(f"{SEEDS[profile]}~method lower case", "method lower case", seed["method"].lower(), seed["path"], "refused", "fuzz")
    return cases


def generate(profile, enforcement, out):
    """The policy the fleet runs for the profile (deploy/aks/agents/<profile>/policy.audit.yaml, which tests/policy_export.rs keeps equal to `policy-export --enforcement audit`), and for
    enforce the same file with the endpoint's mode switched: that is all `policy-export --enforcement enforce` changes. No build is needed."""
    text = open(os.path.join(ROOT, "deploy", "aks", "agents", profile, "policy.audit.yaml"), encoding="utf-8").read().replace(chr(13) + chr(10), chr(10))
    assert text.count("enforcement: audit") == 1, "expected exactly one audited endpoint"
    if enforcement == "enforce":
        text = text.replace("enforcement: audit", "enforcement: enforce")
    with open(out, "w", encoding="utf-8", newline=chr(10)) as f:
        f.write(text)
    return {"allow_rules": text.count("allow:")}


def risk_guard(*args):
    return ap.kubectl("exec", "deploy/risk-guard", "-c", "risk-guard", "--", "/usr/local/bin/openshell-risk-guard", *args, timeout=60)


def clear_restrictions(agent):
    """A refusal latches a restriction on the workload; clear it so the next case is judged on its own. Only this probe's throwaway workload."""
    try:
        listed = json.loads(risk_guard("restriction-list", "--db", DB, "--agent-id", agent))
    except ValueError:
        return 0
    cleared = 0
    for r in listed.get("restrictions", []):
        scope = r.get("scope")
        if scope and r.get("blocking", r.get("blocks", True)):
            risk_guard("restriction-clear", "--db", DB, "--agent-id", agent, "--scope", scope, "--operator", "epprobe", "--reason", "throwaway path probe, next case judged alone", "--break-glass")
            cleared += 1
    return cleared


def parse_events(sandbox_id):
    """OpenShell's own OCSF records of the sandbox: HTTP activity (policy decisions, middleware) and findings, with timestamps."""
    events = []
    for line in ap.kubectl("logs", f"pod/os-supervisor-{sandbox_id}", timeout=120).splitlines():
        if "OCSF-JSON " not in line:
            continue
        try:
            r = json.loads(line.split("OCSF-JSON ", 1)[1])
        except ValueError:
            continue
        if r.get("class_uid") not in (4001, 4002, 2004):
            continue
        req = r.get("http_request") or {}
        events.append({"t": r.get("time", 0) / 1000.0, "class": r.get("class_name"), "message": r.get("message"), "status_detail": r.get("status_detail"), "action": r.get("action"),
                       "path": (req.get("url") or {}).get("path"), "method": req.get("http_method"), "finding": (r.get("finding_info") or {}).get("title")})
    return events


def classify(resp, events):
    """What OpenShell did, what Risk Guard did, and where the request ended up. `events` are the OCSF records of this one request's connection."""
    messages = [e["message"] or "" for e in events]
    l7 = [m for m in messages if m.startswith("L7_REQUEST")]
    middleware = [e for e in events if (e["message"] or "").startswith("MIDDLEWARE")]
    status = resp.get("status_line") or ""
    code = status.split(" ")[1] if len(status.split(" ")) > 1 else ""
    body = resp.get("body") or ""
    if any(m.startswith("L7_REQUEST deny") for m in l7):
        openshell = "denied"
    elif any(m.startswith("L7_REQUEST audit") and "not permitted by policy" in m for m in l7):
        openshell = "would block (audit)"
    elif any(m.startswith("L7_REQUEST allow") for m in l7):
        openshell = "allowed by rule"
    elif any("blocked unsupported tunnel protocol" in m for m in messages):
        openshell = "blocked (not recognised as HTTP)"
    elif any("rejected before policy evaluation" in m for m in messages):
        openshell = "malformed (rejected before any rule)"
    elif not messages:
        openshell = "dropped (no decision logged)"
    else:
        openshell = "other: " + messages[-1][:60]
    verdicts = sorted({(e["message"] or "").split("decision=")[-1] + (f" ({e['status_detail']})" if e.get("status_detail") else "") for e in middleware})
    risk_guard = "; ".join(verdicts) if verdicts else "not consulted"
    if resp.get("error") and not status:
        final = "dropped"
    elif code == "400":
        final = "malformed"
    elif any("blocked unsupported tunnel protocol" in m for m in messages):
        final = "refused by OpenShell (not recognised as HTTP)"
    elif "policy_denied" in body:
        final = "refused by OpenShell policy"
    elif code == "403":
        final = "refused by Risk Guard" if middleware else "refused (403, source unclear)"
    elif "decision=Allow" in " ".join(messages) and code[:1] in ("2", "3", "4", "5") or "local_fixture" in body or "unknown fixture route" in body or "no such" in body:
        final = "reached the service"
    else:
        final = "other: " + status
    return {"openshell": openshell, "risk_guard": risk_guard, "final": final, "http_status": code or None,
            "openshell_saw_path": sorted({e["path"] for e in events if e.get("path")})}


def policy_file(profile, mode):
    return os.path.join(ROOT, ".aks", "policy-probe", f"{profile}.{mode}.yaml")


def run_sandbox(profile, mode, cases, skew, log, summary):
    tag = time.strftime("%H%M%S")
    name = f"epprobe-{mode[0]}{profile[0]}{tag}"  # OpenShell limits names to 19 characters
    agent = name
    data = open(policy_file(profile, mode), "rb").read()
    ap.fleet("sh", "-c", f"echo {base64.b64encode(data).decode()} | base64 -d > /tmp/{name}.yaml")
    acr = ap.kubectl("get", "deploy/agent-fleet", "-o", "jsonpath={.spec.template.spec.containers[0].env[?(@.name==\"ACR_SERVER\")].value}").strip()
    risk_guard("agent-register", "--db", DB, "--agent-id", agent, "--display-name", "epprobe throwaway path probe")
    log(f"[{name}] creating sandbox (policy: {profile} {mode}, {summary['allow_rules']} allow rules)")
    created = ""
    for attempt in range(3):
        created = ap.fleet("openshell", "sandbox", "create", "--name", name, "--from", f"{acr}/openshell-demo/nat-agent:{ap.IMAGE_TAG}", "--policy", f"/tmp/{name}.yaml", "--provider", "nvidia-nat",
                           "--annotation", f"openshell.nvidia.com/agent-id={agent}", "--annotation", "openshell.nvidia.com/agent-name=epprobe", "--no-tty", "--detach", "--", "/usr/bin/sleep", "infinity", timeout=300)
        if "sandbox not found" not in ap.fleet("openshell", "sandbox", "get", name, "--output", "json"):
            break
        log(f"[{name}] create attempt {attempt + 1} failed: {created.strip()[-200:]}")
        time.sleep(10)
    results = []
    try:
        last = ""
        for _ in range(60):
            last = ap.fleet("openshell", "sandbox", "get", name, "--output", "json")
            if '"Ready"' in last.replace('": "', '":"'):
                break
            time.sleep(6)
        else:
            raise RuntimeError("the sandbox did not become ready; last answer: " + last.strip()[:300])
        sandbox_id = json.loads(ap.fleet("openshell", "sandbox", "get", name, "--output", "json"))["id"]
        ap.fleet("openshell", "sandbox", "exec", "--name", name, "--no-tty", "--no-login-shell", "--", "/bin/sh", "-c", f"echo {RUNNER_B64} | base64 -d > /tmp/rawreq.py")
        for i, c in enumerate(cases):
            spec = {"method": c["method"], "target": base64.b64encode(c["path"].encode("utf-8")).decode(), "connect_host": c["connect_host"], "host_header": c["connect_host"] + ":18081"}
            t0 = time.time()
            text = ap.fleet("openshell", "sandbox", "exec", "--name", name, "--no-tty", "--no-login-shell", "--", "/opt/agent/bin/python3.12", "/tmp/rawreq.py",
                            base64.b64encode(json.dumps(spec).encode()).decode(), timeout=120)
            t1 = time.time()
            resp = {"status_line": None, "headers": [], "body": "", "error": "no result from the sandbox exec: " + text.strip()[:120]}
            for line in text.splitlines():
                if line.startswith("RESULT "):
                    resp = json.loads(line[7:])
            results.append({**c, "mode": mode, "sandbox": name, "response": resp, "_t0": t0 + skew, "_t1": t1 + skew})
            denied = resp.get("body") and ("risk" in resp["body"].lower() or "middleware" in resp["body"].lower() or resp.get("status_line", "") and " 403" in resp["status_line"])
            if denied:
                clear_restrictions(agent)
            if (i + 1) % 10 == 0:
                log(f"[{name}] {i + 1}/{len(cases)}")
        time.sleep(5)
        events = parse_events(sandbox_id)
        if os.environ.get("PATH_PROBE_DEBUG"):
            json.dump({"events": events, "windows": [(r["id"], r["_t0"], r["_t1"]) for r in results]}, open(os.path.join(ROOT, ".aks", "policy-probe", f"debug-{name}.json"), "w"), indent=1)
        # One request is one connection, and OpenShell logs a `CONNECT_L7 allowed` record as each connection starts, so the records between two of them belong to one request.
        # The clock is only a cross-check: if the counts differ the groups are not trusted.
        owned, current = [], None
        for e in events:
            if (e["message"] or "").startswith("CONNECT_L7 allowed"):
                current = []
                owned.append(current)
            if current is not None:
                current.append(e)
        if len(owned) != len(results):
            log(f"[{name}] WARNING: {len(owned)} connections logged for {len(results)} requests; falling back to the clock")
            starts = [r["_t0"] - 0.05 for r in results]
            owned = [[] for _ in results]
            for e in events:
                index = max((i for i, t in enumerate(starts) if t <= e["t"]), default=None)
                if index is not None:
                    owned[index].append(e)
        for r, window in zip(results, owned):
            r["events"] = [{k: v for k, v in e.items() if k not in ("t", "class") and v} for e in window if not (e["message"] or "").startswith("CONNECT_L7 allowed")]
            r.update(classify(r["response"], window))
            r["openshell_allowed_by_rule"] = r["openshell"] == "allowed by rule"
            reached = r["final"] == "reached the service"
            r["verdict"] = ("UNSAFE: reached the service although the catalog says it must be refused" if r["expect"] == "refused" and reached
                            else "OpenShell's rule allowed it, Risk Guard refused it" if r["expect"] == "refused" and r["openshell_allowed_by_rule"]
                            else "as expected" if r["expect"] in ("refused", "allowed") else "no catalog expectation")
            del r["_t0"], r["_t1"]
    finally:
        ap.fleet("openshell", "sandbox", "delete", name, timeout=120)
        log(f"[{name}] sandbox deleted")
        clear_restrictions(agent)
    return results, summary


def fixture_hits():
    out = ap.kubectl("exec", "deploy/risk-guard-fixture", "--", "python3", "-c",
                     "import json,urllib.request;print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:18081/_actions'))))")
    return {(a["method"], a["path"]): a["hits"] for a in json.loads(out)}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--smoke", action="store_true", help="only the controls, the catalog attacks and the traversals")
    parser.add_argument("--profiles", default="release,cloud")
    parser.add_argument("--out", default=os.path.join(ROOT, "conformance", "policy-export", "path-edge-cases.json"))
    args = parser.parse_args()
    profiles = args.profiles.split(",")
    remote = float(ap.fleet("date", "+%s.%N").strip())
    skew = remote - time.time()
    print(f"clock difference to the cluster node: {skew:+.2f} s")
    os.makedirs(os.path.join(ROOT, ".aks", "policy-probe"), exist_ok=True)
    generated = {}
    for p in profiles:
        for m in ("audit", "enforce"):
            for attempt in range(3):  # kept from an earlier version that built the policies with WSL
                try:
                    generated[(p, m)] = generate(p, m, policy_file(p, m))
                    break
                except SystemExit:
                    if attempt == 2:
                        raise
                    time.sleep(5)
    before = fixture_hits()
    jobs = [(p, m) for p in profiles for m in ("audit", "enforce")]
    lock = __import__("threading").Lock()

    def log(msg):
        with lock:
            print(msg, flush=True)

    all_results, summaries = [], {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {pool.submit(run_sandbox, p, m, build_cases(p, args.smoke), skew, log, generated[(p, m)]): (p, m) for p, m in jobs}
        for f in concurrent.futures.as_completed(futures):
            p, m = futures[f]
            try:
                results, summary = f.result()
            except Exception as e:  # noqa: BLE001
                log(f"{p} {m}: FAILED {type(e).__name__}: {e}")
                continue
            all_results.extend(results)
            summaries[f"{p}/{m}"] = {"policy_file": f"deploy/aks/agents/{p}/policy.audit.yaml" + (" with enforcement: enforce" if m == "enforce" else ""), "allow_rules": summary["allow_rules"]}
    after = fixture_hits()
    served = {f"{m} {p}": after[(m, p)] - before.get((m, p), 0) for (m, p) in after if after[(m, p)] != before.get((m, p), 0)}
    order = {"control": 0, "catalog": 1, "traversal": 2, "fuzz": 3}
    all_results.sort(key=lambda r: (r["profile"], order[r["source"]], r["id"], r["mode"]))
    summary = {}
    for r in all_results:
        key = f"{r['profile']}/{r['mode']}"
        summary.setdefault(key, {}).setdefault(r["final"], 0)
        summary[key][r["final"]] += 1
    report = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "what": "Raw requests sent from inside throwaway OpenShell sandboxes against the generated release and cloud policies, in audit and in enforce mode. See docs/policy-path-edge-cases.md.",
        "policies": summaries,
        "outcomes": summary,
        "unsafe": [f"{r['profile']} {r['mode']} {r['id']} {r['method']} {r['path']}" for r in all_results if r["verdict"].startswith("UNSAFE")],
        "openshell_allowed_what_the_catalog_refuses": [f"{r['profile']} {r['mode']} {r['id']} {r['method']} {r['path']} -> {r['risk_guard']}; {r['final']}" for r in all_results if r["expect"] == "refused" and r["openshell_allowed_by_rule"]],
        "service_hits_during_run": served,
        "cases": [{k: v for k, v in r.items() if k not in ("headers",)} for r in all_results],
    }
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {args.out}: {len(all_results)} results")
    for r in all_results:
        print(f"{r['profile']:7} {r['mode']:7} {r['id'][:34]:34} {r['method']:6} {ascii(r['path'])[:44]:44} openshell={r['openshell'][:28]:28} rg={r['risk_guard'][:24]:24} -> {r['final']}")


if __name__ == "__main__":
    main()
