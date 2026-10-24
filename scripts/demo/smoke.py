#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Is the deployment working? Judged by running the demo, not by reading an API.

    python scripts/demo/smoke.py                 # pre-flight, then the four acts of the partner demo
    python scripts/demo/smoke.py --end-state     # also the five acts of the end-state demo (needs its sandbox: end_state.py --prepare)

Run it after every deploy and before saying anything works. It does what a person presenting would do and checks what they would look for in each act: routine calls return 200,
a destructive call is refused and the destination's counter does not move, a quarantined workload times out, the recorded decisions replay, and (end state) OpenShell refuses what
a path rule can, Risk Guard refuses what it cannot, and the SIEM has every call. It exits 1 and says exactly which expectation failed. It changes nothing that the demo itself does not.
"""
import argparse
import os
import re
import subprocess
import sys

os.environ.setdefault("MSYS_NO_PATHCONV", "1")
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HERE = os.path.dirname(os.path.abspath(__file__))
ANSI = re.compile(r"\x1b\[[0-9;]*m")
failures = []


def run(script, *args, timeout=900):
    result = subprocess.run([sys.executable, os.path.join(HERE, script), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout,
                            env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    return result.returncode, ANSI.sub("", result.stdout + result.stderr)


def section(text, start, end=None):
    """The part of the output from the line starting `start` to the next line starting `end` (or the end)."""
    i = text.find(start)
    if i < 0:
        return ""
    j = text.find(end, i + len(start)) if end else -1
    return text[i: j if j > 0 else len(text)]


def expect(ok, what, detail=""):
    print(("  ok    " if ok else "  FAIL  ") + what + (f"\n          {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(what)


def partner_demo():
    print("\nPartner demo (run_demo.py)")
    code, out = run("run_demo.py")
    expect(code == 0, "the demo ran to the end", out[-400:])
    a1 = section(out, "Act 1", "Act 2")
    expect(len(re.findall(r"-> 200\b", a1)) >= 2, "act 1: both routine reads return 200", a1.strip()[-300:])
    a2 = section(out, "Act 2", "Act 3")
    expect("DELETE /services/worker -> 403" in a2, "act 2: the destructive call is refused (403)", a2.strip()[-300:])
    expect("no effect at the destination" in a2, "act 2: the destination's own counter did not move", a2.strip()[-300:])
    expect("middleware_failed" not in a2, "act 2: Risk Guard decided (it did not error)", a2.strip()[-300:])
    a3 = section(out, "Act 3", "Act 4")
    expect("before: connected 200" in a3 and "after:  refused" in a3, "act 3: connected before the quarantine, refused after", a3.strip()[-300:])
    a4 = section(out, "Act 4")
    expect("no differences" in a4 and "replayed in a fresh store" in a4, "act 4: the recorded decisions replay with no differences", a4.strip()[-300:])


def end_state():
    print("\nEnd-state demo (end_state.py)")
    code, out = run("end_state.py")
    expect(code == 0, "the end-state demo ran to the end (if it says the sandbox is missing, run end_state.py --prepare)", out[-400:])
    a = section(out, "Act A", "Act B")
    expect("GET /services  ->  200" in a, "act A: a routine call passes both layers", a.strip()[-300:])
    b = section(out, "Act B", "Act C")
    expect("403 policy_denied" in b and "Risk Guard was not consulted" in b, "act B: OpenShell refuses and Risk Guard never sees it", b.strip()[-300:])
    c = section(out, "Act C", "Act D")
    expect("403 middleware_denied" in c and "no effect at the destination" in c, "act C: an exception passes OpenShell and Risk Guard refuses it", c.strip()[-300:])
    d = section(out, "Act D", "Act E")
    expect("unapproved_resource" in d and "403" in d, "act D: Risk Guard's resource rule refuses an approved route on an unapproved resource", d.strip()[-300:])
    e = section(out, "Act E")
    m = re.search(r"OpenShell only \(enforcing would add\):\s+(\d+)", e)
    expect(bool(m) and int(m.group(1)) == 0, "act E: enforcing the fleet would add no new blocks", e.strip()[-300:])
    expect(re.search(r"all \d+ calls are in the SIEM", out) is not None, "every call of the demo is in the SIEM", out[-300:])


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--end-state", action="store_true")
    args = parser.parse_args()
    print("Pre-flight (preflight.py)")
    code, out = run("preflight.py", "--quick")
    print("\n".join("  " + line for line in out.strip().splitlines()[-4:]))
    expect(code == 0 and "0 FAIL" in out, "pre-flight has no failures", out[-300:])
    partner_demo()
    if args.end_state:
        end_state()
    print(f"\n{'SMOKE FAILED: ' + str(len(failures)) + ' expectation(s) not met' if failures else 'SMOKE PASSED'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
