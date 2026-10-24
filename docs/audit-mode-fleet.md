# The fleet on the generated OpenShell policy (audit mode)

The agent fleet's sandboxes (support, release, cloud) run `deploy/aks/agents/<profile>/policy.audit.yaml`: the profile's approved routes and deny list written as OpenShell rules by `policy-export --enforcement audit`, in **audit** mode. OpenShell logs `L7_REQUEST audit ... not permitted by policy` for what it would block and blocks nothing; Risk Guard still decides. `python scripts/policy/agreement.py --hours 1` compares the two.

- Regenerate: `RG_BIN=<built openshell-risk-guard> python3 scripts/policy/generate_audit_policies.py` (add `--check` to only verify). `tests/policy_export.rs` and CI fail when a committed file is stale.
- Switch: `AGENT_POLICY_MODE=audit` in `scripts/aks/run-agent.sh` selects the generated file; unset keeps `policy.yaml`. `deploy/aks/fleet.yaml` sets it for the fleet. Only sandboxes created afterwards are affected.
- Not touched: the inference endpoint stays `enforce` as in `policy.yaml`; nothing is switched to enforce.

## Roll back

Either of these, then wait one run per agent (about ten minutes) for new sandboxes:

1. One setting: `kubectl -n openshell set env deploy/agent-fleet AGENT_POLICY_MODE-` (removes it; the pod restarts). Re-running `16-deploy-fleet.ps1` re-applies `fleet.yaml`, so also change the value there to `""` if the redeploy is to keep it off.
2. Redeploy the previous image: `kubectl -n openshell set image deploy/agent-fleet fleet=<previous image>`. The image before the audit change was `fleet:a7ce1a1-20261022-160926` in the cluster's registry.
