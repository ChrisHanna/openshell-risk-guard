# A beginner's guide to the demo SIEM

This explains what the starter content in the demo SIEM is, how to look at it, and what to expect. Setup is in [siem-integration.md](siem-integration.md). The starter content is installed by:

```
python scripts/siem/install_content.py
```

It is safe to run again; it updates what it made and skips what exists. It runs `kubectl exec` into the Dashboards pod, so nothing new is exposed.

## The ideas, in plain words

- **Event.** One record: "this sandbox asked for `/records/7` and Risk Guard said allow". Every event lands in the index `ocsf-openshell`.
- **Search.** Ask the index a question: "show me every refusal". Open **Discover**, pick the `ocsf-openshell` index pattern, set the time range (top right).
- **Visualization.** A saved search drawn as a number, chart or table.
- **Dashboard.** A page of visualizations. Ours: **Risk Guard and OpenShell: overview**.
- **Anomaly detection.** You do not say what is bad. The detector learns what a normal count per minute looks like and flags minutes that look unlike it (the method is called Random Cut Forest).
- **Alert (monitor).** You do say what is bad: "three or more failures in five minutes". It checks on a schedule and fires a trigger.
- **Report.** A scheduled PDF or PNG of a dashboard.

## What was created

| Kind | Name | What it shows or does |
|---|---|---|
| Dashboard | Risk Guard and OpenShell: overview | Events, refusals, middleware failures, events by OCSF class, refusals over time by reason, sandboxes and routes refused most. Defaults to the last 24 hours, refreshes every 30 s. |
| Saved searches | Risk Guard refusals; Middleware failures (failed closed); All risk-guard decisions | The three questions you will ask most. Open them under Discover, **Open**. |
| Anomaly detectors | `risk-guard-refusals-per-minute`, `middleware-failures-per-minute`, `all-security-events-per-minute` | Each counts events per minute and flags unusual minutes. Under **Anomaly Detection**. |
| Alert monitor | Middleware failures: 3 or more in 5 minutes | Checks every 5 minutes. Fires when Risk Guard could not answer (so the request was refused) at least three times in the last five minutes. |
| Report | Risk Guard daily overview | A daily PDF of the dashboard, under **Reporting**. |

## The dashboards, organised around agents

**Start with `0. Start here: OpenShell, Risk Guard, OpenSearch`.** It shows the three systems side by side, left to right: what OpenShell denied, what Risk Guard refused (and why), and what OpenSearch holds, with one chart that splits "who stopped calls" between the layers and the "One call, both layers" search underneath. Every other dashboard links back to it.

Each starts with the same navigation bar. The questions they answer, in the order an operator asks them:

| Dashboard | The question | What is on it |
|---|---|---|
| **Fleet: are my agents behaving?** | Is anything wrong, and with whom? | Agents active, decisions, refused, highest score, containment actions. A table of every agent (task, decisions, refused, highest score, last seen). Decisions per minute and share refused, by agent. Which sandbox is which agent. Recent notable events |
| **One agent: what it does and what was refused** | What is this agent doing? | Pick an agent; the whole page follows. Decisions, refused, highest score, routes and destinations used. Allowed and refused over time. **What it calls** (host, method, route, allowed, refused) and **where it connects** (destination, allowed, refused, would be refused in enforce mode). Why it was refused. Its event log |
| **Incidents: what was refused, contained or signalled** | What happened, in what order? Is it safe to enforce? | Refusals, tunnels refused, signals. A timeline by kind. By agent: events, first seen, last seen, highest score. **Enforcement readiness:** what shadow mode would have refused, per agent. Signals and their outcomes. The incident log in time order |
| **Control health: is the control itself working?** | Can I trust what I see? | Times Risk Guard could not answer, supervisors that went quiet, signals held back by a limit. Risk Guard's heartbeat (a gap is silence). Which sources are reporting. Gateway authentication failures. Operator sessions |
| **Sandbox view: calls / egress and policy** | What do the sandboxes (not the agents) do? | OpenShell's own events: model and tool calls, denied destinations, names agents asked for that policy has not approved |
| **Model training: the synthetic data** | (demo) | The generated traffic behind the anomaly detector |

Where the numbers come from: Risk Guard counts every decision per agent per minute and sends a summary, one row per route and one row per destination (`gate: summary`, `route`, `egress`). The
agent's name is the one set with `agent-rename`. OpenShell's events know only the sandbox, so the sandbox views are per sandbox; **Fleet** has the table that says which sandbox is which agent.

`python scripts/siem/install_content.py` installs them and removes the dashboards they replace.

Two words in the data that matter: a **refusal** (`middleware_denied:...`) means Risk Guard decided the behaviour was too risky. A **failure** (`middleware_failed`) means Risk Guard did not answer in time or at all, and OpenShell refused because the middleware is set to fail closed. They need different responses: refusals are the guard working; failures are the guard having a bad moment.

## What to expect, honestly

- **Anomaly detectors need history.** They need roughly 128 one-minute intervals of data (about two hours of steady traffic) before they produce results, and they do poorly on very sparse data. This demo mostly has bursts when you run a scenario, so expect "initializing" first, and noisy or empty results after. It becomes useful when agents run for hours or days, not in a five-minute demo. Treat them as a feature to show, not as proof of detection quality.
- **The alert has no destination yet.** It records an alert in the **Alerting** page but sends nothing (no Slack or email channel is configured), by design for a demo.
- **Reports:** the definition exists and the schedule is set. Generating the PDF needs a headless browser inside the Dashboards pod, and I have not confirmed it renders here. Use **Reporting, Create** and press "Generate" once to check before relying on it.
- **The viewer account** (read-only) can open the dashboard and searches, but cannot edit or delete them. The detectors, alerting and reporting pages are for the admin account.
- **Not a verdict.** A spike here means "look", not "attack".

## First ten minutes

1. Sign in, open **Dashboards**, **Risk Guard and OpenShell: overview**. Set the time range to the last 7 days if it looks empty.
2. Click into a bar of "Refusals over time, by reason" and note the reason text.
3. Open **Discover**, **Open**, **Risk Guard refusals**. Expand one event and read the fields (see the field map in [siem-integration.md](siem-integration.md)).
4. Open **Anomaly Detection**, **Detectors**. Status should say initializing or running.
5. Open **Alerting**, **Monitors**, then run the demo to trigger a few failures if you want to see the alert state change.

## Where this goes next

Today the SIEM only listens. The design for sending what it learns back to Risk Guard (tighten automatically, loosen only with a person's approval, every automated action limited, logged and expiring) is in [siem-integration.md](siem-integration.md); the action API it needs is not built.

## Checking the dashboards

`python scripts/siem/check_dashboards.py` runs every chart's search against OpenSearch and lists any that would draw nothing or fail. It cannot see how a chart renders, only whether its data is there.
