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

## Dashboards built on Risk Guard's own events

| Dashboard | Shows |
|---|---|
| **Risk Guard: decisions and workloads** | Events, middleware refusals, tunnel events, signals and workloads seen; refusals over time by reason; the risk score of refused requests (average and highest); each workload's events and highest score; the signals behind refusals; events by task profile and by where Risk Guard acted |
| **Risk Guard: quarantine and signals** | Tunnels refused or would-be-refused, silent supervisors, and the signals the SIEM sent (applied, dry run, limited or unknown), who sent them and which workloads they named |
| **Model training: the synthetic data** | The generated traffic and injected attacks behind the anomaly detector. Its data sits in January 2027, so the dashboard opens on that range |

They are installed by `python scripts/siem/install_content.py` along with the first dashboard. The workload names are what Risk Guard knows the agents as (for the fleet, their application IDs).

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
