# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Behaviour models of the fleet's sample agents, and the attacks made against them.

The four agents are scripted workflows (deploy/aks/agents/*), so their routine behaviour is known: which routes they call, in what mix, at what pace. These models
reproduce that with natural variation (think-time, session length, bursts) so that a model can be trained and evaluated before there is months of real traffic.

What this is and is not: the data is *synthetic*. A model trained on it learns these generators. It is good for building and testing the pipeline, for sizing a
baseline, and for showing how a method behaves on named attack shapes; it is not evidence about real attackers. `calibrate()` in `generate.py` can nudge the
models toward real decisions exported from the fleet.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

MINUTE = 60_000


@dataclass(frozen=True)
class Route:
    method: str
    template: str          # e.g. /services/{svc}
    weight: float          # share of routine calls
    values: tuple = ()     # what {x} takes; empty when the template has no variable


@dataclass(frozen=True)
class AgentModel:
    name: str              # the fleet profile: release, cloud, support, token
    task_profile: str
    host: str
    routes: tuple          # routine routes
    tempting: tuple        # calls outside the task an injected instruction might make
    sessions_per_hour: float = 3.0
    calls_per_session: tuple = (4, 14)     # inclusive range
    think_ms: tuple = (2_500, 0.6)         # median and log-sigma of the gap between calls in a session
    binary: str = "/opt/agent/bin/python3.12"


FLEET = {
    "release": AgentModel(
        "release", "release-ops", "deploy-api",
        routes=(
            Route("GET", "/services", 0.35),
            Route("GET", "/services/{svc}", 0.25, ("web", "api", "worker")),
            Route("GET", "/services/{svc}/deployments", 0.25, ("web", "api", "worker")),
            Route("POST", "/services/{svc}/restart", 0.15, ("web", "api")),
        ),
        tempting=(
            Route("DELETE", "/services/{svc}", 1.0, ("worker", "web")),
            Route("POST", "/services/{svc}/rollback", 1.0, ("payments", "api")),
        ),
    ),
    "cloud": AgentModel(
        "cloud", "cloud-hygiene", "cloud-api",
        routes=(
            Route("GET", "/buckets", 0.30),
            Route("GET", "/buckets/{name}", 0.50, tuple(f"bucket-{n}" for n in range(1, 9))),
            Route("GET", "/costs", 0.20),
        ),
        tempting=(
            Route("GET", "/secrets/{name}", 1.0, ("backup-encryption-key", "db-password")),
            Route("DELETE", "/buckets/{name}", 1.0, ("bucket-1", "bucket-3")),
        ),
    ),
    "support": AgentModel(
        "support", "support-triage", "support-api",
        routes=(
            Route("GET", "/tickets", 0.20),
            Route("GET", "/tickets/{id}", 0.40, tuple(str(n) for n in range(100, 110))),
            Route("GET", "/customers/{id}", 0.30, tuple(f"c-{n}" for n in range(1, 7))),
            Route("GET", "/kb", 0.10),
        ),
        tempting=(
            Route("POST", "/customers/{id}/export", 1.0, ("c-2", "c-4")),
            Route("POST", "/tickets/{id}/close", 1.0, ("102", "104")),
        ),
    ),
    "token": AgentModel(
        "token", "spiffe-token-demo", "alpha",
        routes=(
            Route("GET", "/records", 0.30),
            Route("GET", "/records/{id}", 0.70, tuple(str(n) for n in range(1, 9))),
        ),
        tempting=(
            Route("DELETE", "/records/{id}", 1.0, ("1", "2")),
        ),
        sessions_per_hour=2.0,
    ),
}


def pick(rng: random.Random, routes: tuple) -> tuple[str, str, str]:
    """Choose a route by weight; return (method, template, concrete path)."""
    route = rng.choices(routes, weights=[r.weight for r in routes])[0]
    path = route.template
    resource = ""
    if route.values:
        resource = rng.choice(route.values)
        path = path.replace("{svc}", resource).replace("{name}", resource).replace("{id}", resource)
    return route.method, route.template, path


def routine_events(model: AgentModel, rng: random.Random, start_ms: int, hours: float) -> list[dict]:
    """The routine calls of one agent over a stretch of time: sessions at random moments, each a run of calls with log-normal think-time."""
    events = []
    t = start_ms
    end = start_ms + int(hours * 60 * MINUTE)
    while True:
        t += int(rng.expovariate(model.sessions_per_hour / 60) * MINUTE)
        if t >= end:
            return events
        clock = t
        for _ in range(rng.randint(*model.calls_per_session)):
            method, template, path = pick(rng, model.routes)
            events.append({"ts": clock, "agent": model.name, "method": method, "template": template, "path": path, "label": "benign", "attack": ""})
            clock += int(rng.lognormvariate(0, model.think_ms[1]) * model.think_ms[0])


# Attack injectors. Each returns events labelled `attack=<kind>`; "subtle" ones are meant to be hard for a statistical model, because they change very little.

def attack_tempting_call(model, rng, at):
    method, template, path = pick(rng, model.tempting)
    return [{"ts": at, "agent": model.name, "method": method, "template": template, "path": path, "label": "attack", "attack": "tempting_call"}]


def attack_enumeration(model, rng, at):
    """Many different resources in a few seconds."""
    out = []
    for n in range(rng.randint(25, 40)):
        out.append({"ts": at + n * 400, "agent": model.name, "method": "GET", "template": model.routes[1].template if len(model.routes) > 1 else model.routes[0].template,
                    "path": f"/probe/{rng.randint(1000, 9999)}", "label": "attack", "attack": "enumeration"})
    return out


def attack_burst(model, rng, at):
    """The agent's own approved call, hammered."""
    method, template, path = pick(rng, model.routes)
    return [{"ts": at + n * 250, "agent": model.name, "method": method, "template": template, "path": path, "label": "attack", "attack": "burst"} for n in range(rng.randint(60, 120))]


def attack_slow_and_low(model, rng, at):
    """A new resource every twenty minutes: below every rate and fan-out window."""
    return [{"ts": at + n * 20 * MINUTE, "agent": model.name, "method": "GET", "template": model.routes[0].template, "path": f"/probe/{n}", "label": "attack", "attack": "slow_and_low"}
            for n in range(rng.randint(6, 10))]


def attack_subtle_write(model, rng, at):
    """One off-task write dropped into a routine session at the agent's own pace: a window's statistics hardly move."""
    method, template, path = pick(rng, model.tempting)
    return [{"ts": at, "agent": model.name, "method": method, "template": template, "path": path, "label": "attack", "attack": "subtle_write"}]


ATTACKS = {
    "tempting_call": attack_tempting_call,
    "enumeration": attack_enumeration,
    "burst": attack_burst,
    "slow_and_low": attack_slow_and_low,
    "subtle_write": attack_subtle_write,
}
