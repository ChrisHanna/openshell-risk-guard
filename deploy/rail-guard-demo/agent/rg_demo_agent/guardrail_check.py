# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Screen a task with NVIDIA NeMo Guardrails before the agent runs.

Exit codes: 0 = passed, 3 = blocked by the input rail, 4 = the rail could not run.
A rail failure is reported, not silently treated as a pass, so the runner can decide.
"""

import asyncio
import os
import pathlib
import sys

from nemoguardrails import LLMRails
from nemoguardrails import RailsConfig
from nemoguardrails.rails.llm.options import RailStatus
from nemoguardrails.rails.llm.options import RailType

CONFIG_DIR = pathlib.Path(os.environ.get("RG_GUARDRAILS_DIR", "/opt/agent-src/guardrails"))


async def _check(task: str) -> int:
    rails = LLMRails(RailsConfig.from_path(str(CONFIG_DIR)))
    result = await rails.check_async([{"role": "user", "content": task}], rail_types=[RailType.INPUT])
    if result.status == RailStatus.BLOCKED:
        print(f"GUARDRAILS: blocked by input rail ({getattr(result, 'rail', None) or 'self check input'})")
        return 3
    print("GUARDRAILS: input rail passed")
    return 0


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: guardrail_check.py <task>", file=sys.stderr)
        return 4
    try:
        return asyncio.run(_check(sys.argv[1]))
    except Exception as error:  # noqa: BLE001 - surface any rail failure to the runner
        print(f"GUARDRAILS: input rail could not run: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
