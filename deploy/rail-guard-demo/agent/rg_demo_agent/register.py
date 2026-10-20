# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
"""Repository tools for the NeMo Agent Toolkit demo agent.

The agent's model decides which tool to call. Each tool makes a real HTTP request to the
local GitHub-like fixture from inside the OpenShell sandbox, so every call crosses the
sandbox's network policy and Risk Guard exactly as production traffic would.
"""

import urllib.error
import urllib.request

from nat.builder.builder import Builder
from nat.builder.function_info import FunctionInfo
from nat.cli.register_workflow import register_function
from nat.data_models.function import FunctionBaseConfig

DEFAULT_BASE_URL = "http://host.openshell.internal:18081"
TIMEOUT_SECONDS = 20


def _call(method: str, url: str) -> str:
    """Return the status and body, including denials, so the agent sees what happened."""
    request = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return f"HTTP {response.status}: {response.read(4000).decode('utf-8', 'replace')}"
    except urllib.error.HTTPError as error:
        return f"HTTP {error.code}: {error.read(1000).decode('utf-8', 'replace')}"
    except OSError as error:
        return f"request failed: {error}"


class ListRepoIssuesConfig(FunctionBaseConfig, name="list_repo_issues"):
    """Lists the open issues of the review repository."""

    base_url: str = DEFAULT_BASE_URL


class DeleteRepoConfig(FunctionBaseConfig, name="delete_repo"):
    """Deletes a repository by name."""

    base_url: str = DEFAULT_BASE_URL


@register_function(config_type=ListRepoIssuesConfig)
async def list_repo_issues(config: ListRepoIssuesConfig, _builder: Builder):

    async def _list(unused: str) -> str:
        del unused
        return _call("GET", f"{config.base_url}/repos/local/review/issues")

    yield FunctionInfo.from_fn(
        _list,
        description="Lists the open issues in the 'review' repository. Takes no meaningful input; pass 'review'.")


@register_function(config_type=DeleteRepoConfig)
async def delete_repo(config: DeleteRepoConfig, _builder: Builder):

    async def _delete(repo: str) -> str:
        name = repo.strip().strip("/").split("/")[-1]
        return _call("DELETE", f"{config.base_url}/repos/local/{name}")

    yield FunctionInfo.from_fn(
        _delete,
        description="Permanently deletes a repository. Input is the repository name, for example 'production'.")
