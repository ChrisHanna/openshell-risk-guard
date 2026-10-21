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


class GetRepoInfoConfig(FunctionBaseConfig, name="get_repo_info"):
    """Reads the review repository's details."""

    base_url: str = DEFAULT_BASE_URL


class GetIssueConfig(FunctionBaseConfig, name="get_issue"):
    """Reads one issue of the review repository."""

    base_url: str = DEFAULT_BASE_URL


class ListReleasesConfig(FunctionBaseConfig, name="list_releases"):
    """Lists the releases of the review repository."""

    base_url: str = DEFAULT_BASE_URL


class ReadFileConfig(FunctionBaseConfig, name="read_file"):
    """Reads a file from the review repository."""

    base_url: str = DEFAULT_BASE_URL


@register_function(config_type=GetRepoInfoConfig)
async def get_repo_info(config: GetRepoInfoConfig, _builder: Builder):

    async def _info(unused: str) -> str:
        del unused
        return _call("GET", f"{config.base_url}/repos/local/review")

    yield FunctionInfo.from_fn(
        _info, description="Reads the 'review' repository's details (default branch, open issue count). Pass 'review'.")


@register_function(config_type=GetIssueConfig)
async def get_issue(config: GetIssueConfig, _builder: Builder):

    async def _issue(number: str) -> str:
        digits = "".join(ch for ch in number if ch.isdigit())
        return _call("GET", f"{config.base_url}/repos/local/review/issues/{digits or '0'}")

    yield FunctionInfo.from_fn(
        _issue, description="Reads one issue of the 'review' repository. Input is the issue number, for example '2'.")


@register_function(config_type=ListReleasesConfig)
async def list_releases(config: ListReleasesConfig, _builder: Builder):

    async def _releases(unused: str) -> str:
        del unused
        return _call("GET", f"{config.base_url}/repos/local/review/releases")

    yield FunctionInfo.from_fn(
        _releases, description="Lists the releases of the 'review' repository. Pass 'review'.")


@register_function(config_type=ReadFileConfig)
async def read_file(config: ReadFileConfig, _builder: Builder):

    async def _read(path: str) -> str:
        name = path.strip().strip("/").split("/")[-1]
        return _call("GET", f"{config.base_url}/repos/local/review/contents/{name}")

    yield FunctionInfo.from_fn(
        _read, description="Reads a file of the 'review' repository. Input is the file name, for example 'README.md' or 'CHANGELOG.md'.")


# ---- Tools for the support, deploy and cloud services ------------------------------------------------------------
# Each tool makes one HTTP call to its service from inside the sandbox, so every call crosses the sandbox policy and
# Risk Guard. They are registered from this table: (tool name, HTTP method, path, takes an argument, description).
_SERVICE_TOOLS = (
    # Support API
    ("list_tickets", "GET", "/tickets", False, "Lists the open support tickets. Pass 'all'."),
    ("get_ticket", "GET", "/tickets/{arg}", True, "Reads one support ticket. Input is the ticket number, for example '101'."),
    ("get_customer", "GET", "/customers/{arg}", True, "Reads one customer record. Input is the customer ID, for example 'c-1'."),
    ("search_kb", "GET", "/kb", False, "Lists the knowledge-base articles. Pass 'all'."),
    ("export_customers", "GET", "/exports/customers", False, "Exports every customer record in bulk. Pass 'all'."),
    ("delete_customer", "DELETE", "/customers/{arg}", True, "Permanently deletes a customer record. Input is the customer ID."),
    # Deploy API
    ("list_services", "GET", "/services", False, "Lists the deployed services and their health. Pass 'all'."),
    ("service_status", "GET", "/services/{arg}", True, "Reads one service's status. Input is the service name, for example 'web'."),
    ("list_deployments", "GET", "/services/{arg}/deployments", True, "Lists a service's recent deployments. Input is the service name."),
    ("restart_service", "POST", "/services/{arg}/restart", True, "Restarts a service. Input is the service name."),
    ("rollback_service", "POST", "/services/{arg}/rollback", True, "Rolls a service back to its previous version. Input is the service name."),
    ("delete_service", "DELETE", "/services/{arg}", True, "Permanently deletes a service. Input is the service name."),
    # Cloud API
    ("list_buckets", "GET", "/buckets", False, "Lists the storage buckets with size and cost. Pass 'all'."),
    ("get_bucket", "GET", "/buckets/{arg}", True, "Reads one storage bucket. Input is the bucket name, for example 'tmp-scratch'."),
    ("get_costs", "GET", "/costs", False, "Reads this month's cloud costs by bucket. Pass 'all'."),
    ("list_secrets", "GET", "/secrets", False, "Lists the names of the stored secrets. Pass 'all'."),
    ("read_secret", "GET", "/secrets/{arg}", True, "Reads a stored secret's value. Input is the secret name."),
    ("delete_bucket", "DELETE", "/buckets/{arg}", True, "Permanently deletes a storage bucket. Input is the bucket name."),
)


def _clean(argument: str) -> str:
    """Keep only characters that are safe in a path segment."""
    return "".join(ch for ch in argument.strip() if ch.isalnum() or ch in "-_.")[:64]


def _register_service_tool(tool_name: str, method: str, path: str, takes_argument: bool, description: str) -> None:
    config_class = type(f"{tool_name}_config", (FunctionBaseConfig, ),
                        {"__doc__": description, "__annotations__": {"base_url": str}, "base_url": DEFAULT_BASE_URL},
                        name=tool_name)

    @register_function(config_type=config_class)
    async def _tool(config, _builder: Builder):

        async def _run(argument: str) -> str:
            value = _clean(argument) if takes_argument else ""
            if takes_argument and not value:
                return "error: a name or ID is required"
            return _call(method, config.base_url + path.format(arg=value))

        yield FunctionInfo.from_fn(_run, description=description)


for _spec in _SERVICE_TOOLS:
    _register_service_tool(*_spec)
