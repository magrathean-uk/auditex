"""One sign-in per audit run (DEC-065), Exchange kept in the guided delegated path (DEC-068 (4)).

The run path is driven for real (``cli.run_live`` and ``guided.run_guided`` over a real ``GraphClient``); only
the network edge is faked: msal (counting every interactive call), the HTTP session and the certificate
client. Two static checks over ``src/`` close what a run cannot show: no ``az login`` on the run path and no
``Connect-*`` without an access token.
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest
import requests

from auditex import guided
from azure_tenant_audit import certificate_auth
from azure_tenant_audit import cli as tenant_cli
from azure_tenant_audit.adapters.powershell_graph import PowerShellGraphAdapter
from azure_tenant_audit.collectors.base import CollectorResult
from azure_tenant_audit.collectors.exchange_policy import (
    EXCHANGE_ONLINE_SCOPE,
    _exchange_session,
)
from azure_tenant_audit.config import AuthConfig, CollectorConfig
from azure_tenant_audit.graph import GraphClient, GraphError
from azure_tenant_audit.power_bi import POWERBI_SCOPE
from azure_tenant_audit.power_platform import BAP_SCOPE

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
UPN = "auditor@constructed.onmicrosoft.com"
TEAMS_SCOPE = "48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default"
SERVICE_SCOPES = (EXCHANGE_ONLINE_SCOPE, POWERBI_SCOPE, BAP_SCOPE, TEAMS_SCOPE)


# The network edge -------------------------------------------------------------------------------

class FakeMsal:
    """Stands in for the msal module: counts interactive sign-ins, public clients and token caches."""

    def __init__(self, *, silent_refuses: tuple[str, ...] = ()) -> None:
        self.interactive_calls: list[list[str]] = []
        self.silent_calls: list[list[str]] = []
        self.caches: list[object] = []
        self.public_clients: list[object] = []
        self.silent_refuses = silent_refuses
        fake = self

        class TokenCache:
            def __init__(self) -> None:
                fake.caches.append(self)
                self.accounts: list[dict] = []

        class PublicClientApplication:
            def __init__(self, client_id, authority=None, token_cache=None, **kwargs):  # noqa: ANN001
                assert token_cache is not None, "the delegated run needs its one shared in-memory cache"
                fake.public_clients.append(self)
                self.cache = token_cache

            def get_accounts(self):
                return list(self.cache.accounts)

            def acquire_token_interactive(self, scopes, **kwargs):  # noqa: ANN001
                fake.interactive_calls.append(list(scopes))
                self.cache.accounts = [{"username": UPN}]
                return {"access_token": "delegated-graph-token"}

            def acquire_token_silent(self, scopes, account=None, **kwargs):  # noqa: ANN001
                fake.silent_calls.append(list(scopes))
                if account is None or not self.cache.accounts or scopes[0] in fake.silent_refuses:
                    return None
                return {"access_token": f"delegated:{scopes[0]}"}

        self.module = types.SimpleNamespace(TokenCache=TokenCache, PublicClientApplication=PublicClientApplication)

    @property
    def interactive_count(self) -> int:
        return len(self.interactive_calls)


def _response(payload: dict, status: int = 200) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(payload).encode("utf-8")
    response.headers["Content-Type"] = "application/json"
    return response


class FakeSession:
    """Graph reads answer an empty page; token POSTs (client secret) answer an app token."""

    def __init__(self) -> None:
        self.token_posts: list[str] = []

    def request(self, method, url, **kwargs):  # noqa: ANN001
        if url.endswith("/me"):
            return _response({"displayName": "Constructed Auditor", "userPrincipalName": UPN, "id": "constructed"})
        if "/domains" in url:
            return _response({"value": [{"id": "constructed.onmicrosoft.com", "isInitial": True}]})
        return _response({"value": []})

    def post(self, url, data=None, **kwargs):  # noqa: ANN001
        self.token_posts.append(str((data or {}).get("scope")))
        return _response({"access_token": f"app:{(data or {}).get('scope')}", "expires_in": 3600})


class FakeConfidential:
    def __init__(self) -> None:
        self.scopes: list[str] = []

    def acquire_token_for_client(self, scopes):  # noqa: ANN001
        self.scopes.append(scopes[0])
        return {"access_token": f"certificate:{scopes[0]}", "expires_in": 3600}


class TokenProbe:
    """A collector that asks for every service token the shipped collectors ask for, as they ask for it."""

    def __init__(self, name: str, seen: dict) -> None:
        self.name = name
        self.seen = seen

    def run(self, context):  # noqa: ANN001
        client = context["client"]
        client.get_json("/organization")
        self.seen["app"] = {scope: client.app_token_for(scope) for scope in SERVICE_SCOPES}
        self.seen["exchange_session"] = _exchange_session(client, None)
        return CollectorResult(name=self.name, status="ok", payload={}, item_count=0)


def _no_sign_in_subprocess(monkeypatch) -> list[list[str]]:  # noqa: ANN001
    """Any az login, m365 login or Connect-* without an access token reached through subprocess fails the test."""
    calls: list[list[str]] = []
    real = subprocess.run

    def guarded(argv, *args, **kwargs):  # noqa: ANN001
        words = [str(part) for part in (argv if isinstance(argv, (list, tuple)) else [argv])]
        text = " ".join(words)
        calls.append(words)
        if words[:2] in (["az", "login"], ["m365", "login"]) or re.search(r"Connect-\w+(?![^;]*-AccessToken)", text):
            pytest.fail(f"interactive sign-in subprocess on the run path: {words[:2]}")
        return real(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "run", guarded)
    return calls


@pytest.fixture
def edge(monkeypatch):  # noqa: ANN001
    msal = FakeMsal()
    monkeypatch.setitem(sys.modules, "msal", msal.module)
    session = FakeSession()
    confidential = FakeConfidential()
    monkeypatch.setattr(certificate_auth, "build_confidential_client", lambda *args, **kwargs: confidential)
    monkeypatch.setattr(tenant_cli, "GraphClient", lambda auth, **kwargs: GraphClient(auth, session=session, **kwargs))
    monkeypatch.setattr(tenant_cli.run_core, "collector_pause_seconds", lambda _: 0)
    seen: dict = {}
    config = CollectorConfig.from_path(ROOT / "configs" / "collector-definitions.json")
    monkeypatch.setattr(tenant_cli, "REGISTRY", {name: TokenProbe(name, seen) for name in config.default_order})
    _no_sign_in_subprocess(monkeypatch)
    for key in ("AZURE_CLIENT_SECRET", "AZURE_ACCESS_TOKEN", "M365_CLI_APP_ID", "M365_CLI_CLIENT_ID", "AZURE_CLIENT_ID"):
        monkeypatch.delenv(key, raising=False)
    return types.SimpleNamespace(msal=msal, session=session, confidential=confidential, seen=seen)


def _run(tmp_path, *mode_args: str) -> int:  # noqa: ANN001
    args = tenant_cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "constructed.onmicrosoft.com", "--out", str(tmp_path),
        "--run-name", "one-sign-in", "--collectors", "identity", "--no-probe-first", *mode_args,
    ])
    return tenant_cli.run_live(args)


# Run path: interactive sign-ins per mode ------------------------------------------------------------

def test_app_only_secret_run_never_signs_in_interactively(edge, tmp_path) -> None:  # noqa: ANN001
    assert _run(tmp_path, "--client-id", "constructed-app", "--client-secret", "constructed-secret") == 0
    assert edge.msal.interactive_count == 0
    assert edge.msal.public_clients == []
    assert edge.seen["app"][EXCHANGE_ONLINE_SCOPE] == f"app:{EXCHANGE_ONLINE_SCOPE}"
    assert edge.seen["app"][TEAMS_SCOPE] is None  # Teams only from a certificate: skipped, never prompted
    assert edge.seen["exchange_session"]["organization"] == "constructed.onmicrosoft.com"


def test_app_only_certificate_run_never_signs_in_interactively(edge, tmp_path, certificate_material) -> None:  # noqa: ANN001
    assert _run(
        tmp_path, "--client-id", "constructed-app",
        "--certificate-path", str(certificate_material.pem), "--certificate-thumbprint", certificate_material.thumbprint,
    ) == 0
    assert edge.msal.interactive_count == 0
    assert edge.msal.public_clients == []
    assert edge.session.token_posts == []  # every app token from the one certificate client
    assert set(edge.confidential.scopes) >= set(SERVICE_SCOPES)
    assert edge.seen["exchange_session"]["access_token"] == f"certificate:{EXCHANGE_ONLINE_SCOPE}"


def test_delegated_run_signs_in_once_and_mints_exchange_silently(edge, tmp_path) -> None:  # noqa: ANN001
    assert _run(tmp_path, "--interactive", "--client-id", "constructed-public-app") == 0
    assert edge.msal.interactive_count == 1
    assert len(edge.msal.public_clients) == 1 and len(edge.msal.caches) == 1
    assert [EXCHANGE_ONLINE_SCOPE] in edge.msal.silent_calls
    assert edge.seen["exchange_session"] == {
        "kind": "exchange_online", "access_token": f"delegated:{EXCHANGE_ONLINE_SCOPE}", "user_principal_name": UPN,
    }
    assert all(token is None for token in edge.seen["app"].values())  # no app token in a delegated run


@pytest.mark.parametrize("selection", [[], ["--collectors", "identity"], ["--collectors", "identity,exchange"]])
def test_guided_delegated_exchange_run_signs_in_once(edge, monkeypatch, tmp_path, selection) -> None:  # noqa: ANN001
    monkeypatch.setattr(guided, "build_doctor_report", lambda **kwargs: {
        "system": {"os": "Darwin", "machine": "arm64"}, "auth": {},
        "readiness": {"core_ready": True, "exchange_ready": True},
    })
    monkeypatch.setattr(guided, "_ensure_exchange_module", lambda **kwargs: 0)
    monkeypatch.setattr(guided, "_persist_local_defaults", lambda **kwargs: None)
    monkeypatch.setattr(guided, "_run_azure_login", lambda *a, **k: pytest.fail("az login on the run path"))
    monkeypatch.setattr(guided, "_ensure_m365_login", lambda *a, **k: pytest.fail("m365 login on the run path"))
    seen_argv: list[list[str]] = []
    real_main = tenant_cli.main
    monkeypatch.setattr(guided.tenant_cli, "main", lambda argv, **kwargs: seen_argv.append(list(argv)) or real_main(argv, **kwargs))
    args = guided.build_guided_parser().parse_args([
        "--flow", "gr-audit", "--include-exchange", "--client-id", "constructed-public-app",
        "--tenant-id", "constructed.onmicrosoft.com", "--tenant-name", "acme", "--out", str(tmp_path),
        "--no-probe-first", "--non-interactive", "--browser-command", "true", *selection,
    ])
    assert guided.run_guided(args) == 0
    assert edge.msal.interactive_count == 1
    collectors = seen_argv[0][seen_argv[0].index("--collectors") + 1].split(",")
    # An explicit list keeps Exchange over the one sign-in: exchange_policy added, the m365 CLI collector swapped out.
    assert "exchange_policy" in collectors and "exchange" not in collectors
    if selection:
        assert collectors == ["identity", "exchange_policy"]
    assert edge.seen["exchange_session"]["access_token"] == f"delegated:{EXCHANGE_ONLINE_SCOPE}"


# The guard: no second prompt, no prompt for another resource ----------------------------------------

def _delegated_client(monkeypatch, msal: FakeMsal) -> GraphClient:  # noqa: ANN001
    monkeypatch.setitem(sys.modules, "msal", msal.module)
    auth = AuthConfig(tenant_id="constructed.onmicrosoft.com", client_id="constructed-public-app", auth_mode="interactive",
                      interactive_scopes=["Directory.Read.All"])
    return GraphClient(auth, session=FakeSession())


def test_second_interactive_sign_in_is_refused(monkeypatch) -> None:  # noqa: ANN001
    msal = FakeMsal(silent_refuses=("Directory.Read.All",))
    client = _delegated_client(monkeypatch, msal)
    assert client.ensure_token() == "delegated-graph-token"
    client._token = None  # the Graph token is gone and the cache cannot refresh it
    with pytest.raises(GraphError, match="second sign-in is not opened"):
        client.ensure_token()
    assert msal.interactive_count == 1


def test_resource_without_consent_is_a_gap_not_a_prompt(monkeypatch) -> None:  # noqa: ANN001
    msal = FakeMsal(silent_refuses=(EXCHANGE_ONLINE_SCOPE,))
    client = _delegated_client(monkeypatch, msal)
    assert client.delegated_token_for(EXCHANGE_ONLINE_SCOPE) is None  # before the sign-in: never starts one
    assert msal.interactive_count == 0
    client.ensure_token()
    assert _exchange_session(client, None) == {"kind": "none"}
    assert msal.interactive_count == 1


@pytest.mark.parametrize("upn,connects", [(UPN, True), ("auditor'; Remove-Mailbox x", False), ("", False)])
def test_delegated_exchange_connect_carries_the_token_and_user(upn, connects) -> None:  # noqa: ANN001
    env: dict[str, str] = {}
    session = {"kind": "exchange_online", "access_token": "delegated-token", "user_principal_name": upn}
    prelude = PowerShellGraphAdapter._session_prelude(session, env)
    if not connects:
        assert prelude == "" and "AUDITEX_EXO_ACCESS_TOKEN" not in env
        return
    assert "Connect-ExchangeOnline -AccessToken $env:AUDITEX_EXO_ACCESS_TOKEN" in prelude
    assert "-UserPrincipalName $env:AUDITEX_EXO_USER_PRINCIPAL_NAME" in prelude
    assert upn not in prelude and "delegated-token" not in prelude
    assert env == {"AUDITEX_EXO_ACCESS_TOKEN": "delegated-token", "AUDITEX_EXO_USER_PRINCIPAL_NAME": upn}


# Static checks over src/ ----------------------------------------------------------------------------

def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                ids.add(id(first.value))
    return ids


def _string_parts(tree: ast.AST) -> list[tuple[int, str]]:
    skip = _docstring_nodes(tree)
    return [(node.lineno, node.value) for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in skip]


def connect_without_token(source: str) -> list[int]:
    """Lines of string literals that call a Connect-* cmdlet without -AccessToken in the same literal."""
    return [line for line, text in _string_parts(ast.parse(source))
            for match in re.finditer(r"Connect-[A-Za-z]+", text) if "-AccessToken" not in text[match.start():]]


def _is_az_login(node: ast.AST) -> bool:
    if isinstance(node, (ast.List, ast.Tuple)):
        return [item.value for item in node.elts[:2] if isinstance(item, ast.Constant)] == ["az", "login"]
    return isinstance(node, ast.Call) and any(
        isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.strip().startswith("az login")
        for arg in node.args
    )


def az_login_sites(source: str) -> list[str]:
    """Functions (or <module>) holding an az login invocation: an argv literal starting az, login, or a command string."""
    tree = ast.parse(source)
    sites = {function.name for function in ast.walk(tree) if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
             and any(_is_az_login(node) for node in ast.walk(function))}
    top = [statement for statement in tree.body if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    if any(_is_az_login(node) for statement in top for node in ast.walk(statement)):
        sites.add("<module>")
    return sorted(sites)


def _sources() -> dict[str, str]:
    return {str(path.relative_to(ROOT)): path.read_text(encoding="utf-8") for path in sorted(SRC.rglob("*.py"))}


def test_no_connect_cmdlet_without_an_access_token_in_src() -> None:
    offenders = {path: lines for path, text in _sources().items() if (lines := connect_without_token(text))}
    assert offenders == {}


def test_no_az_login_on_the_run_path_in_src() -> None:
    sites = {path: found for path, text in _sources().items() if (found := az_login_sites(text))}
    # The one az login left is the one-time GA app setup (the Microsoft 365 CLI setup signs in as Azure CLI).
    assert sites == {"src/auditex/guided.py": ["_run_azure_login"]}
    tree = ast.parse((SRC / "auditex" / "guided.py").read_text(encoding="utf-8"))
    callers = {
        function.name for function in ast.walk(tree) if isinstance(function, ast.FunctionDef)
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_run_azure_login"
    }
    assert callers == {"_run_ga_setup_flow"}


def test_static_checks_catch_a_planted_sign_in() -> None:
    planted = (
        "import subprocess\n"
        "def login(t):\n    return subprocess.run(['az', 'login', '--tenant', t])\n"
        "def shell():\n    return subprocess.run('az login --use-device-code', shell=True)\n"
        "SCRIPT = 'Import-Module ExchangeOnlineManagement; Connect-ExchangeOnline -UserPrincipalName x'\n"
        "IPPS = 'Connect-IPPSSession -AccessToken $t'\n"
        "ARGV = ('az', 'login')\n"
    )
    assert az_login_sites(planted) == ["<module>", "login", "shell"]
    assert connect_without_token(planted) == [6]


# The opt-in SharePoint admin read (M08-T12) -----------------------------------------------------------------

# A renamed tenant: the initial domain (--tenant-id) stays constructed.onmicrosoft.com; Graph's root site names the
# current host, and every token scope and request goes there.
SHAREPOINT_ORIGIN = "https://renamed-admin.sharepoint.com"


class SharePointAdminEdge:
    """Graph answers the root site's current SharePoint host; the admin host answers one tenant settings object."""

    def __init__(self, session: FakeSession) -> None:
        self.gets: list[tuple[str, str]] = []
        real = session.request

        def request(method, url, **kwargs):  # noqa: ANN001
            if url.split("?", 1)[0].endswith("/sites/root"):
                return _response({"id": "constructed", "siteCollection": {"hostname": "renamed.sharepoint.com"}})
            return real(method, url, **kwargs)

        session.request = request

    def session(self):  # noqa: ANN201
        edge = self

        class Session:
            def get(self, url, headers=None, **kwargs):  # noqa: ANN001
                edge.gets.append((url, headers["Authorization"]))
                response = _response({"d": {"ODBSharingCapability": 0, "EmailAttestationRequired": True}})
                response.headers["Content-Type"] = "application/json;odata=verbose"
                response._content_consumed = True  # iter_content then streams the constructed body
                return response

            def close(self) -> None:
                return None

        return Session()


@pytest.fixture
def sharepoint_admin(edge, monkeypatch):  # noqa: ANN001
    from azure_tenant_audit.collectors import sharepoint_admin as spa

    admin = SharePointAdminEdge(edge.session)
    collector = spa.SharePointAdminCollector()
    collector.session_factory = admin.session
    monkeypatch.setitem(tenant_cli.REGISTRY, "sharepoint_admin", collector)
    # The constructed tokens are opaque; the gate is proved in tests/test_sharepoint_admin_collector.py.
    monkeypatch.setattr(spa, "token_fits", lambda token, origin, *, delegated: token in {
        f"delegated:{origin}/AllSites.FullControl", f"certificate:{origin}/.default"})
    return admin


def _run_sharepoint_admin(tmp_path, *mode_args: str) -> int:  # noqa: ANN001
    args = tenant_cli.build_parser().parse_args([
        "--tenant-name", "acme", "--tenant-id", "constructed.onmicrosoft.com", "--out", str(tmp_path),
        "--run-name", "sharepoint-admin", "--collectors", "sharepoint_admin", "--no-probe-first", *mode_args,
    ])
    return tenant_cli.run_live(args)


def test_delegated_sharepoint_admin_read_rides_the_one_sign_in(edge, sharepoint_admin, tmp_path) -> None:  # noqa: ANN001
    assert _run_sharepoint_admin(tmp_path, "--interactive", "--client-id", "constructed-public-app") == 0
    assert edge.msal.interactive_count == 1
    assert [SHAREPOINT_ORIGIN + "/AllSites.FullControl"] in edge.msal.silent_calls
    assert sharepoint_admin.gets == [(SHAREPOINT_ORIGIN + "/_api/SPO.Tenant",
                                      f"Bearer delegated:{SHAREPOINT_ORIGIN}/AllSites.FullControl")]
    # The SharePoint permission never joins the Graph sign-in.
    assert not any("sharepoint" in scope.lower() or "FullControl" in scope for scope in edge.msal.interactive_calls[0])


def test_delegated_sharepoint_admin_read_without_consent_is_a_skip_not_a_prompt(edge, sharepoint_admin, tmp_path) -> None:  # noqa: ANN001
    edge.msal.silent_refuses = (SHAREPOINT_ORIGIN + "/AllSites.FullControl",)
    assert _run_sharepoint_admin(tmp_path, "--interactive", "--client-id", "constructed-public-app") == 0
    assert edge.msal.interactive_count == 1
    assert sharepoint_admin.gets == []


def test_certificate_sharepoint_admin_read_never_prompts(edge, sharepoint_admin, tmp_path, certificate_material) -> None:  # noqa: ANN001
    assert _run_sharepoint_admin(
        tmp_path, "--client-id", "constructed-app",
        "--certificate-path", str(certificate_material.pem), "--certificate-thumbprint", certificate_material.thumbprint,
    ) == 0
    assert edge.msal.interactive_count == 0 and edge.msal.public_clients == []
    assert SHAREPOINT_ORIGIN + "/.default" in edge.confidential.scopes and edge.session.token_posts == []
    assert sharepoint_admin.gets == [(SHAREPOINT_ORIGIN + "/_api/SPO.Tenant", f"Bearer certificate:{SHAREPOINT_ORIGIN}/.default")]


def test_secret_run_requests_no_sharepoint_token_and_sends_nothing(edge, sharepoint_admin, tmp_path) -> None:  # noqa: ANN001
    assert _run_sharepoint_admin(tmp_path, "--client-id", "constructed-app", "--client-secret", "constructed-secret") == 0
    assert edge.msal.interactive_count == 0
    assert not any("sharepoint" in scope for scope in edge.session.token_posts)
    assert sharepoint_admin.gets == []
