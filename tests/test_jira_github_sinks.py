from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    from azure_tenant_audit.cli import run_offline

    rc = run_offline(
        REPO_ROOT / "examples" / "sample_audit_bundle" / "sample_result.json",
        tmp_path,
        "contoso",
        "ticket-test",
        auditor_profile="global-reader",
        plane="inventory",
    )
    assert rc == 0
    return tmp_path / "contoso-ticket-test"


def test_send_notification_jira_dry_run_returns_planned(run_dir: Path) -> None:
    from auditex.notify import send_notification

    result = send_notification(run_dir=str(run_dir), sink="jira", dry_run=True)
    assert result["status"] == "planned"
    assert result["sink"] == "jira"


def test_send_notification_github_dry_run_returns_planned(run_dir: Path) -> None:
    from auditex.notify import send_notification

    result = send_notification(run_dir=str(run_dir), sink="github", dry_run=True)
    assert result["status"] == "planned"
    assert result["sink"] == "github"


def test_send_notification_jira_blocks_without_env(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.notify import send_notification

    for var in ("AUDITEX_JIRA_BASE_URL", "AUDITEX_JIRA_PROJECT_KEY", "AUDITEX_JIRA_EMAIL", "AUDITEX_JIRA_API_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    result = send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)
    assert result["status"] == "blocked"
    assert "AUDITEX_JIRA_BASE_URL" in result["reason"]


def test_send_notification_github_blocks_without_env(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from auditex.notify import send_notification

    for var in ("AUDITEX_GITHUB_TOKEN", "AUDITEX_GITHUB_REPO"):
        monkeypatch.delenv(var, raising=False)
    result = send_notification(run_dir=str(run_dir), sink="github", dry_run=False)
    assert result["status"] == "blocked"
    assert "AUDITEX_GITHUB_TOKEN" in result["reason"] or "AUDITEX_GITHUB_REPO" in result["reason"]


class _FakeJiraSearchResponse:
    """Helper for tests: stub a Jira /search response with a list of issues."""

    def __init__(self, issues: list[dict[str, Any]] | None = None, status_code: int = 200) -> None:
        self.status_code = status_code
        self._issues = issues or []
        self.text = "fake"

    def json(self) -> dict[str, Any]:
        return {"issues": self._issues}


def _jira_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_JIRA_BASE_URL", "https://example.atlassian.net")
    monkeypatch.setenv("AUDITEX_JIRA_PROJECT_KEY", "AUDIT")
    monkeypatch.setenv("AUDITEX_JIRA_EMAIL", "bot@example.com")
    monkeypatch.setenv("AUDITEX_JIRA_API_TOKEN", "token-123")


def test_send_notification_jira_posts_issue(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    _jira_env(monkeypatch)
    captured: dict[str, Any] = {}

    class _FakePost:
        status_code = 201
        text = '{"key": "AUDIT-99"}'

        def json(self) -> dict[str, Any]:
            return {"key": "AUDIT-99"}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, auth: Any = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["auth"] = auth
        return _FakePost()

    def _fake_get(url: str, params: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, auth: Any = None, timeout: float | None = None):  # noqa: ANN001
        # Search returns no existing issues — exercise the create path.
        captured.setdefault("get_calls", []).append({"url": url, "params": params, "auth": auth})
        return _FakeJiraSearchResponse(issues=[])

    monkeypatch.setattr(notify_module.requests, "post", _fake_post)
    monkeypatch.setattr(notify_module.requests, "get", _fake_get)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)

    assert result["status"] == "sent"
    assert result["http_status"] == 201
    assert result["issue_key"] == "AUDIT-99"
    assert captured["url"].endswith("/rest/api/3/issue")
    assert captured["json"]["fields"]["project"]["key"] == "AUDIT"
    assert captured["auth"] == ("bot@example.com", "token-123")
    # Dedup label must be present on the created issue.
    labels = captured["json"]["fields"]["labels"]
    assert any(label.startswith("auditex-fp-") for label in labels)
    # Search call must have happened first with the expected JQL.
    assert captured["get_calls"], "search request was not issued before create"
    search_call = captured["get_calls"][0]
    assert search_call["url"].endswith("/rest/api/3/search")
    jql = search_call["params"]["jql"]
    assert 'project = "AUDIT"' in jql
    assert "auditex-fp-" in jql


def test_send_notification_jira_skips_create_when_existing_issue_found(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E1: a re-run against the same bundle must hit the dedup path."""
    import auditex.notify as notify_module

    _jira_env(monkeypatch)
    captured: dict[str, Any] = {}

    def _fake_get(url: str, params: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, auth: Any = None, timeout: float | None = None):  # noqa: ANN001
        captured.setdefault("get_calls", []).append({"url": url, "params": params})
        return _FakeJiraSearchResponse(issues=[{"key": "AUDIT-42", "fields": {"summary": "old"}}])

    def _fail_post(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("requests.post must not be called when dedup hits")

    monkeypatch.setattr(notify_module.requests, "get", _fake_get)
    monkeypatch.setattr(notify_module.requests, "post", _fail_post)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)

    assert result["status"] == "deduped"
    assert result["sink"] == "jira"
    assert result["issue_key"] == "AUDIT-42"
    assert result.get("fingerprint")
    assert captured["get_calls"], "search must have been issued"


def test_send_notification_jira_falls_through_when_search_errors(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-open: a Jira search outage must not silently drop the
    notification — the create path runs anyway."""
    import auditex.notify as notify_module

    _jira_env(monkeypatch)
    captured: dict[str, Any] = {}

    def _broken_get(*args: Any, **kwargs: Any) -> Any:
        raise notify_module.requests.ConnectionError("simulated outage")

    class _FakePost:
        status_code = 201
        text = '{"key": "AUDIT-101"}'

        def json(self) -> dict[str, Any]:
            return {"key": "AUDIT-101"}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, auth: Any = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        return _FakePost()

    monkeypatch.setattr(notify_module.requests, "get", _broken_get)
    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)

    assert result["status"] == "sent"
    assert result["issue_key"] == "AUDIT-101"


def test_send_notification_jira_fingerprint_is_stable_across_renders(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fingerprint must be byte-stable across two notify invocations
    against the same run-dir — otherwise dedup never fires."""
    import auditex.notify as notify_module

    _jira_env(monkeypatch)

    fingerprints: list[str] = []
    issue_counter = {"n": 0}

    def _fake_get(*args: Any, **kwargs: Any) -> Any:
        return _FakeJiraSearchResponse(issues=[])

    class _FakePost:
        def __init__(self) -> None:
            issue_counter["n"] += 1
            self.status_code = 201
            self.text = ""

        def json(self) -> dict[str, Any]:
            return {"key": f"AUDIT-{issue_counter['n']}"}

    def _fake_post(*args: Any, **kwargs: Any) -> Any:
        return _FakePost()

    monkeypatch.setattr(notify_module.requests, "get", _fake_get)
    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    for _ in range(2):
        result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)
        fingerprints.append(result["fingerprint"])

    assert fingerprints[0] == fingerprints[1]
    assert len(fingerprints[0]) == 16  # 16-char hex prefix


class _FakeGithubSearchResponse:
    """Helper for tests: stub a GitHub /search/issues response."""

    def __init__(self, items: list[dict[str, Any]] | None = None, status_code: int = 200) -> None:
        self.status_code = status_code
        self._items = items or []
        self.text = "fake"

    def json(self) -> dict[str, Any]:
        return {"items": self._items}


def _github_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDITEX_GITHUB_TOKEN", "ghp_token")
    monkeypatch.setenv("AUDITEX_GITHUB_REPO", "magrathean-uk/auditex")


def test_send_notification_github_posts_issue(run_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import auditex.notify as notify_module

    _github_env(monkeypatch)
    captured: dict[str, Any] = {}

    class _FakePost:
        status_code = 201
        text = '{"number": 42, "html_url": "https://github.com/x/y/issues/42"}'

        def json(self) -> dict[str, Any]:
            return {"number": 42, "html_url": "https://github.com/x/y/issues/42"}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _FakePost()

    def _fake_get(url: str, params: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        captured.setdefault("get_calls", []).append({"url": url, "params": params, "headers": headers})
        return _FakeGithubSearchResponse(items=[])

    monkeypatch.setattr(notify_module.requests, "post", _fake_post)
    monkeypatch.setattr(notify_module.requests, "get", _fake_get)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="github", dry_run=False)

    assert result["status"] == "sent"
    assert result["http_status"] == 201
    assert result["issue_number"] == 42
    assert captured["url"] == "https://api.github.com/repos/magrathean-uk/auditex/issues"
    title = captured["json"]["title"]
    assert "fp:" in title  # E2 dedup token embedded in title
    assert captured["headers"]["Authorization"] == "Bearer ghp_token"
    # Search must have run before create with the expected query syntax.
    assert captured["get_calls"], "search was not issued before create"
    search_query = captured["get_calls"][0]["params"]["q"]
    assert "repo:magrathean-uk/auditex" in search_query
    assert "is:issue" in search_query
    assert "fp:" in search_query


def test_send_notification_github_comments_when_existing_issue_found(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E2: a re-run against the same bundle must comment on the existing
    issue rather than create a second one."""
    import auditex.notify as notify_module

    _github_env(monkeypatch)
    captured: dict[str, Any] = {}

    def _fake_get(url: str, params: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        captured.setdefault("get_calls", []).append({"url": url, "params": params})
        return _FakeGithubSearchResponse(
            items=[{"number": 7, "html_url": "https://github.com/x/y/issues/7"}]
        )

    class _FakeCommentPost:
        status_code = 201
        text = '{"id": 999}'

        def json(self) -> dict[str, Any]:
            return {"id": 999}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        captured.setdefault("post_calls", []).append({"url": url, "json": json})
        return _FakeCommentPost()

    monkeypatch.setattr(notify_module.requests, "get", _fake_get)
    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="github", dry_run=False)

    assert result["status"] == "commented"
    assert result["issue_number"] == 7
    assert result["issue_url"] == "https://github.com/x/y/issues/7"
    assert result.get("fingerprint")
    # The single POST call must have hit the comments endpoint, NOT the
    # issues create endpoint.
    assert captured["post_calls"], "comment post was not issued"
    assert all("/comments" in call["url"] for call in captured["post_calls"])
    assert not any(call["url"].endswith("/issues") for call in captured["post_calls"])


def test_send_notification_github_falls_through_when_search_errors(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-open: a GitHub search outage must not silently drop the
    notification — the create path runs anyway."""
    import auditex.notify as notify_module

    _github_env(monkeypatch)
    captured: dict[str, Any] = {}

    def _broken_get(*args: Any, **kwargs: Any) -> Any:
        raise notify_module.requests.ConnectionError("simulated outage")

    class _FakePost:
        status_code = 201
        text = '{"number": 11, "html_url": "https://github.com/x/y/issues/11"}'

        def json(self) -> dict[str, Any]:
            return {"number": 11, "html_url": "https://github.com/x/y/issues/11"}

    def _fake_post(url: str, json: dict[str, Any] | None = None, headers: dict[str, Any] | None = None, timeout: float | None = None):  # noqa: ANN001
        captured["url"] = url
        return _FakePost()

    monkeypatch.setattr(notify_module.requests, "get", _broken_get)
    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    result = notify_module.send_notification(run_dir=str(run_dir), sink="github", dry_run=False)

    assert result["status"] == "sent"
    assert result["issue_number"] == 11


def test_send_notification_github_fingerprint_aligns_with_jira(
    run_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Jira and GitHub sinks must emit the same fingerprint for the
    same run_dir — operators correlating the two sinks rely on it."""
    import auditex.notify as notify_module

    _github_env(monkeypatch)
    _jira_env(monkeypatch)

    def _empty_search(*args: Any, **kwargs: Any) -> Any:
        # Both sinks search; both find nothing; both create.
        if "search/issues" in args[0]:  # GitHub
            return _FakeGithubSearchResponse(items=[])
        return _FakeJiraSearchResponse(issues=[])

    class _FakeCreate:
        status_code = 201
        text = '{"number": 1, "key": "AUDIT-1", "html_url": "https://example/1"}'

        def json(self) -> dict[str, Any]:
            return {"number": 1, "key": "AUDIT-1", "html_url": "https://example/1"}

    def _fake_post(*args: Any, **kwargs: Any) -> Any:
        return _FakeCreate()

    monkeypatch.setattr(notify_module.requests, "get", _empty_search)
    monkeypatch.setattr(notify_module.requests, "post", _fake_post)

    jira_result = notify_module.send_notification(run_dir=str(run_dir), sink="jira", dry_run=False)
    github_result = notify_module.send_notification(run_dir=str(run_dir), sink="github", dry_run=False)
    assert jira_result["fingerprint"] == github_result["fingerprint"]
