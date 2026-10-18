from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

import pytest


@pytest.fixture
def module(monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/exercise-free-directory.py"
    spec = importlib.util.spec_from_file_location("free_directory_exercise", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.seed, "access_token", lambda *_: pytest.fail("unexpected authentication"))
    return module


def source(module):
    plan = module.seed.fixtures("auditex-lab-test", "fixture.onmicrosoft.com")
    created = [{"fixture": name, "kind": item["kind"], "id": str(UUID(int=index + 1)),
                **({"appId": str(UUID(int=index + 100))} if item["kind"] == "applications" else {})}
               for index, (name, item) in enumerate(plan.items())]
    return {"tenantId": str(UUID(int=9999)), "domain": "fixture.onmicrosoft.com", "prefix": "auditex-lab-test",
            "fixtures": plan, "created": created, "state": "complete", "complete": True}


class Response:
    def __init__(self, body=None, status=200):
        self.body, self.status_code = body, status

    def json(self):
        return self.body

    def close(self):
        pass


class Session:
    def __init__(self, src, module):
        self.source, self.module = src, module
        self.objects = {row["fixture"]: row for row in src["created"]}
        self.by_id = {row["id"]: name for name, row in self.objects.items()}
        self.links = {key: set(value) for key, value in module.states()[0].items()}
        self.calls = []
        self.fail_write = False
        self.licensed = False

    def request(self, method, url, **kwargs):
        assert urlsplit(url).netloc == "graph.microsoft.com" and kwargs["allow_redirects"] is False
        self.calls.append((method, url))
        parts = urlsplit(url).path.split("/")[2:]
        if parts == ["organization"]:
            return Response({"value": [{"id": self.source["tenantId"]}]})
        kind, obj_id = parts[:2]
        name = self.by_id[obj_id]
        if len(parts) == 2:
            value = {"id": obj_id, "displayName": self.source["fixtures"][name]["displayName"]}
            if kind == "users":
                value.update(accountEnabled=False, assignedLicenses=[])
            elif kind == "groups":
                value.update(groupTypes=[], securityEnabled=True, mailEnabled=False, assignedLicenses=[{}] if self.licensed else [])
            elif kind == "applications":
                value.update(appId=self.objects[name]["appId"], signInAudience="AzureADMyOrg", requiredResourceAccess=[], passwordCredentials=[], keyCredentials=[])
            else:
                value.update(accountEnabled=False, appId=self.objects[name.replace("sp-", "app-")]["appId"])
            return Response(value)
        link = name + "/" + parts[2]
        if method == "GET":
            return Response({"value": [{"id": self.objects[target]["id"]} for target in sorted(self.links[link])]})
        if self.fail_write:
            return Response({"error": "private remote message"}, 503)
        assert parts[-1] == "$ref"
        if method == "POST":
            target = kwargs["json"]["@odata.id"].rsplit("/", 1)[1]
            self.links[link].add(self.by_id[target])
        else:
            assert method == "DELETE"
            self.links[link].remove(self.by_id[parts[-2]])
        return Response(status=204)

    def close(self):
        pass


def test_apply_and_restore_exact_lab_edges(module, tmp_path):
    src = source(module)
    session = Session(src, module)
    change = module.Exercise(src, tmp_path / "change", "apply", session)
    change.token = "test-token"
    change.execute()
    assert change.data["complete"] and session.links == module.states()[1]
    assert len(change.data["operations"]) == 4
    restore = module.Exercise(src, tmp_path / "restore", "restore", session)
    restore.token = "test-token"
    restore.execute()
    assert restore.data["complete"] and session.links == module.states()[0]
    assert len(restore.data["operations"]) == 4
    for method, url in session.calls:
        if method != "GET":
            assert url.endswith("/$ref") and ("/owners/" in url or "/members/" in url)
    assert "test-token" not in change.path.read_text() + restore.path.read_text()


def test_no_write_before_preflight_and_no_object_deletion(module, tmp_path):
    src = source(module)
    session = Session(src, module)
    change = module.Exercise(src, tmp_path / "change", "apply", session)
    with pytest.raises(module.ScenarioError, match="write_not_allowed"):
        change.request("DELETE", change.object_path("group-empty"))
    assert session.calls == []
    change.preflight()
    before = len(session.calls)
    with pytest.raises(module.ScenarioError, match="write_not_allowed"):
        change.request("DELETE", change.object_path("group-nested-inner") + "/members/" + change.objects["user-03"]["id"])
    assert len(session.calls) == before


def test_preflight_licensed_fixture_stops_before_mutation(module, tmp_path):
    src = source(module)
    session = Session(src, module)
    session.licensed = True
    change = module.Exercise(src, tmp_path / "change", "apply", session)
    with pytest.raises(module.ScenarioError, match="unlicensed_fixture_required"):
        change.execute()
    assert all(method == "GET" for method, _ in session.calls)


def test_write_failure_is_not_retried_and_restore_handles_known_partial_state(module, tmp_path):
    src = source(module)
    session = Session(src, module)
    session.fail_write = True
    change = module.Exercise(src, tmp_path / "change", "apply", session)
    with pytest.raises(module.ScenarioError, match="request_failed_review_manifest"):
        change.execute()
    assert sum(method != "GET" for method, _ in session.calls) == 1
    assert change.data["requests"][-1]["outcome"] == "outcome_unknown"
    assert "private remote message" not in change.path.read_text()
    session.fail_write = False
    session.links["app-owned/owners"].add("user-02")
    restore = module.Exercise(src, tmp_path / "restore", "restore", session)
    restore.execute()
    assert session.links == module.states()[0]
