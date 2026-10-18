#!/usr/bin/env python3
"""Apply or restore fixed ownership/membership scenarios on an existing free lab."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

import requests


GRAPH = "https://graph.microsoft.com/v1.0"
SOURCE = Path(__file__).with_name("seed-free-directory.py")
spec = importlib.util.spec_from_file_location("free_directory_seed", SOURCE)
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)


class ScenarioError(Exception):
    pass


def load_seed(path: Path) -> dict:
    value = json.loads(path.read_text())
    if value.get("complete") is not True or value.get("state") != "complete":
        raise ScenarioError("completed_seed_required")
    seed.tenant_argument(value["tenantId"])
    seed.prefix_argument(value["prefix"])
    seed.domain_argument(value["domain"])
    expected = seed.fixtures(value["prefix"], value["domain"])
    created = value.get("created", [])
    if len(created) != len(expected) or {obj.get("fixture") for obj in created} != set(expected):
        raise ScenarioError("invalid_fixture_inventory")
    ids = set()
    for obj in created:
        if obj["kind"] != expected[obj["fixture"]]["kind"] or seed.uuid_value(obj["id"]) in ids:
            raise ScenarioError("invalid_fixture_inventory")
        ids.add(obj["id"])
    if value.get("fixtures") != expected:
        raise ScenarioError("invalid_fixture_plan")
    return value


def states() -> tuple[dict, dict]:
    before = {"app-owned/owners": {"user-01"}, "group-nested-inner/members": {"user-03", "user-04"}}
    after = {"app-owned/owners": {"user-02"}, "group-nested-inner/members": {"user-02", "user-04"}}
    return before, after


class Exercise:
    def __init__(self, source: dict, output: Path, action: str, session=None):
        output.mkdir(mode=0o700)
        self.path = output / "manifest.json"
        self.source, self.action = source, action
        self.objects = {obj["fixture"]: obj for obj in source["created"]}
        self.by_id = {obj["id"]: name for name, obj in self.objects.items()}
        self.session = session if session is not None else requests.Session()
        self.session.trust_env = False
        self.token = ""
        self.ready = False
        self.data = {"schemaVersion": 1, "tenantId": source["tenantId"], "prefix": source["prefix"],
                     "action": action, "state": "planned", "complete": False, "requests": [],
                     "before": {}, "after": {}, "operations": []}
        self.save()

    def save(self):
        target = self.path.with_suffix(".tmp")
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(self.data, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(target, self.path)

    def object_path(self, name):
        obj = self.objects[name]
        return f"/{obj['kind']}/{obj['id']}"

    def allowed_operations(self):
        before, after = states()
        allowed = set()
        for link in before:
            parent, relation = link.split("/")
            for target in before[link] | after[link]:
                path = self.object_path(parent) + "/" + relation
                allowed.add(("POST", path + "/$ref", self.objects[target]["id"]))
                allowed.add(("DELETE", path + "/" + self.objects[target]["id"] + "/$ref", None))
        return allowed

    def request(self, method, path, *, target=None, select=None):
        if method == "GET":
            readable = {"/organization", *(self.object_path(name) for name in self.objects)}
            readable.update(self.object_path(link.split("/")[0]) + "/" + link.split("/")[1] for link in states()[0])
            if path not in readable:
                raise ScenarioError("read_not_allowed")
        elif not self.ready or (method, path, target) not in self.allowed_operations():
            raise ScenarioError("write_not_allowed")
        row = {"method": method, "path": path, "status": None, "outcome": "pending"}
        self.data["requests"].append(row)
        self.save()
        try:
            response = self.session.request(method, GRAPH + path,
                                            headers={"Authorization": "Bearer " + self.token},
                                            params={"$select": select} if select else None,
                                            json={"@odata.id": GRAPH + "/directoryObjects/" + target} if target else None,
                                            timeout=60, allow_redirects=False)
            try:
                row["status"] = response.status_code
                if response.status_code != (200 if method == "GET" else 204):
                    raise ScenarioError("unexpected_http_status")
                body = response.json() if method == "GET" else {}
                if not isinstance(body, dict) or body.get("@odata.nextLink"):
                    raise ScenarioError("unexpected_or_incomplete_response")
                row["outcome"] = "succeeded"
                return body
            finally:
                response.close()
        except Exception:
            row["outcome"] = "failed" if method == "GET" else "outcome_unknown"
            self.ready = False
            raise ScenarioError("request_failed_review_manifest") from None
        finally:
            self.save()

    def relationships(self):
        result = {}
        for link in states()[0]:
            parent, relation = link.split("/")
            values = self.request("GET", self.object_path(parent) + "/" + relation, select="id").get("value")
            if not isinstance(values, list) or any(not isinstance(value, dict) or value.get("id") not in self.by_id for value in values):
                raise ScenarioError("unexpected_relationship_member")
            aliases = {self.by_id[value["id"]] for value in values}
            if len(values) != len(aliases):
                raise ScenarioError("duplicate_relationship_member")
            result[link] = aliases
        return result

    def preflight(self):
        org = self.request("GET", "/organization", select="id").get("value", [])
        if len(org) != 1 or org[0].get("id") != self.source["tenantId"]:
            raise ScenarioError("tenant_mismatch")
        for name, obj in self.objects.items():
            extra = {"users": "accountEnabled,assignedLicenses", "groups": "groupTypes,assignedLicenses,securityEnabled,mailEnabled",
                     "applications": "appId,signInAudience,requiredResourceAccess,passwordCredentials,keyCredentials",
                     "servicePrincipals": "appId,accountEnabled"}[obj["kind"]]
            row = self.request("GET", self.object_path(name), select="id,displayName," + extra)
            if row.get("id") != obj["id"] or row.get("displayName") != self.source["fixtures"][name]["displayName"]:
                raise ScenarioError("fixture_identity_mismatch")
            if obj["kind"] in {"users", "servicePrincipals"} and row.get("accountEnabled") is not False:
                raise ScenarioError("disabled_fixture_required")
            if obj["kind"] in {"users", "groups"} and row.get("assignedLicenses") != []:
                raise ScenarioError("unlicensed_fixture_required")
            if obj["kind"] == "groups" and not (row.get("groupTypes") == [] and row.get("securityEnabled") is True and row.get("mailEnabled") is False):
                raise ScenarioError("assigned_security_group_required")
            if obj["kind"] == "applications" and not (row.get("appId") == obj["appId"] and row.get("signInAudience") == "AzureADMyOrg" and all(row.get(key) == [] for key in ("requiredResourceAccess", "passwordCredentials", "keyCredentials"))):
                raise ScenarioError("empty_single_tenant_app_required")
            if obj["kind"] == "servicePrincipals" and row.get("appId") != self.objects[name.replace("sp-", "app-", 1)]["appId"]:
                raise ScenarioError("fixture_app_identity_mismatch")
        current = self.relationships()
        before, after = states()
        if self.action == "apply" and current != before:
            raise ScenarioError("baseline_relationships_required")
        if self.action == "restore" and any(not current[key] <= before[key] | after[key] for key in before):
            raise ScenarioError("unexpected_relationship_state")
        self.data["before"] = {key: sorted(value) for key, value in current.items()}
        self.ready = True
        return current

    def execute(self):
        self.data["state"] = "preflight"
        self.save()
        current = self.preflight()
        desired = states()[1 if self.action == "apply" else 0]
        self.data["state"] = "changing"
        for link, expected in desired.items():
            parent, relation = link.split("/")
            path = self.object_path(parent) + "/" + relation
            for target in sorted(expected - current[link]):
                self.data["operations"].append({"operation": "add", "link": link, "target": target})
                self.request("POST", path + "/$ref", target=self.objects[target]["id"])
            for target in sorted(current[link] - expected):
                self.data["operations"].append({"operation": "remove", "link": link, "target": target})
                self.request("DELETE", path + "/" + self.objects[target]["id"] + "/$ref")
        observed = self.relationships()
        if observed != desired:
            raise ScenarioError("post_change_verification_failed")
        self.ready = False
        self.data.update(state="complete", complete=True, after={key: sorted(value) for key, value in observed.items()})
        self.save()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-manifest", type=Path, required=True)
    parser.add_argument("--action", choices=("apply", "restore"), required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    exercise = None
    try:
        source = load_seed(args.seed_manifest)
        exercise = Exercise(source, args.output_dir, args.action)
        if args.execute:
            exercise.token = seed.access_token(source["tenantId"])
            exercise.execute()
        print(json.dumps({"state": exercise.data["state"], "manifest": str(exercise.path), "action": args.action}))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        code = str(error) if isinstance(error, ScenarioError) else "local_or_interrupted_failure"
        if exercise:
            exercise.data.update(state="partial" if any(row["method"] != "GET" for row in exercise.data["requests"]) else "failed", error=code)
            exercise.save()
        print("Scenario stopped: " + code, file=sys.stderr)
        return 1
    finally:
        if exercise:
            exercise.token = ""
            exercise.session.close()


if __name__ == "__main__":
    raise SystemExit(main())
