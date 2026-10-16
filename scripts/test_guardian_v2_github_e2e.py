#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

from guardian_v2_github_e2e import (
    MergeMode,
    RealMergeEvidence,
    RepositoryCapability,
    assert_no_workstream_collision,
    assert_production_equivalent,
    choose_merge_mode,
    parse_ruleset,
    validate_isolated_repository,
    verify_real_merge_evidence,
)
from guardian_v2_policy import GuardianV2Error

ROOT = Path(__file__).resolve().parents[1]
RULESET = json.loads((ROOT / "test/fixtures/guardian-v2/jalo-main-ruleset-23492977.json").read_text())
CAPABILITY = json.loads((ROOT / "test/fixtures/guardian-v2/github-capability-snapshot-20261015.json").read_text())


def ok(name: str, condition: bool) -> None:
    if not condition:
        raise AssertionError(name)
    print(name + " PASS")


def block(name: str, fn, contains: str) -> None:
    try:
        fn()
    except GuardianV2Error as exc:
        if contains not in str(exc):
            raise AssertionError(f"{name}: {exc}") from exc
        print(name + " PASS -> BLOCK")
        return
    raise AssertionError(name + ": expected block")


production = parse_ruleset(RULESET)
ok("production ruleset active", production.enforcement == "active")
ok(
    "production required checks exact",
    set(production.required_checks) == {"guardian-pr-gate", "quality", "gitleaks"},
)
ok("production ruleset strict", production.strict_required_checks)
ok("production thread resolution", production.required_review_thread_resolution)
ok("production ruleset zero bypass", production.bypass_actor_count == 0)

personal_private = RepositoryCapability(
    repository="pawelzaurski/jalo-guardian-v2-e2e",
    owner_type=CAPABILITY["owner_type"],
    visibility=CAPABILITY["visibility"],
    enterprise_cloud_org=CAPABILITY["enterprise_cloud_org"],
    isolated_repo=True,
    production_credentials_present=False,
)
ok(
    "personal private repo uses serialized merge fallback",
    choose_merge_mode(personal_private) is MergeMode.SERIALIZED_PROTECTED_MERGE,
)

org_public = RepositoryCapability(
    repository="example-org/guardian-v2-e2e",
    owner_type="Organization",
    visibility="public",
    enterprise_cloud_org=False,
    isolated_repo=True,
    production_credentials_present=False,
)
ok("public org may use merge queue", choose_merge_mode(org_public) is MergeMode.MERGE_QUEUE)

private_enterprise = RepositoryCapability(
    repository="example-org/guardian-v2-e2e",
    owner_type="Organization",
    visibility="private",
    enterprise_cloud_org=True,
    isolated_repo=True,
    production_credentials_present=False,
)
ok("private enterprise org may use merge queue", choose_merge_mode(private_enterprise) is MergeMode.MERGE_QUEUE)

block(
    "production JALO cannot be E2E target",
    lambda: validate_isolated_repository(RepositoryCapability(
        repository="pawelzaurski/jalo",
        owner_type="User",
        visibility="private",
        enterprise_cloud_org=False,
        isolated_repo=True,
        production_credentials_present=False,
    )),
    "must not be",
)

block(
    "non-isolated repo rejected",
    lambda: validate_isolated_repository(RepositoryCapability(
        repository="pawelzaurski/random-repo",
        owner_type="User",
        visibility="private",
        enterprise_cloud_org=False,
        isolated_repo=False,
        production_credentials_present=False,
    )),
    "explicitly isolated",
)

block(
    "production credentials forbidden in E2E",
    lambda: validate_isolated_repository(RepositoryCapability(
        repository="pawelzaurski/jalo-guardian-v2-e2e",
        owner_type="User",
        visibility="private",
        enterprise_cloud_org=False,
        isolated_repo=True,
        production_credentials_present=True,
    )),
    "production credentials",
)

candidate = parse_ruleset(RULESET)
assert_production_equivalent(candidate, production)
ok("production-equivalent ruleset accepted", True)

weakened = json.loads(json.dumps(RULESET))
for rule in weakened["rules"]:
    if rule["type"] == "required_status_checks":
        rule["parameters"]["required_status_checks"] = [
            {"context": "quality", "integration_id": 15368},
            {"context": "gitleaks", "integration_id": 15368},
        ]
block(
    "missing Guardian required check rejected",
    lambda: assert_production_equivalent(parse_ruleset(weakened), production),
    "required checks differ",
)

bypass = json.loads(json.dumps(RULESET))
bypass["bypass_actors"] = [{"actor_id": 1, "actor_type": "RepositoryRole"}]
block(
    "ruleset bypass rejected",
    lambda: assert_production_equivalent(parse_ruleset(bypass), production),
    "bypass",
)

good = RealMergeEvidence(
    repository="pawelzaurski/jalo-guardian-v2-e2e",
    pr=7,
    head_sha="a" * 40,
    base_sha="b" * 40,
    merge_sha="c" * 40,
    pr_checks=(
        ("guardian-pr-gate", "success"),
        ("quality", "success"),
        ("gitleaks", "success"),
    ),
    post_merge_event="push",
    post_merge_branch="main",
    post_merge_head_sha="c" * 40,
    post_merge_checks=(
        ("guardian-pr-gate", "success"),
        ("quality", "success"),
        ("gitleaks", "success"),
    ),
)
verify_real_merge_evidence(
    good,
    capability=personal_private,
    candidate_ruleset=candidate,
    production_ruleset=production,
)
ok("synthetic complete real-merge evidence shape accepted", True)

block(
    "PR-only post-merge evidence rejected",
    lambda: verify_real_merge_evidence(
        RealMergeEvidence(**{**good.__dict__, "post_merge_event": "pull_request"}),
        capability=personal_private,
        candidate_ruleset=candidate,
        production_ruleset=production,
    ),
    "real push",
)

block(
    "stale merge SHA rejected",
    lambda: verify_real_merge_evidence(
        RealMergeEvidence(**{**good.__dict__, "post_merge_head_sha": "d" * 40}),
        capability=personal_private,
        candidate_ruleset=candidate,
        production_ruleset=production,
    ),
    "exact merge SHA",
)

block(
    "failed required post-merge check rejected",
    lambda: verify_real_merge_evidence(
        RealMergeEvidence(**{
            **good.__dict__,
            "post_merge_checks": (
                ("guardian-pr-gate", "success"),
                ("quality", "failure"),
                ("gitleaks", "success"),
            ),
        }),
        capability=personal_private,
        candidate_ruleset=candidate,
        production_ruleset=production,
    ),
    "failed",
)

assert_no_workstream_collision(
    [{"workstream": "JALO_GUARDIAN_2", "scope_digest": "scope-a"}],
    candidate_workstream="JALO_GUARDIAN_2",
    candidate_scope_digest="scope-a",
)
ok("same workstream same scope non-conflict", True)

block(
    "same workstream conflicting scope rejected",
    lambda: assert_no_workstream_collision(
        [{"workstream": "JALO_GUARDIAN_2", "scope_digest": "scope-a"}],
        candidate_workstream="JALO_GUARDIAN_2",
        candidate_scope_digest="scope-b",
    ),
    "conflicting scope",
)

print(
    "JALO Guardian 2.0 V2-04 harness PASS: production ruleset parity + merge queue "
    "capability fallback + isolated credential boundary + real-merge evidence contract + collision fail-closed"
)
