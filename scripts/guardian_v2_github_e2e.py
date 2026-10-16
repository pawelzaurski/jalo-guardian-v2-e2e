#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from guardian_v2_policy import GuardianV2Error

REQUIRED_CHECKS = ("guardian-pr-gate", "quality", "gitleaks")
PROTECTED_PRODUCTION_REPOS = {
    "pawelzaurski/jalo",
    "pawelzaurski/jalo-doc",
    "pawelzaurski/JCOS",
    "pawelzaurski/ksaaf",
}


class MergeMode(str, Enum):
    MERGE_QUEUE = "MERGE_QUEUE"
    SERIALIZED_PROTECTED_MERGE = "SERIALIZED_PROTECTED_MERGE"


@dataclass(frozen=True)
class RepositoryCapability:
    repository: str
    owner_type: str
    visibility: str
    enterprise_cloud_org: bool
    isolated_repo: bool
    production_credentials_present: bool


@dataclass(frozen=True)
class RulesetSnapshot:
    ruleset_id: int
    enforcement: str
    default_branch_only: bool
    required_checks: tuple[str, ...]
    strict_required_checks: bool
    required_review_thread_resolution: bool
    bypass_actor_count: int


@dataclass(frozen=True)
class RealMergeEvidence:
    repository: str
    pr: int
    head_sha: str
    base_sha: str
    merge_sha: str
    pr_checks: tuple[tuple[str, str], ...]
    post_merge_event: str
    post_merge_branch: str
    post_merge_head_sha: str
    post_merge_checks: tuple[tuple[str, str], ...]


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GuardianV2Error(f"{name} must be non-empty string")
    return value.strip()


def choose_merge_mode(cap: RepositoryCapability) -> MergeMode:
    owner_type = _text(cap.owner_type, "owner_type")
    visibility = _text(cap.visibility, "visibility")
    queue_eligible = owner_type == "Organization" and (
        visibility == "public" or (visibility == "private" and cap.enterprise_cloud_org)
    )
    return MergeMode.MERGE_QUEUE if queue_eligible else MergeMode.SERIALIZED_PROTECTED_MERGE


def validate_isolated_repository(cap: RepositoryCapability) -> None:
    repo = _text(cap.repository, "repository")
    if repo in PROTECTED_PRODUCTION_REPOS:
        raise GuardianV2Error("V2-04 E2E repository must not be a production/project repository")
    if not cap.isolated_repo:
        raise GuardianV2Error("V2-04 requires an explicitly isolated GitHub repository")
    if cap.production_credentials_present:
        raise GuardianV2Error("isolated V2-04 repository must not contain production credentials")


def parse_ruleset(raw: Mapping[str, Any]) -> RulesetSnapshot:
    if raw.get("enforcement") != "active":
        raise GuardianV2Error("ruleset must be active")
    conditions = raw.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    include = ref_name.get("include") if isinstance(ref_name, dict) else None
    default_only = include == ["~DEFAULT_BRANCH"]
    if not default_only:
        raise GuardianV2Error("ruleset must target the default branch")
    rules = raw.get("rules")
    if not isinstance(rules, list):
        raise GuardianV2Error("ruleset rules missing")
    checks = None
    strict = False
    threads = False
    has_pr_rule = False
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if rule.get("type") == "required_status_checks":
            params = rule.get("parameters") or {}
            strict = params.get("strict_required_status_checks_policy") is True
            entries = params.get("required_status_checks") or []
            checks = tuple(sorted(
                item.get("context") for item in entries
                if isinstance(item, dict) and isinstance(item.get("context"), str)
            ))
        if rule.get("type") == "pull_request":
            has_pr_rule = True
            params = rule.get("parameters") or {}
            threads = params.get("required_review_thread_resolution") is True
    if checks is None:
        raise GuardianV2Error("ruleset required status checks missing")
    if not has_pr_rule:
        raise GuardianV2Error("ruleset pull request protection missing")
    bypass = raw.get("bypass_actors") or []
    return RulesetSnapshot(
        ruleset_id=int(raw.get("id")),
        enforcement="active",
        default_branch_only=True,
        required_checks=checks,
        strict_required_checks=strict,
        required_review_thread_resolution=threads,
        bypass_actor_count=len(bypass),
    )


def assert_production_equivalent(candidate: RulesetSnapshot, production: RulesetSnapshot) -> None:
    if candidate.enforcement != "active":
        raise GuardianV2Error("candidate ruleset not active")
    if not candidate.default_branch_only:
        raise GuardianV2Error("candidate ruleset does not protect default branch")
    if not candidate.strict_required_checks:
        raise GuardianV2Error("candidate ruleset must require up-to-date checks")
    if not candidate.required_review_thread_resolution:
        raise GuardianV2Error("candidate ruleset must require thread resolution")
    if candidate.bypass_actor_count != 0:
        raise GuardianV2Error("candidate ruleset must not define bypass actors")
    if set(candidate.required_checks) != set(production.required_checks):
        raise GuardianV2Error("candidate required checks differ from production")


def _assert_checks(checks: Sequence[tuple[str, str]], name: str) -> None:
    seen: set[str] = set()
    for check, conclusion in checks:
        check = _text(check, f"{name}.check")
        conclusion = _text(conclusion, f"{name}.{check}.conclusion")
        if check in seen:
            raise GuardianV2Error(f"duplicate {name} check: {check}")
        seen.add(check)
        if conclusion != "success":
            raise GuardianV2Error(f"{name} check failed: {check}={conclusion}")
    missing = set(REQUIRED_CHECKS) - seen
    if missing:
        raise GuardianV2Error(f"{name} missing required checks: {', '.join(sorted(missing))}")


def verify_real_merge_evidence(
    evidence: RealMergeEvidence,
    *,
    capability: RepositoryCapability,
    candidate_ruleset: RulesetSnapshot,
    production_ruleset: RulesetSnapshot,
) -> None:
    validate_isolated_repository(capability)
    if evidence.repository != capability.repository:
        raise GuardianV2Error("merge evidence repository differs from isolated capability")
    if evidence.pr < 1:
        raise GuardianV2Error("real E2E PR must be positive")
    for value, name in (
        (evidence.head_sha, "head_sha"),
        (evidence.base_sha, "base_sha"),
        (evidence.merge_sha, "merge_sha"),
        (evidence.post_merge_head_sha, "post_merge_head_sha"),
    ):
        value = _text(value, name)
        if len(value) != 40 or any(ch not in "0123456789abcdef" for ch in value):
            raise GuardianV2Error(f"{name} must be exact 40-char Git SHA")
    if evidence.head_sha == evidence.base_sha:
        raise GuardianV2Error("E2E HEAD and BASE must differ")
    assert_production_equivalent(candidate_ruleset, production_ruleset)
    _assert_checks(evidence.pr_checks, "pre-merge")
    if evidence.post_merge_event != "push":
        raise GuardianV2Error("post-merge E2E evidence must be a real push event")
    if evidence.post_merge_branch != "main":
        raise GuardianV2Error("post-merge E2E evidence must target main")
    if evidence.post_merge_head_sha != evidence.merge_sha:
        raise GuardianV2Error("post-merge E2E push is not exact merge SHA")
    _assert_checks(evidence.post_merge_checks, "post-merge")


def assert_no_workstream_collision(
    active: Sequence[Mapping[str, Any]],
    *,
    candidate_workstream: str,
    candidate_scope_digest: str,
) -> None:
    candidate_workstream = _text(candidate_workstream, "candidate_workstream")
    candidate_scope_digest = _text(candidate_scope_digest, "candidate_scope_digest")
    for item in active:
        if item.get("workstream") != candidate_workstream:
            continue
        other = _text(item.get("scope_digest"), "active.scope_digest")
        if other != candidate_scope_digest:
            raise GuardianV2Error("multiple active PRs for same workstream have conflicting scope")
