#!/usr/bin/env python3
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

import yaml
from yaml.nodes import MappingNode
from yaml.tokens import AliasToken, AnchorToken

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class GuardianV2Error(RuntimeError):
    pass


class ContractType(str, Enum):
    PRODUCT_READINESS_V1 = "PRODUCT_READINESS_V1"
    GUARDIAN_CONTROL_PLANE_V1 = "GUARDIAN_CONTROL_PLANE_V1"
    WORKSTREAM_AUTHORITY_V1 = "WORKSTREAM_AUTHORITY_V1"
    DELIVERY_EVIDENCE_V1 = "DELIVERY_EVIDENCE_V1"


class RiskProfile(str, Enum):
    R1_ROUTINE = "R1_ROUTINE"
    R2_SENSITIVE = "R2_SENSITIVE"
    R3_CONTROL_PLANE = "R3_CONTROL_PLANE"


class AiState(str, Enum):
    PASS = "PASS"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    NOT_REQUIRED = "NOT_REQUIRED"
    REVIEW_PENDING = "REVIEW_PENDING"
    CAPACITY_UNAVAILABLE = "CAPACITY_UNAVAILABLE"
    INVALID_ATTESTATION = "INVALID_ATTESTATION"


class HumanGate(str, Enum):
    NONE = "NONE"
    BOUNDED_AUTHORITY_VERIFIED = "BOUNDED_AUTHORITY_VERIFIED"
    INDEPENDENT_HUMAN_APPROVED = "INDEPENDENT_HUMAN_APPROVED"
    EXACT_PR_HEAD_TRANSITION_APPROVED = "EXACT_PR_HEAD_TRANSITION_APPROVED"


class DecisionStatus(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    WAITING_REQUIRED_CHECKS = "WAITING_REQUIRED_CHECKS"
    WAITING_AI_REVIEW = "WAITING_AI_REVIEW"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class TypedDocument:
    contract_type: ContractType
    contract_id: str
    source: str
    source_sha256: str
    data: Mapping[str, Any]


@dataclass(frozen=True)
class WorkstreamAuthority:
    workstream_id: str
    canonical_docs_sha: str
    canonical_manifest: str
    allowed_paths: tuple[str, ...]
    effects: Mapping[str, bool]
    mode: str
    source_sha256: str


@dataclass(frozen=True)
class DeliveryDecision:
    schema: str
    repository: str
    pr: int
    head_sha: str
    base_sha: str
    canonical_docs_sha: str
    policy_digest_sha256: str
    content_digest_sha256: str
    risk_profile: RiskProfile
    ai_state: AiState
    human_gate: HumanGate
    status: DecisionStatus
    reasons: tuple[str, ...]
    attempt_key_sha256: str
    decision_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "repository": self.repository,
            "pr": self.pr,
            "head_sha": self.head_sha,
            "base_sha": self.base_sha,
            "canonical_docs_sha": self.canonical_docs_sha,
            "policy_digest_sha256": self.policy_digest_sha256,
            "content_digest_sha256": self.content_digest_sha256,
            "risk_profile": self.risk_profile.value,
            "ai_state": self.ai_state.value,
            "human_gate": self.human_gate.value,
            "status": self.status.value,
            "reasons": list(self.reasons),
            "attempt_key_sha256": self.attempt_key_sha256,
            "decision_sha256": self.decision_sha256,
        }


class _UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_unique_mapping(loader: _UniqueKeySafeLoader, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key == "<<":
            raise GuardianV2Error("YAML merge keys are forbidden in Guardian v2 contracts")
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise GuardianV2Error("unhashable YAML mapping key is forbidden") from exc
        if duplicate:
            raise GuardianV2Error(f"duplicate YAML mapping key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _digest_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _canonical_digest(value: Any) -> str:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _strict_yaml(text: str) -> dict[str, Any]:
    if not isinstance(text, str) or not text.strip():
        raise GuardianV2Error("empty YAML document")
    try:
        for token in yaml.scan(text):
            if isinstance(token, (AliasToken, AnchorToken)):
                raise GuardianV2Error("YAML anchors and aliases are forbidden in Guardian v2 contracts")
        loaded = yaml.load(text, Loader=_UniqueKeySafeLoader)
    except GuardianV2Error:
        raise
    except yaml.YAMLError as exc:
        raise GuardianV2Error(f"invalid YAML: {exc}") from exc
    if not isinstance(loaded, dict):
        raise GuardianV2Error("Guardian v2 contract root must be a mapping")
    return loaded


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GuardianV2Error(f"{name} must be a mapping")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise GuardianV2Error(f"{name} must be a list")
    return value


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GuardianV2Error(f"{name} must be a non-empty string")
    return value.strip()


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GuardianV2Error(f"{name} must be an integer")
    return value


def _bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise GuardianV2Error(f"{name} must be boolean")
    return value


def _require_sha40(value: Any, name: str) -> str:
    text = _text(value, name)
    if not SHA40.fullmatch(text):
        raise GuardianV2Error(f"{name} must be a lowercase 40-char Git SHA")
    return text


def _require_sha256(value: Any, name: str) -> str:
    text = _text(value, name)
    if not SHA256.fullmatch(text):
        raise GuardianV2Error(f"{name} must be a lowercase 64-char SHA-256")
    return text


def _path(root: Mapping[str, Any], path: Sequence[str], name: str) -> Any:
    cur: Any = root
    for key in path:
        if not isinstance(cur, dict) or key not in cur:
            raise GuardianV2Error(f"missing {name}")
        cur = cur[key]
    return cur


def _known_keys(value: Mapping[str, Any], allowed: set[str], name: str) -> None:
    unknown = sorted(str(k) for k in value if k not in allowed)
    if unknown:
        raise GuardianV2Error(f"{name} contains unknown fields: {', '.join(unknown)}")


def _validate_m7_product(readiness: dict[str, Any]) -> None:
    if readiness.get("id") != "KSAAF_M7_RESULT_SOURCE_CATALOG_1_ENTITY_PARITY_READY_V1":
        return
    if readiness.get("status") != "READY_TO_IMPLEMENT_CODE_ONLY":
        raise GuardianV2Error("M7 product readiness status mismatch")
    if readiness.get("implementation_mode") != "B_CODE_ONLY_MIGRATION_CONTRACT":
        raise GuardianV2Error("M7 product implementation mode mismatch")
    current = _mapping(_path(readiness, ("manifest_sequence", "current"), "M7 manifest_sequence.current"), "M7 manifest_sequence.current")
    if current.get("ordinal") != 147 or current.get("source_entity") != "public.result_source_catalog" or current.get("decision") != "ARCHIVE_EXTERNAL":
        raise GuardianV2Error("M7 manifest sequence mismatch")
    source = _mapping(readiness.get("source_contract"), "M7 source_contract")
    if source.get("entities") != 1 or source.get("fields") != 40:
        raise GuardianV2Error("M7 source contract must be exactly 1 entity / 40 fields")
    target = _mapping(readiness.get("target"), "M7 target")
    if (
        target.get("provenance_command") != "migration.import_entity_provenance.v1"
        or target.get("payload_fields") != 4
        or target.get("executable_adapter") != "NONE"
        or target.get("archive_export") != "BLOCKED"
    ):
        raise GuardianV2Error("M7 target is not the accepted code-only provenance contract")
    payload = _mapping(readiness.get("payload_contract"), "M7 payload_contract")
    constants = _mapping(payload.get("constants"), "M7 payload_contract.constants")
    if constants.get("source_entity") != "public.result_source_catalog" or payload.get("field_count") != 4:
        raise GuardianV2Error("M7 payload contract mismatch")
    authorization = _mapping(readiness.get("authorization"), "M7 authorization")
    forbidden = {
        "live_source_payload_read_or_export",
        "archive_storage_write",
        "provider_or_source_file_access",
        "network_access",
        "catalog_discovery_or_update",
        "sync_review_or_import_execution",
        "result_or_competition_write",
        "tenant_binding",
        "permission_grant",
        "environment_configuration_write",
        "database_change",
        "target_execution_adapter",
        "tenant_activation",
    }
    for key in forbidden:
        if authorization.get(key) != "NO_GO":
            raise GuardianV2Error(f"M7 accepted NO_GO authority changed: {key}")


def _validate_product_readiness(root: dict[str, Any], source: str, source_digest: str) -> TypedDocument:
    if set(root) != {"readiness"}:
        raise GuardianV2Error("PRODUCT_READINESS_V1 historical adapter requires exactly one root key: readiness")
    readiness = _mapping(root["readiness"], "readiness")
    contract_id = _text(readiness.get("id"), "readiness.id")
    _text(readiness.get("status"), "readiness.status")
    _text(readiness.get("implementation_mode"), "readiness.implementation_mode")
    _validate_m7_product(readiness)
    return TypedDocument(
        ContractType.PRODUCT_READINESS_V1,
        contract_id,
        source,
        source_digest,
        root,
    )


def _validate_guardian_control_plane(root: dict[str, Any], source: str, source_digest: str) -> TypedDocument:
    if root.get("kind") != "READY_TO_IMPLEMENT":
        raise GuardianV2Error("GUARDIAN_CONTROL_PLANE_V1 kind must be READY_TO_IMPLEMENT")
    contract_id = _text(root.get("id"), "id")
    workstream = _mapping(root.get("workstream"), "workstream")
    _text(workstream.get("id"), "workstream.id")
    status = _text(root.get("status"), "status")
    if contract_id == "JALO_GUARDIAN_AUTONOMOUS_DELIVERY_READY_V1":
        if status != "PASS":
            raise GuardianV2Error("historical Guardian delivery readiness status must be PASS")
        scope = _mapping(root.get("scope"), "scope")
        paths = _list(scope.get("paths"), "scope.paths")
        if not paths or any(not isinstance(item, str) or not item for item in paths):
            raise GuardianV2Error("historical Guardian scope.paths must be non-empty strings")
        security = _mapping(root.get("security_contract"), "security_contract")
        if security.get("direct_push_main") != "forbidden" or security.get("branch_protection_bypass") != "forbidden":
            raise GuardianV2Error("historical Guardian control-plane branch protection contract mismatch")
        if security.get("post_merge_main_ci") != "required":
            raise GuardianV2Error("historical Guardian control-plane post-merge CI contract mismatch")
    return TypedDocument(
        ContractType.GUARDIAN_CONTROL_PLANE_V1,
        contract_id,
        source,
        source_digest,
        root,
    )


_AUTHORITY_KEYS = {
    "schema",
    "workstream_id",
    "canonical_docs_sha",
    "canonical_manifest",
    "allowed_paths",
    "effects",
    "mode",
}


def _validate_authority(root: dict[str, Any], source: str, source_digest: str) -> TypedDocument:
    _known_keys(root, _AUTHORITY_KEYS, "WORKSTREAM_AUTHORITY_V1")
    if root.get("schema") != ContractType.WORKSTREAM_AUTHORITY_V1.value:
        raise GuardianV2Error("authority schema mismatch")
    workstream_id = _text(root.get("workstream_id"), "workstream_id")
    _require_sha40(root.get("canonical_docs_sha"), "canonical_docs_sha")
    _text(root.get("canonical_manifest"), "canonical_manifest")
    paths = _list(root.get("allowed_paths"), "allowed_paths")
    if not paths or any(not isinstance(p, str) or not p.strip() for p in paths):
        raise GuardianV2Error("allowed_paths must contain non-empty path patterns")
    effects = _mapping(root.get("effects"), "effects")
    if not effects:
        raise GuardianV2Error("effects must be non-empty")
    unknown_effects = sorted(str(key) for key in effects if key not in _KNOWN_EFFECTS)
    if unknown_effects:
        raise GuardianV2Error("authority contains unknown effect keys: " + ", ".join(unknown_effects))
    for key, value in effects.items():
        _text(str(key), "effect key")
        _bool(value, f"effects.{key}")
    mode = _text(root.get("mode"), "mode")
    if mode not in {"BOUNDED_WORKSTREAM", "EXACT_TRANSITION"}:
        raise GuardianV2Error("authority mode unsupported")
    return TypedDocument(
        ContractType.WORKSTREAM_AUTHORITY_V1,
        workstream_id,
        source,
        source_digest,
        root,
    )


_EVIDENCE_KEYS = {
    "schema",
    "repository",
    "pr",
    "head_sha",
    "base_sha",
    "canonical_docs_sha",
    "policy_digest_sha256",
    "content_digest_sha256",
    "workstream_id",
    "required_checks",
}


def _validate_delivery_evidence(root: dict[str, Any], source: str, source_digest: str) -> TypedDocument:
    _known_keys(root, _EVIDENCE_KEYS, "DELIVERY_EVIDENCE_V1")
    if root.get("schema") != ContractType.DELIVERY_EVIDENCE_V1.value:
        raise GuardianV2Error("delivery evidence schema mismatch")
    repository = _text(root.get("repository"), "repository")
    if "/" not in repository:
        raise GuardianV2Error("repository must be owner/name")
    pr = _integer(root.get("pr"), "pr")
    if pr < 1:
        raise GuardianV2Error("pr must be positive")
    _require_sha40(root.get("head_sha"), "head_sha")
    _require_sha40(root.get("base_sha"), "base_sha")
    _require_sha40(root.get("canonical_docs_sha"), "canonical_docs_sha")
    _require_sha256(root.get("policy_digest_sha256"), "policy_digest_sha256")
    _require_sha256(root.get("content_digest_sha256"), "content_digest_sha256")
    _text(root.get("workstream_id"), "workstream_id")
    checks = _list(root.get("required_checks"), "required_checks")
    seen: set[str] = set()
    for item in checks:
        check = _mapping(item, "required_checks[]")
        _known_keys(check, {"name", "run_id", "conclusion"}, "required_checks[]")
        name = _text(check.get("name"), "required check name")
        if name in seen:
            raise GuardianV2Error(f"duplicate required check name: {name}")
        seen.add(name)
        if _integer(check.get("run_id"), "required check run_id") < 1:
            raise GuardianV2Error("required check run_id must be positive")
        if _text(check.get("conclusion"), "required check conclusion") not in {
            "success", "failure", "cancelled", "skipped", "pending", "in_progress"
        }:
            raise GuardianV2Error("unsupported required check conclusion")
    return TypedDocument(
        ContractType.DELIVERY_EVIDENCE_V1,
        f"{repository}#{pr}",
        source,
        source_digest,
        root,
    )


def parse_typed_document(text: str, source: str = "<memory>") -> TypedDocument:
    root = _strict_yaml(text)
    source_digest = _digest_text(text)
    explicit = root.get("schema")
    if explicit == ContractType.WORKSTREAM_AUTHORITY_V1.value:
        return _validate_authority(root, source, source_digest)
    if explicit == ContractType.DELIVERY_EVIDENCE_V1.value:
        return _validate_delivery_evidence(root, source, source_digest)
    if explicit is not None:
        raise GuardianV2Error(f"unsupported Guardian v2 schema: {explicit}")
    if "readiness" in root:
        return _validate_product_readiness(root, source, source_digest)
    if root.get("kind") == "READY_TO_IMPLEMENT":
        return _validate_guardian_control_plane(root, source, source_digest)
    raise GuardianV2Error("unknown or unversioned Guardian v2 contract")


def workstream_authority(document: TypedDocument) -> WorkstreamAuthority:
    if document.contract_type is not ContractType.WORKSTREAM_AUTHORITY_V1:
        raise GuardianV2Error("document is not WORKSTREAM_AUTHORITY_V1")
    data = document.data
    effects = _mapping(data["effects"], "effects")
    return WorkstreamAuthority(
        workstream_id=_text(data["workstream_id"], "workstream_id"),
        canonical_docs_sha=_require_sha40(data["canonical_docs_sha"], "canonical_docs_sha"),
        canonical_manifest=_text(data["canonical_manifest"], "canonical_manifest"),
        allowed_paths=tuple(_text(item, "allowed_paths[]") for item in _list(data["allowed_paths"], "allowed_paths")),
        effects={str(k): _bool(v, f"effects.{k}") for k, v in effects.items()},
        mode=_text(data["mode"], "mode"),
        source_sha256=document.source_sha256,
    )


_R3_PATHS = (
    ".github/",
    ".jalo/",
    "AGENTS.md",
    "scripts/guardian",
    "scripts/test_guardian",
    "specs/guardian/",
)

_R2_MARKERS = (
    "/auth",
    "auth/",
    "security",
    "permission",
    "rbac",
    "restricted-data",
    "restricted_data",
    "payment",
    "billing",
    "consent",
    "privacy",
)

_R3_EFFECTS = {
    "guardian_control_plane",
    "ruleset_mutation",
    "provider_secret_mutation",
    "secret_rotation",
    "deployment_trigger",
    "production_mutation",
    "provider_deploy",
    "environment_promotion",
}

_R2_EFFECTS = {
    "database_schema_additive",
    "existing_schema_semantics_change",
    "database_mutation",
    "source_payload_read",
    "source_write",
    "target_write",
    "runtime_content_copy",
    "archive_export",
    "external_archive_storage_write",
    "provider_read",
    "provider_verify",
    "provider_plan",
    "provider_write",
    "provider_delete",
    "source_file_access",
    "network_access",
    "catalog_discovery",
    "catalog_update",
    "sync_execution",
    "review_decision_execution",
    "import_execution",
    "result_or_competition_write",
    "canonical_tenant_binding",
    "permission_grant",
    "real_data_import",
    "tenant_activation",
    "target_execution_adapter",
}

_KNOWN_EFFECTS = _R3_EFFECTS | _R2_EFFECTS


def classify_risk(changed_paths: Sequence[str], effects: Mapping[str, bool]) -> RiskProfile:
    normalized = [str(path).strip() for path in changed_paths if str(path).strip()]
    if not normalized:
        raise GuardianV2Error("changed_paths must not be empty")
    unknown_effects = sorted(str(effect) for effect in effects if effect not in _KNOWN_EFFECTS)
    if unknown_effects:
        raise GuardianV2Error("unknown effect keys: " + ", ".join(unknown_effects))
    for effect, value in effects.items():
        _bool(value, f"effects.{effect}")
    if any(effects.get(name) is True for name in _R3_EFFECTS):
        return RiskProfile.R3_CONTROL_PLANE
    for path in normalized:
        lower = path.lower()
        if (
            lower.startswith(".github/")
            or lower.startswith(".jalo/")
            or path == "AGENTS.md"
            or lower.startswith("scripts/guardian")
            or lower.startswith("scripts/test_guardian")
            or lower.startswith("specs/guardian/")
        ):
            return RiskProfile.R3_CONTROL_PLANE
    if any(effects.get(name) is True for name in _R2_EFFECTS):
        return RiskProfile.R2_SENSITIVE
    for path in normalized:
        lower = path.lower()
        if lower.startswith("supabase/migrations/") or any(marker in lower for marker in _R2_MARKERS):
            return RiskProfile.R2_SENSITIVE
    routine_prefixes = ("src/", "test/", "tests/", "docs/", "public/")
    routine_exact = {"README.md", "CHANGELOG.md"}
    if all(path in routine_exact or path.lower().startswith(routine_prefixes) for path in normalized):
        return RiskProfile.R1_ROUTINE
    return RiskProfile.R3_CONTROL_PLANE


def assert_authority_scope(
    authority: WorkstreamAuthority,
    *,
    changed_paths: Sequence[str],
    effects: Mapping[str, bool],
) -> None:
    for path in changed_paths:
        if not any(fnmatch.fnmatchcase(path, pattern) for pattern in authority.allowed_paths):
            raise GuardianV2Error(f"path outside bounded authority: {path}")
    for effect, detected in effects.items():
        _bool(detected, f"effects.{effect}")
        if detected and authority.effects.get(effect) is not True:
            raise GuardianV2Error(f"effect exceeds bounded authority: {effect}")


def _checks_state(required_checks: Sequence[Mapping[str, Any]]) -> tuple[DecisionStatus | None, list[str]]:
    reasons: list[str] = []
    if not required_checks:
        return DecisionStatus.BLOCKED, ["required checks are missing"]
    names: set[str] = set()
    waiting = False
    for item in required_checks:
        name = _text(item.get("name"), "required check name")
        if name in names:
            return DecisionStatus.BLOCKED, [f"duplicate required check: {name}"]
        names.add(name)
        conclusion = _text(item.get("conclusion"), f"{name}.conclusion")
        if conclusion == "success":
            continue
        if conclusion in {"pending", "in_progress"}:
            waiting = True
            reasons.append(f"required check pending: {name}")
        else:
            return DecisionStatus.BLOCKED, [f"required check failed: {name}={conclusion}"]
    return (DecisionStatus.WAITING_REQUIRED_CHECKS if waiting else None), reasons


def evaluate_delivery(
    *,
    repository: str,
    pr: int,
    head_sha: str,
    base_sha: str,
    canonical_docs_sha: str,
    policy_digest_sha256: str,
    content_digest_sha256: str,
    changed_paths: Sequence[str],
    effects: Mapping[str, bool],
    required_checks: Sequence[Mapping[str, Any]],
    ai_state: AiState = AiState.NOT_REQUIRED,
    ai_required: bool = False,
    human_gate: HumanGate = HumanGate.NONE,
    authority: WorkstreamAuthority | None = None,
) -> DeliveryDecision:
    if "/" not in _text(repository, "repository"):
        raise GuardianV2Error("repository must be owner/name")
    if isinstance(pr, bool) or not isinstance(pr, int) or pr < 1:
        raise GuardianV2Error("pr must be a positive integer")
    head_sha = _require_sha40(head_sha, "head_sha")
    base_sha = _require_sha40(base_sha, "base_sha")
    canonical_docs_sha = _require_sha40(canonical_docs_sha, "canonical_docs_sha")
    policy_digest_sha256 = _require_sha256(policy_digest_sha256, "policy_digest_sha256")
    content_digest_sha256 = _require_sha256(content_digest_sha256, "content_digest_sha256")
    if head_sha == base_sha:
        raise GuardianV2Error("head_sha and base_sha must differ")
    risk = classify_risk(changed_paths, effects)

    if authority is not None:
        assert_authority_scope(authority, changed_paths=changed_paths, effects=effects)
        if authority.canonical_docs_sha != canonical_docs_sha:
            raise GuardianV2Error("authority canonical docs SHA does not match frozen delivery docs SHA")

    status, reasons = _checks_state(required_checks)
    if status is None:
        status = DecisionStatus.ELIGIBLE

    if status is DecisionStatus.ELIGIBLE:
        if ai_state in {AiState.REQUEST_CHANGES, AiState.INVALID_ATTESTATION}:
            status = DecisionStatus.BLOCKED
            reasons.append(f"AI review blocks delivery: {ai_state.value}")
        elif ai_required and ai_state is not AiState.PASS:
            status = DecisionStatus.WAITING_AI_REVIEW
            reasons.append(f"required AI review not satisfied: {ai_state.value}")

    if status is DecisionStatus.ELIGIBLE and human_gate is HumanGate.BOUNDED_AUTHORITY_VERIFIED and authority is None:
        status = DecisionStatus.BLOCKED
        reasons.append("bounded authority gate asserted without a verified authority contract")

    if status is DecisionStatus.ELIGIBLE:
        if risk is RiskProfile.R2_SENSITIVE and human_gate not in {
            HumanGate.BOUNDED_AUTHORITY_VERIFIED,
            HumanGate.INDEPENDENT_HUMAN_APPROVED,
            HumanGate.EXACT_PR_HEAD_TRANSITION_APPROVED,
        }:
            status = DecisionStatus.BLOCKED
            reasons.append("R2 requires verified bounded or Human Principal authority")
        if risk is RiskProfile.R3_CONTROL_PLANE and human_gate not in {
            HumanGate.INDEPENDENT_HUMAN_APPROVED,
            HumanGate.EXACT_PR_HEAD_TRANSITION_APPROVED,
        }:
            status = DecisionStatus.BLOCKED
            reasons.append("R3 requires independent human or exact transition approval")

    evidence_core = {
        "schema": "DELIVERY_DECISION_V2_01",
        "repository": repository,
        "pr": pr,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "canonical_docs_sha": canonical_docs_sha,
        "policy_digest_sha256": policy_digest_sha256,
        "content_digest_sha256": content_digest_sha256,
        "risk_profile": risk.value,
        "ai_state": ai_state.value,
        "ai_required": ai_required,
        "human_gate": human_gate.value,
        "required_checks": sorted(
            [{"name": str(item["name"]), "conclusion": str(item["conclusion"])} for item in required_checks],
            key=lambda x: x["name"],
        ),
        "authority_sha256": authority.source_sha256 if authority else None,
    }
    attempt_key = _canonical_digest({
        "repository": repository,
        "pr": pr,
        "head_sha": head_sha,
        "base_sha": base_sha,
        "canonical_docs_sha": canonical_docs_sha,
        "policy_digest_sha256": policy_digest_sha256,
        "content_digest_sha256": content_digest_sha256,
    })
    decision_material = {
        **evidence_core,
        "status": status.value,
        "reasons": reasons,
        "attempt_key_sha256": attempt_key,
    }
    decision_digest = _canonical_digest(decision_material)
    return DeliveryDecision(
        schema="DELIVERY_DECISION_V2_01",
        repository=repository,
        pr=pr,
        head_sha=head_sha,
        base_sha=base_sha,
        canonical_docs_sha=canonical_docs_sha,
        policy_digest_sha256=policy_digest_sha256,
        content_digest_sha256=content_digest_sha256,
        risk_profile=risk,
        ai_state=ai_state,
        human_gate=human_gate,
        status=status,
        reasons=tuple(reasons),
        attempt_key_sha256=attempt_key,
        decision_sha256=decision_digest,
    )
