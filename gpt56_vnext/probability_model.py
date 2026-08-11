from __future__ import annotations

from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable

from .utils import canonical_json, softmax


SCHEMA_VERSION = 3
SCORING_VERSION = "trusted-fingerprint-v3"
MODELS = ("gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna")
SMOOTHING = 0.5
COMPLETION_RATIO = 0.90
FORMAL_THRESHOLDS = {
    "medium": {
        "gpt-5.6-sol": 0.70,
        "gpt-5.6-terra": 0.75,
        "gpt-5.6-luna": 0.90,
    },
    "high": {
        "gpt-5.6-sol": 0.95,
        "gpt-5.6-terra": 0.90,
        "gpt-5.6-luna": 0.90,
    },
}


def _safe_log(value: float) -> float:
    return math.log(max(float(value), 1e-300))


def _mean(values: Iterable[float]) -> float:
    items = list(values)
    return sum(items) / len(items) if items else 0.0


def _distribution(
    counts: dict[str, int],
    categories: tuple[str, ...],
    alpha: float = SMOOTHING,
) -> dict[str, float]:
    total = sum(max(0, int(counts.get(category, 0))) for category in categories)
    denominator = total + alpha * len(categories)
    if denominator <= 0:
        return {category: 1.0 / len(categories) for category in categories}
    return {
        category: (max(0, int(counts.get(category, 0))) + alpha) / denominator
        for category in categories
    }


def js_divergence(left: dict[str, float], right: dict[str, float]) -> float:
    categories = sorted(set(left) | set(right))
    if not categories:
        return 0.0
    middle = {
        category: 0.5 * (left.get(category, 0.0) + right.get(category, 0.0))
        for category in categories
    }

    def kl(source: dict[str, float]) -> float:
        return sum(
            probability * math.log2(probability / middle[category])
            for category, probability in source.items()
            if probability > 0 and middle[category] > 0
        )

    return 0.5 * kl(left) + 0.5 * kl(right)


def _pairwise_mean(distributions: list[dict[str, float]]) -> float:
    return _mean(
        js_divergence(distributions[left], distributions[right])
        for left in range(len(distributions))
        for right in range(left + 1, len(distributions))
    )


def _window_map(profile: dict[str, Any], model: str) -> dict[str, dict[str, Any]]:
    return {
        str(key): value
        for key, value in profile.get("models", {}).get(model, {}).get("windows", {}).items()
    }


def _cell_categories(profile: dict[str, Any]) -> tuple[str, ...]:
    categories = {
        str(category)
        for model in MODELS
        for window in _window_map(profile, model).values()
        for category in (window.get("counts") or {})
    }
    categories.update({"__OTHER__", "__INVALID_OUTPUT__"})
    return tuple(sorted(categories))


def _aggregate_windows(profile: dict[str, Any], model: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for window in _window_map(profile, model).values():
        counts.update({str(key): int(value) for key, value in (window.get("counts") or {}).items()})
    return counts


def fit_cell(profile: dict[str, Any]) -> dict[str, Any]:
    categories = _cell_categories(profile)
    model_counts = {model: dict(_aggregate_windows(profile, model)) for model in MODELS}
    model_distributions = {
        model: _distribution(model_counts[model], categories)
        for model in MODELS
    }
    between = _pairwise_mean([model_distributions[model] for model in MODELS])
    within_values: list[float] = []
    windows_by_model: dict[str, int] = {}
    for model in MODELS:
        windows = [
            _distribution(
                {str(key): int(value) for key, value in (window.get("counts") or {}).items()},
                categories,
            )
            for window in _window_map(profile, model).values()
        ]
        windows_by_model[model] = len(windows)
        if len(windows) >= 2:
            within_values.append(_pairwise_mean(windows))
    drift = _mean(within_values)
    weight = 0.0 if between <= 0 or between <= drift else min(1.0, (between - drift) / between)
    return {
        "categories": list(categories),
        "model_counts": model_counts,
        "model_distributions": model_distributions,
        "between_model_jsd": between,
        "within_model_jsd": drift,
        "weight": weight,
        "windows_by_model": windows_by_model,
        "time_stability_verified": all(count >= 2 for count in windows_by_model.values()),
    }


def _normalize_candidate_counts(counts: dict[str, int], categories: list[str]) -> dict[str, int]:
    allowed = set(categories)
    normalized: Counter[str] = Counter({category: 0 for category in categories})
    for raw_category, raw_count in counts.items():
        category = str(raw_category)
        normalized[category if category in allowed else "__OTHER__"] += int(raw_count)
    return dict(normalized)


def _cell_average_log_likelihood(
    counts: dict[str, int],
    distribution: dict[str, float],
    sample_count: int,
) -> float:
    if sample_count <= 0:
        return 0.0
    return sum(
        int(count) * _safe_log(distribution.get(category, 0.0))
        for category, count in counts.items()
    ) / sample_count


def _family_scores(cells: dict[str, dict[str, Any]]) -> tuple[dict[str, float], dict[str, Any]]:
    families: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for key, cell in cells.items():
        if int(cell.get("sample_count", 0)) > 0 and float(cell.get("weight", 0.0)) > 0:
            families[str(cell["probe_id"])].append((key, cell))
    total_scores = {model: 0.0 for model in MODELS}
    details: dict[str, Any] = {}
    for family, entries in sorted(families.items()):
        weight_sum = sum(float(cell["weight"]) for _key, cell in entries)
        if weight_sum <= 0:
            continue
        family_scores = {
            model: sum(
                float(cell["weight"]) * float(cell["average_log_likelihood"][model])
                for _key, cell in entries
            ) / weight_sum
            for model in MODELS
        }
        family_weight = min(1.0, max(float(cell["weight"]) for _key, cell in entries))
        for model in MODELS:
            total_scores[model] += family_weight * family_scores[model]
        details[family] = {
            "family_weight": family_weight,
            "profile_count": len(entries),
            "profile_keys": [key for key, _cell in entries],
            "profile_weight_sum": weight_sum,
            "model_contributions": family_scores,
        }
    return total_scores, details


def _runtime_signature(runtime_spec: dict[str, Any]) -> str:
    canonical = {
        "cells": {
            str(key): int(value)
            for key, value in sorted((runtime_spec.get("cells") or {}).items())
        },
        "contracts": {
            str(key): value
            for key, value in sorted((runtime_spec.get("contracts") or {}).items())
        },
    }
    return hashlib.sha256(canonical_json(canonical).encode("utf-8")).hexdigest()


def _expected_contract(
    key: str,
    probe_metadata: dict[str, Any],
) -> dict[str, Any] | None:
    probe_id, profile = key.split("|", 1)
    request_format, context_mode = profile.split("+", 1)
    metadata = probe_metadata.get(probe_id)
    if not metadata:
        return None
    return {
        "probe_id": probe_id,
        "profile": profile,
        "user_prompt_sha256": metadata.get("user_prompt_sha256"),
        "developer_prompt_sha256": metadata.get("developer_prompt_sha256"),
        "effort": metadata.get("effort"),
        "request_format": request_format,
        "context_mode": context_mode,
        "normalizer_hash": metadata.get("normalizer_hash"),
    }


def _contract_failures(
    runtime_spec: dict[str, Any],
    probe_metadata: dict[str, Any],
) -> list[str]:
    failures: list[str] = []
    contracts = runtime_spec.get("contracts") or {}
    for key in runtime_spec.get("cells") or {}:
        expected = _expected_contract(str(key), probe_metadata)
        observed = contracts.get(key)
        if expected is None or observed != expected:
            failures.append(str(key))
    return sorted(failures)


def _decision_level(runtime_name: str) -> str | None:
    parts = runtime_name.split(":")
    if len(parts) >= 2 and parts[0] in {"single", "continuous"} and parts[1] in FORMAL_THRESHOLDS:
        return parts[1]
    return None


def _validate_raw_baseline(raw: dict[str, Any]) -> None:
    probes = raw.get("probes")
    if not isinstance(probes, dict) or not probes:
        raise ValueError("baseline probes are required")
    for probe_id, probe in probes.items():
        profiles = probe.get("profiles") or {}
        if not profiles:
            raise ValueError(f"baseline probe has no profiles: {probe_id}")
        for profile_name, profile in profiles.items():
            for model in MODELS:
                if not _window_map(profile, model):
                    raise ValueError(f"baseline cell has no trusted window: {probe_id}|{profile_name}|{model}")


def fit_baseline(
    raw: dict[str, Any],
    *,
    runtime_specs: list[dict[str, Any]],
    probe_metadata: dict[str, Any] | None = None,
    baseline_id: str | None = None,
) -> dict[str, Any]:
    _validate_raw_baseline(raw)
    probe_metadata = deepcopy(probe_metadata or {})
    raw_cells = {
        f"{probe_id}|{profile_name}": profile
        for probe_id, probe in raw["probes"].items()
        for profile_name, profile in (probe.get("profiles") or {}).items()
    }
    fitted_cells = {key: fit_cell(profile) for key, profile in raw_cells.items()}
    cells_quality: dict[str, Any] = {}
    for key, profile in raw_cells.items():
        model_summary: dict[str, Any] = {}
        for model in MODELS:
            windows = _window_map(profile, model)
            total = sum(int(window.get("total", sum((window.get("counts") or {}).values()))) for window in windows.values())
            valid = sum(int(window.get("valid", window.get("total", 0))) for window in windows.values())
            model_summary[model] = {
                "windows": len(windows),
                "total": total,
                "valid": valid,
                "valid_rate": valid / max(1, total),
            }
        cells_quality[key] = {
            "models": model_summary,
            "minimum_valid_rate": min(value["valid_rate"] for value in model_summary.values()),
            "minimum_total_samples": min(value["total"] for value in model_summary.values()),
            "minimum_windows": min(value["windows"] for value in model_summary.values()),
        }

    runtime_contracts: dict[str, Any] = {}
    for runtime_spec in runtime_specs:
        signature = _runtime_signature(runtime_spec)
        required = {
            str(key): int(value)
            for key, value in (runtime_spec.get("cells") or {}).items()
        }
        missing = sorted(set(required) - set(raw_cells))
        contract_failures = _contract_failures(runtime_spec, probe_metadata)
        runtime_name = str(runtime_spec.get("name") or "runtime")
        level = _decision_level(runtime_name)
        runtime_contracts[signature] = {
            "runtime_name": runtime_name,
            "runtime_signature": signature,
            "decision_level": level,
            "required_samples": required,
            "exact_contracts": deepcopy(runtime_spec.get("contracts") or {}),
            "missing_cells": missing,
            "contract_failures": contract_failures,
            "formal_eligible": bool(level and not missing and not contract_failures),
        }

    reference_ready = all(
        cells_quality[key]["models"][model]["total"] > 0
        for key in cells_quality
        for model in MODELS
    )
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "scoring_version": SCORING_VERSION,
        "baseline_id": str(baseline_id or raw.get("baseline_id") or "gpt56-fingerprint-baseline"),
        "smoothing_alpha": SMOOTHING,
        "completion_ratio": COMPLETION_RATIO,
        "models": list(MODELS),
        "probe_metadata": probe_metadata,
        "raw_counts": deepcopy(raw.get("probes") or {}),
        "cells_quality": cells_quality,
        "cells": fitted_cells,
        "runtime_contracts": runtime_contracts,
        "formal_eligible": any(value["formal_eligible"] for value in runtime_contracts.values()),
        "reference_ready": reference_ready,
        "weight_formula": "0 if S<=0 or S<=D else min(1,(S-D)/S)",
        "match_transform": "softmax_T_1",
    }
    artifact["content_sha256"] = hashlib.sha256(canonical_json(artifact).encode("utf-8")).hexdigest()
    return artifact


def verify_baseline(artifact: dict[str, Any]) -> None:
    if int(artifact.get("schema_version", 0)) != SCHEMA_VERSION:
        raise ValueError("unsupported fingerprint baseline schema")
    if artifact.get("scoring_version") != SCORING_VERSION:
        raise ValueError("unsupported fingerprint scoring version")
    if tuple(artifact.get("models") or ()) != MODELS:
        raise ValueError("fingerprint baseline model list mismatch")
    if float(artifact.get("smoothing_alpha", -1)) != SMOOTHING:
        raise ValueError("fingerprint baseline smoothing mismatch")
    expected = str(artifact.get("content_sha256") or "")
    body = deepcopy(artifact)
    body.pop("content_sha256", None)
    observed = hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()
    if expected != observed:
        raise ValueError("fingerprint baseline content hash mismatch")


def load_baseline(path: str | Path) -> dict[str, Any]:
    artifact = json.loads(Path(path).read_text(encoding="utf-8"))
    verify_baseline(artifact)
    return artifact


class ProbabilityModel:
    def __init__(self, artifact: dict[str, Any]):
        verify_baseline(artifact)
        self.artifact = artifact

    def score(
        self,
        rows: Iterable[dict[str, Any]],
        *,
        runtime_spec: dict[str, Any],
        claimed_model: str,
    ) -> dict[str, Any]:
        del claimed_model
        signature = _runtime_signature(runtime_spec)
        runtime_contract = (self.artifact.get("runtime_contracts") or {}).get(signature)
        planned = {
            str(key): int(value)
            for key, value in (runtime_spec.get("cells") or {}).items()
        }
        counts: dict[str, Counter[str]] = defaultdict(Counter)
        for row in rows:
            if row.get("status") != "ok" or row.get("classification") != "category":
                continue
            key = f"{row.get('probe_id')}|{row.get('request_format')}+{row.get('context_mode')}"
            if key in planned:
                counts[key][str(row.get("category") or "__INVALID_OUTPUT__")] += 1

        cells: dict[str, dict[str, Any]] = {}
        missing_baseline_cells: list[str] = []
        incomplete_cells: list[str] = []
        for key, requested in planned.items():
            fitted = (self.artifact.get("cells") or {}).get(key)
            if fitted is None:
                missing_baseline_cells.append(key)
                continue
            normalized = _normalize_candidate_counts(dict(counts[key]), fitted["categories"])
            completed = sum(normalized.values())
            minimum = math.ceil(requested * COMPLETION_RATIO)
            complete = completed >= minimum
            if not complete:
                incomplete_cells.append(key)
            average_ll = {
                model: _cell_average_log_likelihood(
                    normalized,
                    fitted["model_distributions"][model],
                    completed,
                )
                for model in MODELS
            }
            probe_id, profile = key.split("|", 1)
            cells[key] = {
                "probe_id": probe_id,
                "profile": profile,
                "counts": normalized,
                "planned_samples": requested,
                "minimum_completed_samples": minimum,
                "sample_count": completed,
                "completion_ratio": completed / max(1, requested),
                "complete": complete,
                "weight": float(fitted["weight"]),
                "between_model_jsd": float(fitted["between_model_jsd"]),
                "within_model_jsd": float(fitted["within_model_jsd"]),
                "time_stability_verified": bool(fitted.get("time_stability_verified")),
                "average_log_likelihood": average_ll,
            }

        scores, family_details = _family_scores(cells)
        active_families = len(family_details)
        matches = softmax(scores) if active_families else {model: 1.0 / len(MODELS) for model in MODELS}
        ordered = sorted(MODELS, key=lambda model: matches[model], reverse=True)
        contract_failures = _contract_failures(runtime_spec, self.artifact.get("probe_metadata") or {})
        reasons: list[str] = []
        if runtime_contract is None:
            reasons.append("no_exact_runtime_contract")
        elif not runtime_contract.get("formal_eligible"):
            reasons.append("runtime_reference_only")
        if contract_failures:
            reasons.append("runtime_contract_mismatch")
        if missing_baseline_cells:
            reasons.append("baseline_cells_missing")
        if incomplete_cells:
            reasons.append("candidate_samples_incomplete")
        if active_families == 0:
            reasons.append("no_weighted_fingerprint_family")

        decision_level = runtime_contract.get("decision_level") if runtime_contract else None
        thresholds = FORMAL_THRESHOLDS.get(str(decision_level), {})
        official_eligible = bool(
            runtime_contract
            and runtime_contract.get("formal_eligible")
            and not contract_failures
            and not missing_baseline_cells
            and not incomplete_cells
            and active_families > 0
        )
        winners = [
            model for model in MODELS
            if official_eligible and matches[model] > float(thresholds.get(model, 1.0))
        ]
        fingerprint_status = "strong_match" if len(winners) == 1 else "unclear"
        fingerprint_model = winners[0] if len(winners) == 1 else None
        if official_eligible and not winners:
            reasons.append("no_model_reached_strong_match_threshold")
        if len(winners) > 1:
            reasons.append("multiple_models_reached_threshold")
        return {
            "schema_version": SCHEMA_VERSION,
            "scoring_version": SCORING_VERSION,
            "baseline_id": self.artifact["baseline_id"],
            "baseline_sha256": self.artifact["content_sha256"],
            "runtime_signature": signature,
            "runtime_name": str(runtime_spec.get("name") or "runtime"),
            "decision_level": decision_level,
            "fingerprint_status": fingerprint_status,
            "fingerprint_model": fingerprint_model,
            "fingerprint_match": matches,
            "fingerprint_thresholds": thresholds,
            "fingerprint_official_eligible": official_eligible,
            "fingerprint_unclear_reasons": reasons,
            "winner": ordered[0],
            "runner_up": ordered[1],
            "scores": scores,
            "family_contributions": family_details,
            "cell_details": cells,
            "fingerprint_completeness": {
                key: {
                    "planned": value["planned_samples"],
                    "minimum": value["minimum_completed_samples"],
                    "completed": value["sample_count"],
                    "ratio": value["completion_ratio"],
                    "complete": value["complete"],
                }
                for key, value in cells.items()
            },
            "actual_samples": {key: sum(value.values()) for key, value in counts.items()},
            "planned_samples": planned,
            "exact_contracts": deepcopy(runtime_spec.get("contracts") or {}),
            "contract_failures": contract_failures,
            "reference_only": not official_eligible,
            "fingerprint_name_cn": "与内置可信答案分布的相对指纹匹配度",
        }


__all__ = [
    "COMPLETION_RATIO",
    "FORMAL_THRESHOLDS",
    "MODELS",
    "ProbabilityModel",
    "SCHEMA_VERSION",
    "SCORING_VERSION",
    "SMOOTHING",
    "fit_baseline",
    "fit_cell",
    "js_divergence",
    "load_baseline",
    "verify_baseline",
]
