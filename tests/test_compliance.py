"""Tests for UAE regulatory & compliance framework mapping (strix.compliance).

Covered: CWE- and OWASP-based mapping into ADDA/ADSS, NESA IAS, DESC ISR,
UAE CSC, and UAE PDPL controls; framework selection; integration with the
Markdown/SARIF writers and the report state auto-enricher.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.compliance import (
    FRAMEWORK_KEYS,
    map_vulnerability_to_uae_frameworks,
    mappings_to_dict,
    resolve_framework_keys,
)
from strix.report.sarif import write_sarif
from strix.report.state import ReportState
from strix.report.writer import render_vulnerability_md


if TYPE_CHECKING:
    from pathlib import Path


def _control_ids(mappings: dict) -> dict[str, list[str]]:
    return {key: [c["control_id"] for c in controls] for key, controls in mappings.items()}


def test_resolve_framework_keys_defaults_to_all() -> None:
    assert resolve_framework_keys([]) == FRAMEWORK_KEYS
    assert resolve_framework_keys(["all"]) == FRAMEWORK_KEYS


def test_resolve_framework_keys_subset_preserves_user_order() -> None:
    assert resolve_framework_keys(["pdpl", "nesa"]) == ("pdpl", "nesa")
    assert resolve_framework_keys(["csc"]) == ("csc",)


def test_resolve_framework_keys_filters_unknown() -> None:
    assert resolve_framework_keys(["enisa"]) == ()
    assert resolve_framework_keys(["nesa", "enisa", "csc"]) == ("nesa", "csc")


def test_cwe_89_maps_into_all_frameworks() -> None:
    ids = _control_ids(mappings_to_dict(map_vulnerability_to_uae_frameworks("CWE-89")))
    assert set(ids) == set(FRAMEWORK_KEYS)
    assert ids["adda"] == ["SD"]
    assert "T7 (8.28)" in ids["nesa"]
    assert "ISR D8" in ids["desc"]
    assert "IA 8.28" in ids["csc"]
    assert "PDPL Art. 20(1)(b)" in ids["pdpl"]


@pytest.mark.parametrize(
    ("cwe_id", "expected"),
    [
        (
            "CWE-79",
            {
                "adda": "SD",
                "nesa": "T7 (8.26)",
                "desc": "ISR D8",
                "csc": "IA 8.26",
                "pdpl": "PDPL Art. 20(1)(b)",
            },
        ),
        (
            "CWE-284",
            {
                "adda": "AC",
                "nesa": "T5",
                "desc": "ISR D5",
                "csc": "IA 5.15",
                "pdpl": "PDPL Art. 20(1)(b)",
            },
        ),
        (
            "CWE-319",
            {
                "adda": "CN",
                "nesa": "T4",
                "desc": "ISR D6",
                "csc": "IA 8.24",
                "pdpl": "PDPL Art. 20(1)(a)",
            },
        ),
    ],
)
def test_known_cwes_map_into_all_frameworks(cwe_id: str, expected: dict[str, str]) -> None:
    ids = _control_ids(mappings_to_dict(map_vulnerability_to_uae_frameworks(cwe_id)))
    assert set(ids) == set(FRAMEWORK_KEYS)
    for framework, control in expected.items():
        assert control in ids[framework]


@pytest.mark.parametrize("cwe_form", ["CWE-89", "cwe: 89", "89", "cwe-89 "])
def test_cwe_normalization_forms_are_equivalent(cwe_form: str) -> None:
    ids = _control_ids(mappings_to_dict(map_vulnerability_to_uae_frameworks(cwe_form)))
    assert "SD" in ids["adda"]


def test_unknown_cwe_maps_to_nothing() -> None:
    assert map_vulnerability_to_uae_frameworks("CWE-99999") == {}
    assert map_vulnerability_to_uae_frameworks(None, None) == {}


def test_owasp_web_category_maps_via_family() -> None:
    ids = _control_ids(
        mappings_to_dict(map_vulnerability_to_uae_frameworks(None, "A03:2021 Injection"))
    )
    assert set(ids) == set(FRAMEWORK_KEYS)
    assert "SD" in ids["adda"]
    # compact alias forms resolve the same way
    compact = _control_ids(mappings_to_dict(map_vulnerability_to_uae_frameworks(None, "A3")))
    assert compact == ids


def test_owasp_api_category_maps_with_framework_filter() -> None:
    ids = _control_ids(
        mappings_to_dict(
            map_vulnerability_to_uae_frameworks(
                None,
                "API1:2023 Broken Object Level Authorization",
                frameworks=["desc", "pdpl"],
            )
        )
    )
    assert list(ids) == ["desc", "pdpl"]
    assert "ISR D5" in ids["desc"]
    assert "PDPL Art. 20(1)(b)" in ids["pdpl"]


def test_owasp_api_alias_api1_resolves_same_as_api1_2023() -> None:
    full = _control_ids(
        mappings_to_dict(
            map_vulnerability_to_uae_frameworks(None, "API1:2023 Broken Object Level Authorization")
        )
    )
    alias = _control_ids(mappings_to_dict(map_vulnerability_to_uae_frameworks(None, "API1")))
    assert alias == full


def test_mappings_to_dict_is_json_serialisable() -> None:
    mappings = map_vulnerability_to_uae_frameworks("CWE-89")
    payload = json.dumps(mappings_to_dict(mappings))
    assert "T7 (8.28)" in payload


def test_render_vulnerability_md_includes_compliance_section() -> None:
    md = render_vulnerability_md(
        {
            "id": "vuln-0001",
            "title": "SQL Injection",
            "severity": "high",
            "timestamp": "2026-07-02 10:00:00 UTC",
            "description": "d",
            "compliance_mappings": mappings_to_dict(map_vulnerability_to_uae_frameworks("CWE-89")),
        }
    )
    assert "## UAE Regulatory & Compliance Breakdown" in md
    assert "### UAE Information Assurance Standards (IAS)" in md
    assert "T7 (8.28)" in md
    assert "PDPL Art. 20(1)(b)" in md


def test_render_vulnerability_md_omits_compliance_section_without_mappings() -> None:
    md = render_vulnerability_md(
        {
            "id": "vuln-0001",
            "title": "SQL Injection",
            "severity": "high",
            "timestamp": "2026-07-02 10:00:00 UTC",
            "description": "d",
        }
    )
    assert "UAE Regulatory & Compliance Breakdown" not in md


def _sarif_finding(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "SQL Injection in get_user",
        "severity": "critical",
        "cwe": "CWE-89",
        "timestamp": "2026-07-02 10:00:00 UTC",
        "code_locations": [{"file": "app.py", "start_line": 4}],
    }
    base.update(overrides)
    return base


def test_sarif_includes_strix_compliance_property(tmp_path: Path) -> None:
    finding = _sarif_finding(
        compliance_mappings=mappings_to_dict(map_vulnerability_to_uae_frameworks("CWE-89"))
    )
    write_sarif(tmp_path, [finding])
    doc = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    props = doc["runs"][0]["results"][0]["properties"]["strix"]
    assert "compliance" in props
    assert "nesa" in props["compliance"]
    assert props["compliance"]["nesa"][0]["control_id"] == "T7 (8.28)"


def test_sarif_omits_compliance_property_without_mappings(tmp_path: Path) -> None:
    write_sarif(tmp_path, [_sarif_finding()])
    doc = json.loads((tmp_path / "findings.sarif").read_text(encoding="utf-8"))
    strix = doc["runs"][0]["results"][0]["properties"]["strix"]
    assert "compliance" not in strix


def _new_state(compliance: dict[str, Any] | None) -> ReportState:
    state = ReportState()
    state.set_scan_config({"compliance": compliance})
    return state


def _add_finding(state: ReportState, **overrides: Any) -> dict[str, Any]:
    args: dict[str, Any] = {
        "title": "SQL Injection",
        "severity": "high",
        "cwe": "CWE-89",
    }
    args.update(overrides)
    state.add_vulnerability_report(**args)
    return state.vulnerability_reports[-1]


def test_state_auto_enriches_when_compliance_enabled() -> None:
    state = _new_state({"enabled": True, "frameworks": ["nesa"]})
    report = _add_finding(state)
    assert report["compliance_mappings"] == mappings_to_dict(
        map_vulnerability_to_uae_frameworks("CWE-89", frameworks=["nesa"])
    )


def test_state_respects_framework_selection() -> None:
    state = _new_state({"enabled": True, "frameworks": ["csc"]})
    report = _add_finding(state)
    assert set(report["compliance_mappings"]) == {"csc"}


def test_state_compliance_off_keeps_finding_clean() -> None:
    state = _new_state({"enabled": False, "frameworks": []})
    report = _add_finding(state)
    assert "compliance_mappings" not in report


def test_state_explicit_mappings_win_over_auto() -> None:
    state = _new_state({"enabled": True, "frameworks": ["nesa"]})
    explicit = {
        "csc": [{"control_id": "NCSP-3", "control_name": "Cloud Adoption", "description": "x"}]
    }
    report = _add_finding(state, compliance_mappings=explicit)
    assert report["compliance_mappings"] == explicit
    assert set(report["compliance_mappings"]) == {"csc"}


def test_state_auto_enrich_skips_unknown_cwe() -> None:
    state = _new_state({"enabled": True, "frameworks": ["nesa"]})
    report = _add_finding(state, cwe="CWE-99999")
    assert "compliance_mappings" not in report


def test_run_record_compliance_block_is_written() -> None:
    state = _new_state({"enabled": True, "frameworks": ["adda", "nesa"]})
    _add_finding(state)
    record = state.run_record["compliance"]
    assert record["enabled"] is True
    assert record["frameworks"] == ["adda", "nesa"]
    assert record["findings"] == 1
    assert record["findings_with_mappings"] == 1
