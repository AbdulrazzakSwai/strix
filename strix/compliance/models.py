"""Type definitions for UAE compliance framework mapping.

Strix findings (CWE / OWASP category) are mapped to controls in the UAE
national and emirate-level frameworks:

- ``adda`` — Abu Dhabi Information Security Standards v2 (ADSIC / ADDA)
- ``nesa`` — UAE Information Assurance Standards (NESA / Cyber Security
  Council)
- ``desc`` — Dubai Electronic Security Center Information Security
  Regulation (ISR) v3.1
- ``csc`` — UAE Cybersecurity Council Cloud & IoT policy package
  (National Cloud Security Policy, National IoT Security Policy, UAE IA
  Standard)
- ``pdpl`` — Federal Decree-Law No. 45 of 2021 on the Protection of
  Personal Data
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


FrameworkKind = Literal["adda", "nesa", "desc", "csc", "pdpl"]

FRAMEWORK_KEYS: tuple[FrameworkKind, ...] = ("adda", "nesa", "desc", "csc", "pdpl")

#: Canonical order used for rendering (report sections, JSON keys).
FRAMEWORK_ORDER: tuple[FrameworkKind, ...] = FRAMEWORK_KEYS


@dataclass(frozen=True)
class ComplianceControl:
    """Reference to one control of a UAE compliance framework.

    ``control_id`` is the reference used by the framework (e.g. ``ISR D5``,
    ``PDPL Art. 20(1)(a)``, ``T7``). ``description`` is a brief,
    vulnerability-class-specific compliance note.
    """

    control_id: str
    control_name: str
    description: str


@dataclass(frozen=True)
class ComplianceFramework:
    """Metadata for one supported UAE compliance framework."""

    key: FrameworkKind
    name: str
    version: str
    authority: str
    jurisdiction: str
    reference: str
    domains: tuple[str, ...] = field(default_factory=tuple)


#: Per-finding mapping: framework key -> applicable controls.
type ComplianceMappings = dict[FrameworkKind, list[ComplianceControl]]


def control_to_dict(control: ComplianceControl) -> dict[str, str]:
    """Serialize one control reference (JSON-safe report payload)."""
    return {
        "control_id": control.control_id,
        "control_name": control.control_name,
        "description": control.description,
    }


def mappings_to_dict(mappings: ComplianceMappings) -> dict[str, list[dict[str, str]]]:
    """Serialize a full mapping payload for ``vulnerabilities.json`` / SARIF."""
    return {
        key: [control_to_dict(control) for control in controls]
        for key, controls in mappings.items()
        if controls
    }
