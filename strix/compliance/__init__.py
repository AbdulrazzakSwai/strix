"""UAE National Cybersecurity & Compliance framework mapping.

Maps Strix findings (CWE ids and OWASP Top 10 Web / API categories) to
controls of the UAE compliance frameworks:

- ``adda`` — Abu Dhabi Information Security Standards (ADDA / ADISSC)
- ``nesa`` — UAE Information Assurance Standards (NESA IAS)
- ``desc`` — Dubai Information Security Regulation v3.1 (DESC ISR)
- ``csc`` — UAE Cybersecurity Council Cloud & IoT Security package
- ``pdpl`` — UAE PDPL (Federal Decree-Law No. 45/2021)

Public surface:

- :func:`map_vulnerability_to_uae_frameworks` — the mapping engine
- :func:`resolve_framework_keys` — ``--frameworks`` selection normalizer
- :func:`normalise_cwe` / :func:`normalise_owasp_category` — input
  normalizers
- :func:`framework_registry` / :func:`framework_display_names` — framework
  metadata
"""

from strix.compliance.frameworks import framework_registry, get_framework
from strix.compliance.mapping import (
    framework_display_names,
    map_vulnerability_to_uae_frameworks,
    normalise_cwe,
    normalise_owasp_category,
    resolve_framework_keys,
)
from strix.compliance.models import (
    FRAMEWORK_KEYS,
    ComplianceControl,
    ComplianceFramework,
    ComplianceMappings,
    FrameworkKind,
    mappings_to_dict,
)


__all__ = [
    "FRAMEWORK_KEYS",
    "ComplianceControl",
    "ComplianceFramework",
    "ComplianceMappings",
    "FrameworkKind",
    "framework_display_names",
    "framework_registry",
    "get_framework",
    "map_vulnerability_to_uae_frameworks",
    "mappings_to_dict",
    "normalise_cwe",
    "normalise_owasp_category",
    "resolve_framework_keys",
]
