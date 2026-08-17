"""OWASP Top 10 category definitions used by the compliance mapper.

Supports two published lists:

- OWASP Top 10 Web Application Security Risks (2021): ``A01``-``A10``
- OWASP API Security Top 10 (2023): ``API1``-``API10``

Each category lists the CWE families it covers so findings may be mapped
via the category alone when no CWE is attached (e.g. scanner output that
only carries an OWASP reference).
"""

from __future__ import annotations


#: OWASP category id -> vulnerability families (see ``strix.compliance.mapping``).
type OwaspToFamilies = dict[str, tuple[str, ...]]

_OWASP_WEB_2021: OwaspToFamilies = {
    "A01:2021 Broken Access Control": ("access_control",),
    "A02:2021 Cryptographic Failures": ("cleartext", "crypto"),
    "A03:2021 Injection": ("injection",),
    "A04:2021 Insecure Design": ("app_sec", "access_control"),
    "A05:2021 Security Misconfiguration": ("authentication", "credentials", "crypto"),
    "A06:2021 Vulnerable and Outdated Components": ("vuln_mgmt",),
    "A07:2021 Identification and Authentication Failures": ("authentication", "credentials"),
    "A08:2021 Software and Data Integrity Failures": ("app_sec",),
    "A09:2021 Security Logging and Monitoring Failures": ("logging",),
    "A10:2021 Server-Side Request Forgery": ("app_sec",),
}

_OWASP_API_2023: OwaspToFamilies = {
    "API1:2023 Broken Object Level Authorization": ("access_control",),
    "API2:2023 Broken Authentication": ("authentication",),
    "API3:2023 Broken Object Property Level Authorization": ("access_control",),
    "API4:2023 Unrestricted Resource Consumption": ("availability",),
    "API5:2023 Broken Function Level Authorization": ("access_control",),
    "API6:2023 Unrestricted Access to Sensitive Business Flows": (
        "access_control",
        "data_protection",
    ),
    "API7:2023 Server-Side Request Forgery": ("app_sec",),
    "API8:2023 Security Misconfiguration": ("crypto", "access_control"),
    "API9:2023 Improper Inventory Management": ("app_sec",),
    "API10:2023 Unsafe Consumption of APIs": ("app_sec",),
}

#: Canonical (id -> families) combined table.
OWASP_CATEGORIES: OwaspToFamilies = dict(_OWASP_WEB_2021)
OWASP_CATEGORIES.update(_OWASP_API_2023)

#: Compact aliases accepted by the normalizer: ``a01``, ``a1``, ``api1`` etc.
_COMPACT_ALIASES: dict[str, str] = {}
for category in OWASP_CATEGORIES:
    _COMPACT_ALIASES[category.split()[0].lower()] = category  # e.g. "a01:2021"
_COMPACT_ALIASES["a1"] = "A01:2021 Broken Access Control"
_COMPACT_ALIASES["a2"] = "A02:2021 Cryptographic Failures"
_COMPACT_ALIASES["a3"] = "A03:2021 Injection"
_COMPACT_ALIASES["a4"] = "A04:2021 Insecure Design"
_COMPACT_ALIASES["a5"] = "A05:2021 Security Misconfiguration"
_COMPACT_ALIASES["a6"] = "A06:2021 Vulnerable and Outdated Components"
_COMPACT_ALIASES["a7"] = "A07:2021 Identification and Authentication Failures"
_COMPACT_ALIASES["a8"] = "A08:2021 Software and Data Integrity Failures"
_COMPACT_ALIASES["a9"] = "A09:2021 Security Logging and Monitoring Failures"
_COMPACT_ALIASES["a10"] = "A10:2021 Server-Side Request Forgery"
_COMPACT_ALIASES["api1"] = "API1:2023 Broken Object Level Authorization"
_COMPACT_ALIASES["api2"] = "API2:2023 Broken Authentication"
_COMPACT_ALIASES["api3"] = "API3:2023 Broken Object Property Level Authorization"
_COMPACT_ALIASES["api4"] = "API4:2023 Unrestricted Resource Consumption"
_COMPACT_ALIASES["api5"] = "API5:2023 Broken Function Level Authorization"
_COMPACT_ALIASES["api6"] = "API6:2023 Unrestricted Access to Sensitive Business Flows"
_COMPACT_ALIASES["api7"] = "API7:2023 Server-Side Request Forgery"
_COMPACT_ALIASES["api8"] = "API8:2023 Security Misconfiguration"
_COMPACT_ALIASES["api9"] = "API9:2023 Improper Inventory Management"
_COMPACT_ALIASES["api10"] = "API10:2023 Unsafe Consumption of APIs"


def normalise_owasp_category(value: str | None) -> str | None:
    """Return the canonical OWASP category id (``A03:2021 Injection``) or None.

    Accepts the published ids (``A03:2021 Injection``), compact ids
    (``A03``, ``A3``, ``API1``), and case variants, so both scanner output
    and hand-authored findings resolve.
    """
    if not value:
        return None
    compact = value.strip().lower()
    if compact in _COMPACT_ALIASES:
        return _COMPACT_ALIASES[compact]
    for category in OWASP_CATEGORIES:
        if compact == category.lower():
            return category
        if compact.startswith(category.split(" ")[0].lower()):
            return category
    return None
