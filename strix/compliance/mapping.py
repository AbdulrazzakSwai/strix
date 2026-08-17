"""CWE / OWASP -> UAE compliance framework control cross-reference.

Maps weakness families (CWE categories) and OWASP Top 10 Web (2021) / API
(2023) categories to the corresponding controls of the supported UAE
frameworks (ADDA / ADSS, NESA IAS, DESC ISR, UAE CSC Cloud & IoT, UAE
PDPL).

The cross-reference is a two-level table:

- :data:`_FAMILY_BY_CWE` — CWE id -> vulnerability family
- :data:`_CONTROLS_BY_FAMILY` — vulnerability family -> per-framework
  control references

OWASP categories expand to families via :data:`_OWASP_FAMILIES`
(sourced from :mod:`strix.compliance.owasp`), so findings can be mapped
from either identifier alone or both (results are unioned and deduplicated
per framework).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.compliance.frameworks import framework_registry
from strix.compliance.models import (
    FRAMEWORK_KEYS,
    ComplianceControl,
    ComplianceMappings,
    FrameworkKind,
    mappings_to_dict,
)
from strix.compliance.owasp import OWASP_CATEGORIES, normalise_owasp_category


if TYPE_CHECKING:
    from collections.abc import Sequence


VulnerabilityFamily = str


def _ctl(control_id: str, control_name: str, description: str) -> ComplianceControl:
    return ComplianceControl(
        control_id=control_id,
        control_name=control_name,
        description=description,
    )


# ---------------------------------------------------------------------------
# CWE -> family cross-reference
# ---------------------------------------------------------------------------

#: CWE id (digits only) -> vulnerability family. Children of the same class
#: collapse onto one family so the per-family compliance text stays curated.
_FAMILY_BY_CWE: dict[str, VulnerabilityFamily] = {
    # Injection
    "89": "injection",  # SQL Injection
    "943": "injection",  # Improper Neutralization of Special Elements in Data Query Logic
    "78": "injection",  # OS Command Injection
    "77": "injection",  # Command Injection
    "94": "injection",  # Code Injection
    "1336": "injection",  # Server-Side Template Injection
    "90": "injection",  # LDAP Injection
    "91": "injection",  # XML Injection
    # Cross-Site Scripting
    "79": "xss",  # Cross-Site Scripting
    "80": "xss",  # Improper Neutralization of Script-Related HTML Tags
    "81": "xss",  # Improper Neutralization of Script in Error Messages
    "87": "xss",  # Improper Neutralization of Alternate XSS Syntax
    # Cross-Site Request Forgery
    "352": "xsrf",  # CSRF
    # Access control / authorization
    "284": "access_control",  # Improper Access Control
    "285": "access_control",  # Improper Authorization
    "639": "access_control",  # Authorization Bypass Through User-Controlled Key (IDOR)
    "862": "access_control",  # Missing Authorization
    "863": "access_control",  # Incorrect Authorization
    "1220": "access_control",  # Insufficient Granularity of Access Control
    # Authentication & session management
    "287": "authentication",  # Improper Authentication
    "306": "authentication",  # Missing Authentication for Critical Function
    "290": "authentication",  # Authentication Bypass by Spoofing
    "613": "authentication",  # Insufficient Session Expiration
    "640": "authentication",  # Weak Password Recovery Mechanism
    "384": "authentication",  # Session Fixation
    "522": "authentication",  # Insufficiently Protected Credentials
    "521": "authentication",  # Weak Password Requirements
    "1391": "authentication",  # Use of Weak Credentials
    # Credentials / secrets handling
    "798": "credentials",  # Use of Hard-coded Credentials
    "259": "credentials",  # Use of Hard-coded Password
    # Cleartext transmission
    "319": "cleartext",  # Cleartext Transmission of Sensitive Information
    "598": "cleartext",  # Use of GET Request Method With Sensitive Query Strings
    "523": "cleartext",  # Unprotected Transport of Credentials
    # Cryptography
    "327": "crypto",  # Broken or Risky Cryptographic Algorithm
    "328": "crypto",  # Use of Weak Hash
    "916": "crypto",  # Password Storage With Insufficient Computational Effort
    "326": "crypto",  # Inadequate Encryption Strength
    "311": "crypto",  # Missing Encryption of Sensitive Data
    # Information disclosure / data protection
    "200": "data_protection",  # Exposure of Sensitive Information
    "201": "data_protection",  # Insertion of Sensitive Info into Sent Data
    "209": "data_protection",  # Error Message Containing Sensitive Info
    "532": "data_protection",  # Insertion of Sensitive Information into Log File
    "538": "data_protection",  # Insertion of Sensitive Info into Externally-Accessible File
    # Logging & monitoring
    "778": "logging",  # Insufficient Logging
    "117": "logging",  # Improper Output Neutralization for Logs
    "223": "logging",  # Omission of Security-relevant Information
    # Availability / DoS
    "400": "availability",  # Uncontrolled Resource Consumption
    "770": "availability",  # Allocation of Resources Without Limits or Throttling
    "1333": "availability",  # Inefficient Regular Expression Complexity (ReDoS)
    # Application-security catch-all (SSRF, traversal, XXE, deserialization...)
    "918": "app_sec",  # Server-Side Request Forgery
    "22": "app_sec",  # Path Traversal
    "73": "app_sec",  # External Control of File Name or Path
    "502": "app_sec",  # Deserialization of Untrusted Data
    "611": "app_sec",  # XML External Entity (XXE)
    "434": "app_sec",  # Unrestricted File Upload
}


#: Non-CWE vulnerability families addressable via OWASP categories /
#: dependency-style findings (no CWE routes onto them).
_OWASP_ONLY_FAMILIES: tuple[VulnerabilityFamily, ...] = ("vuln_mgmt",)


# ---------------------------------------------------------------------------
# Family -> per-framework controls cross-reference
# ---------------------------------------------------------------------------

_NESA_CONTROLS: dict[VulnerabilityFamily, tuple[ComplianceControl, ...]] = {
    "injection": (
        _ctl(
            "T7 (8.28)",
            "IS Acquisition, Development and Maintenance — secure coding",
            "Application-security controls in system development require input "
            "validation and protection against injection weaknesses (IAS T7; "
            "ISO/IEC 27001:2022 8.28).",
        ),
        _ctl(
            "T5",
            "Access Control",
            "Least-privilege database and application access limits the reach of "
            "a successfully injected query (IAS T5).",
        ),
    ),
    "xss": (
        _ctl(
            "T7 (8.26)",
            "IS Acquisition, Development and Maintenance — application security",
            "Application security requirements in the development lifecycle "
            "include output encoding and trust-boundary handling for untrusted "
            "input, mitigating cross-site scripting (IAS T7; ISO/IEC 27001:2022 "
            "8.26/8.28).",
        ),
        _ctl("M3", "Awareness and Training", "Developer security awareness reduces "
            "introduction of XSS-prone patterns (IAS M3)."),
    ),
    "xsrf": (
        _ctl(
            "T7 (8.26)",
            "IS Acquisition, Development and Maintenance — application security",
            "State-changing request validation (CSRF tokens) is part of the "
            "application security requirements in system development (IAS T7; "
            "ISO/IEC 27001:2022 8.26).",
        ),
    ),
    "access_control": (
        _ctl(
            "T5",
            "Access Control",
            "User access management, least privilege and access-rights reviews "
            "must control access to information and application functions — "
            "broken access control directly violates IAS T5.",
        ),
        _ctl(
            "T7 (8.28)",
            "IS Acquisition, Development and Maintenance — secure coding",
            "Authorization logic is designed and tested in the development "
            "lifecycle (IAS T7; ISO/IEC 27001:2022 8.28).",
        ),
    ),
    "authentication": (
        _ctl(
            "T5",
            "Access Control",
            "Authentication, identity management, privileged access and session "
            "management requirements under IAS T5 cover broken authentication "
            "and session weaknesses.",
        ),
    ),
    "credentials": (
        _ctl(
            "T5",
            "Access Control",
            "Credentials management and privileged-access controls prohibit "
            "hard-coded secrets in information systems (IAS T5).",
        ),
    ),
    "cleartext": (
        _ctl(
            "T4",
            "Communications / Network Security",
            "Protection of information in transit requires encryption of network "
            "traffic — cleartext transmission of sensitive data violates IAS T4 "
            "(ISO/IEC 27001:2022 8.20/8.24).",
        ),
    ),
    "crypto": (
        _ctl(
            "T7",
            "IS Acquisition, Development and Maintenance — cryptography policy",
            "A cryptographic control policy must be in place and use approved, "
            "unbroken algorithms and key management (IAS T7; ISO/IEC 27001:2022 "
            "8.24).",
        ),
    ),
    "data_protection": (
        _ctl(
            "T1",
            "Information Asset Management",
            "Information classification and labelling ensure sensitive data is "
            "protected per its classification — exposure of sensitive "
            "information violates IAS T1 handling requirements.",
        ),
    ),
    "logging": (
        _ctl(
            "T8",
            "Information Security Incident Management",
            "Security events and weaknesses must be reported, collected and "
            "analyzed; insufficient logging blinds incident detection (IAS T8).",
        ),
        _ctl("T3", "Operations Management", "Logging and monitoring requirements under "
            "IAS T3 operations management."),
    ),
    "availability": (
        _ctl(
            "T9",
            "Information Systems Continuity Management",
            "Business continuity management counteracts interruption of critical "
            "business processes from availability failure (IAS T9).",
        ),
    ),
    "app_sec": (
        _ctl(
            "T7 (8.28)",
            "IS Acquisition, Development and Maintenance — secure coding",
            "Input validation and secure design in application development "
            "cover SSRF, path traversal, XXE, deserialization and upload "
            "weaknesses (IAS T7; ISO/IEC 27001:2022 8.28).",
        ),
    ),
    "vuln_mgmt": (
        _ctl(
            "T7",
            "IS Acquisition, Development and Maintenance — technical vulnerabilities",
            "Management of technical vulnerabilities (patching, component "
            "updates) is required under IAS T7.",
        ),
    ),
}


_DESC_CONTROLS: dict[VulnerabilityFamily, tuple[ComplianceControl, ...]] = {
    "injection": (
        _ctl(
            "ISR D8",
            "Information Systems Acquisition, Development and Management",
            "Secure development and application-security requirements (input "
            "validation) prevent injection weaknesses in systems acquired or "
            "developed for Dubai Government Entities (ISR v3.1 D8).",
        ),
    ),
    "xss": (
        _ctl(
            "ISR D8",
            "Information Systems Acquisition, Development and Management",
            "Application security controls in the development management domain "
            "include output encoding for untrusted input (ISR v3.1 D8).",
        ),
    ),
    "xsrf": (
        _ctl(
            "ISR D8",
            "Information Systems Acquisition, Development and Management",
            "State-changing request validation is part of application security "
            "requirements in system development (ISR v3.1 D8).",
        ),
    ),
    "access_control": (
        _ctl(
            "ISR D5",
            "Access Control",
            "Access control requirements govern user access, roles, least "
            "privilege and rights review — broken access control directly "
            "violates ISR v3.1 Domain 5.",
        ),
        _ctl(
            "ISR D13",
            "Monitoring, Audit and Review",
            "Regular audits and reviews verify that access-control implementation "
            "works as intended (ISR v3.1 D13).",
        ),
    ),
    "authentication": (
        _ctl(
            "ISR D5",
            "Access Control",
            "Identity and authentication management, session controls and "
            "privileged-access management under ISR v3.1 Domain 5.",
        ),
    ),
    "credentials": (
        _ctl(
            "ISR D5",
            "Access Control",
            "Credential management requirements prohibit hard-coded or weak "
            "credentials in government information systems (ISR v3.1 D5).",
        ),
    ),
    "cleartext": (
        _ctl(
            "ISR D6",
            "Operation, Systems and Communication Management",
            "Network security and encryption-in-transit requirements under ISR "
            "v3.1 Domain 6 protect information in transit.",
        ),
    ),
    "crypto": (
        _ctl(
            "ISR D6",
            "Operation, Systems and Communication Management (cryptography)",
            "Cryptographic controls and key-management requirements under ISR "
            "v3.1 Domain 6 for data protection.",
        ),
    ),
    "data_protection": (
        _ctl(
            "ISR D2",
            "Information and Information Assets Management",
            "Data classification, masking and controlled handling of sensitive "
            "information prevent unauthorized disclosure (ISR v3.1 D2).",
        ),
    ),
    "logging": (
        _ctl(
            "ISR D13",
            "Monitoring, Audit and Review",
            "Comprehensive logging, monitoring and audit requirements under ISR "
            "v3.1 Domain 13; insufficient logging violates the domain.",
        ),
    ),
    "availability": (
        _ctl(
            "ISR D7",
            "Business Continuity Planning",
            "Business continuity planning counteracts interruption of critical "
            "business processes from resource-exhaustion and availability "
            "failure (ISR v3.1 D7).",
        ),
    ),
    "app_sec": (
        _ctl(
            "ISR D8",
            "Information Systems Acquisition, Development and Management",
            "Application security in development covers SSRF, traversal, XXE, "
            "deserialization and upload weaknesses (ISR v3.1 D8).",
        ),
    ),
    "vuln_mgmt": (
        _ctl(
            "ISR D8",
            "Information Systems Acquisition, Development and Management",
            "Technical vulnerability and patch management requirements under "
            "ISR v3.1 Domain 8.",
        ),
    ),
}


_ADDA_CONTROLS: dict[VulnerabilityFamily, tuple[ComplianceControl, ...]] = {
    "injection": (
        _ctl(
            "SD",
            "IS Acquisition, Development & Maintenance (SD)",
            "Application-security requirements in system development mandate "
            "input validation against injection weaknesses (ADSS v2, SD domain).",
        ),
    ),
    "xss": (
        _ctl(
            "SD",
            "IS Acquisition, Development & Maintenance (SD)",
            "Secure development practices require output encoding and handling "
            "of untrusted input (ADSS v2, SD domain).",
        ),
    ),
    "xsrf": (
        _ctl(
            "SD",
            "IS Acquisition, Development & Maintenance (SD)",
            "State-changing request validation is part of ADSS application "
            "security requirements (ADSS v2, SD domain).",
        ),
    ),
    "access_control": (
        _ctl(
            "AC",
            "Access Control (AC)",
            "Access-control specifications cover user access, least privilege "
            "and rights review; broken access control violates ADSS v2 access "
            "control requirements.",
        ),
        _ctl("LG", "Security Audit & Monitoring (LG)", "Audit and monitoring of access "
            "verifies authorization controls work as intended (ADSS v2, LG)."),
    ),
    "authentication": (
        _ctl(
            "AC",
            "Access Control (AC)",
            "Authentication and identity-management specifications under the "
            "ADSS v2 Access Control domain.",
        ),
    ),
    "credentials": (
        _ctl(
            "AC",
            "Access Control (AC)",
            "Credential-management requirements prohibit hard-coded or weak "
            "credentials in Abu Dhabi government systems (ADSS v2, AC).",
        ),
    ),
    "cleartext": (
        _ctl(
            "CN",
            "Network & Communications Security (CN)",
            "Network security specifications protect information in transit "
            "with encryption (ADSS v2, CN domain).",
        ),
    ),
    "crypto": (
        _ctl(
            "CR",
            "Cryptography (CR)",
            "Cryptographic controls require approved algorithms and key "
            "management (ADSS v2, CR domain).",
        ),
    ),
    "data_protection": (
        _ctl(
            "AM",
            "Asset & Data Management (AM)",
            "Data classification and controlled handling of sensitive data "
            "prevent unauthorized disclosure (ADSS v2, AM domain).",
        ),
    ),
    "logging": (
        _ctl(
            "LG",
            "Security Audit & Monitoring (LG)",
            "Logging, audit and monitoring specifications under the ADSS v2 "
            "monitoring domain.",
        ),
    ),
    "availability": (
        _ctl(
            "BC",
            "Business Continuity (BC)",
            "Business continuity specifications protect critical processes from "
            "availability failure (ADSS v2, BC domain).",
        ),
    ),
    "app_sec": (
        _ctl(
            "SD",
            "IS Acquisition, Development & Maintenance (SD)",
            "Application-security requirements cover SSRF, traversal, XXE, "
            "deserialization and upload weaknesses (ADSS v2, SD domain).",
        ),
    ),
    "vuln_mgmt": (
        _ctl(
            "SD",
            "IS Acquisition, Development & Maintenance (SD)",
            "Technical vulnerability and patch management requirements (ADSS "
            "v2, SD domain).",
        ),
    ),
}


_CSC_CONTROLS: dict[VulnerabilityFamily, tuple[ComplianceControl, ...]] = {
    "injection": (
        _ctl(
            "IA 8.28",
            "UAE IA Standard — secure coding",
            "The CSC UAE IA Standard requires secure coding including input "
            "validation, aligned with ISO/IEC 27001:2022 control 8.28.",
        ),
        _ctl(
            "NCSP-3",
            "National Cloud Security Policy — secure cloud architecture and operations",
            "Cloud workload application security, including protections against "
            "injection in cloud-hosted services (NCSP 2023).",
        ),
    ),
    "xss": (
        _ctl(
            "IA 8.26",
            "UAE IA Standard — application security",
            "Application-security requirements include output encoding and "
            "trust-boundary handling for untrusted input (ISO/IEC 27001:2022 8.26).",
        ),
    ),
    "xsrf": (
        _ctl(
            "IA 8.28",
            "UAE IA Standard — secure coding",
            "State-changing request validation is part of secure coding "
            "requirements (ISO/IEC 27001:2022 8.28).",
        ),
    ),
    "access_control": (
        _ctl(
            "IA 5.15",
            "UAE IA Standard — access control",
            "Identity/access-management controls (ISO/IEC 27001:2022 5.15-5.18, "
            "8.2) require least privilege and authorization reviews — broken "
            "access control violates them.",
        ),
        _ctl(
            "NCSP-3",
            "National Cloud Security Policy — cloud identity and access",
            "Cloud IAM and tenant-isolation requirements for UAE cloud services "
            "(NCSP 2023).",
        ),
    ),
    "authentication": (
        _ctl(
            "IA 5.15",
            "UAE IA Standard — identity and authentication",
            "Identity, authentication and session-management controls under the "
            "IA Standard (ISO/IEC 27001:2022 5.15-5.18, 8.2, 8.5).",
        ),
    ),
    "credentials": (
        _ctl(
            "IA 5.14",
            "UAE IA Standard — secrets and information storage",
            "Protection of authentication information and prohibition of "
            "hard-coded credentials (ISO/IEC 27001:2022 5.14/5.18, 8.24).",
        ),
    ),
    "cleartext": (
        _ctl(
            "IA 8.24",
            "UAE IA Standard — cryptography in transit",
            "Encryption of information in transit is required for systems "
            "within UAE critical infrastructure (ISO/IEC 27001:2022 8.24/8.26).",
        ),
        _ctl(
            "NCSP-2",
            "National Cloud Security Policy — data security and privacy",
            "Cloud data confidentiality and encryption (in transit and at rest) "
            "for UAE cloud services (NCSP 2023).",
        ),
    ),
    "crypto": (
        _ctl(
            "IA 8.24",
            "UAE IA Standard — cryptography",
            "Approved cryptographic algorithms and key management under the IA "
            "Standard (ISO/IEC 27001:2022 8.24).",
        ),
    ),
    "data_protection": (
        _ctl(
            "NCSP-2",
            "National Cloud Security Policy — data security and privacy",
            "Data classification, protection and privacy controls for personal "
            "and critical data in cloud services (NCSP 2023).",
        ),
        _ctl(
            "IA 8.12",
            "UAE IA Standard — information leakage prevention",
            "Data-leak prevention and handling of sensitive information "
            "(ISO/IEC 27001:2022 8.12).",
        ),
    ),
    "logging": (
        _ctl(
            "IA 8.15",
            "UAE IA Standard — logging and monitoring",
            "Logging, monitoring and audit requirements (ISO/IEC 27001:2022 "
            "8.15/8.16) — insufficient logging fails these controls.",
        ),
        _ctl(
            "NCSP-4",
            "National Cloud Security Policy — cyber operations and response",
            "Cloud security-operations and monitoring requirements addressing "
            "logging and detection in cloud environments (NCSP 2023).",
        ),
    ),
    "availability": (
        _ctl(
            "NCSP-4",
            "National Cloud Security Policy — cloud business resilience",
            "Cloud resilience, continuity and resource-scaling requirements "
            "counteract denial-of-service and resource exhaustion (NCSP 2023).",
        ),
    ),
    "app_sec": (
        _ctl(
            "IA 8.28",
            "UAE IA Standard — secure coding",
            "Secure coding and application security cover SSRF, traversal, XXE, "
            "deserialization and upload weaknesses (ISO/IEC 27001:2022 8.28).",
        ),
    ),
    "vuln_mgmt": (
        _ctl(
            "IA 8.8",
            "UAE IA Standard — management of technical vulnerabilities",
            "Timely identification and remediation of technical vulnerabilities "
            "(ISO/IEC 27001:2022 8.8) across hosted and cloud systems.",
        ),
        _ctl(
            "NIP-4",
            "National IoT Security Policy — vulnerability management",
            "IoT devices must support updating and patching; providers must "
            "manage vulnerabilities across device lifecycles (NIP 2023).",
        ),
    ),
}


_PDPL_CONTROLS: dict[VulnerabilityFamily, tuple[ComplianceControl, ...]] = {
    "injection": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — confidentiality, integrity, accuracy",
            "Measures ensuring the confidentiality, integrity, accuracy and "
            "resilience of processing systems are compromised by injection "
            "flaws (PDPL Art. 20(1)(b)).",
        ),
    ),
    "xss": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — confidentiality and security of systems",
            "Technical measures must ensure the ongoing confidentiality and "
            "security of processing systems; XSS enables unauthorized access "
            "to personal data (PDPL Art. 20(1)(b)).",
        ),
    ),
    "xsrf": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — confidentiality of processing",
            "State-changing requests that bypass authorization undermine the "
            "security of personal-data processing (PDPL Art. 20(1)(b)).",
        ),
    ),
    "access_control": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — preventing unauthorized access",
            "Unlawful or unauthorized access to personal data is an explicit "
            "risk factor; broken access control violates the required security "
            "measures (PDPL Art. 20(1)(b), Art. 20(2)(a)).",
        ),
    ),
    "authentication": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — confidentiality and access security",
            "Authentication failures permit unauthorized access to personal "
            "data, contrary to Articles 20(1)(b) and 20(2)(a).",
        ),
    ),
    "credentials": (
        _ctl(
            "PDPL Art. 20(1)(a)",
            "Security of Personal Data — encryption and pseudonymisation",
            "Hard-coded or weak credentials defeat the encryption and access "
            "protection measures required for personal data (PDPL Art. 20(1)(a)).",
        ),
    ),
    "cleartext": (
        _ctl(
            "PDPL Art. 20(1)(a)",
            "Security of Personal Data — encryption and pseudonymisation",
            "Encryption of personal data, including during transmission, is "
            "explicitly required; cleartext transmission violates Art. 20(1)(a) "
            "(risk factor: disclosure during transmission, Art. 20(2)(a)).",
        ),
    ),
    "crypto": (
        _ctl(
            "PDPL Art. 20(1)(a)",
            "Security of Personal Data — encryption and pseudonymisation",
            "Encryption must be applied per international best practice; broken "
            "cryptographic algorithms undermine the required protection "
            "(PDPL Art. 20(1)(a)).",
        ),
    ),
    "data_protection": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — confidentiality",
            "Unauthorized disclosure of personal data violates the required "
            "security measures (PDPL Art. 20(1)(b), Art. 20(2)(a)).",
        ),
        _ctl(
            "PDPL Art. 21",
            "Data Protection Impact Assessment",
            "High-risk processing of sensitive personal data requires a DPIA "
            "before processing (PDPL Art. 21).",
        ),
    ),
    "availability": (
        _ctl(
            "PDPL Art. 20(1)(c)",
            "Security of Personal Data — availability and recovery",
            "Measures must ensure timely retrieval of and access to personal "
            "data in the event of physical or technical failure (PDPL Art. 20(1)(c)).",
        ),
    ),
    "app_sec": (
        _ctl(
            "PDPL Art. 20(1)(b)",
            "Security of Personal Data — security of processing systems",
            "Technical measures must ensure the ongoing confidentiality, "
            "integrity and security of processing systems and services, "
            "covering SSRF, traversal, XXE, deserialization and upload "
            "weaknesses (PDPL Art. 20(1)(b)).",
        ),
    ),
    "vuln_mgmt": (
        _ctl(
            "PDPL Art. 20(1)(d)",
            "Security of Personal Data — testing and evaluation",
            "Security measures must be regularly tested and evaluated; "
            "outdated components with known vulnerabilities fail this "
            "obligation (PDPL Art. 20(1)(d)).",
        ),
    ),
}


#: Family -> framework -> applicable controls. Families are restricted to
#: those with a control entry in *every* framework (e.g. the PDPL has no
#: logging requirement, so ``logging`` stays out of the PDPL table and the
#: mapper resolves it to an empty per-framework result there).
_CONTROLS_BY_FAMILY: dict[
    VulnerabilityFamily, dict[FrameworkKind, tuple[ComplianceControl, ...]]
] = {
    family: {
        "nesa": _NESA_CONTROLS[family],
        "desc": _DESC_CONTROLS[family],
        "adda": _ADDA_CONTROLS[family],
        "csc": _CSC_CONTROLS[family],
        "pdpl": _PDPL_CONTROLS[family],
    }
    for family in _NESA_CONTROLS
    if family in _PDPL_CONTROLS
}


# OWASP category id -> families (canonical ids from strix.compliance.owasp).
_FAMILIES_BY_OWASP: dict[str, tuple[VulnerabilityFamily, ...]] = OWASP_CATEGORIES


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalise_cwe(cwe: str | None) -> str | None:
    """Return the digits of a CWE reference (``CWE-89``, ``cwe: 89``, ``89``), or None."""
    if not cwe:
        return None
    digits = "".join(char for char in str(cwe) if char.isdigit())
    return digits or None


def families_for_cwe(cwe: str | None) -> tuple[VulnerabilityFamily, ...]:
    """Vulnerability families for a CWE id (normalized), empty when unknown."""
    digits = normalise_cwe(cwe)
    if not digits:
        return ()
    family = _FAMILY_BY_CWE.get(digits)
    return (family,) if family else ()


def families_for_owasp(owasp_category: str | None) -> tuple[VulnerabilityFamily, ...]:
    """Vulnerability families for an OWASP category id, empty when unknown."""
    canonical = normalise_owasp_category(owasp_category)
    if not canonical:
        return ()
    return _FAMILIES_BY_OWASP.get(canonical, ())


def resolve_framework_keys(
    selected: Sequence[str] | None = None,
) -> tuple[FrameworkKind, ...]:
    """Normalize a user selection into ordered framework keys.

    Accepts ``["all"]`` (expands to every framework), any subset of the
    keys (``adda`` / ``nesa`` / ``desc`` / ``csc`` / ``pdpl``), and filters
    unknown entries. Returns the canonical framework order.
    """
    if not selected:
        return FRAMEWORK_KEYS
    expanded: list[FrameworkKind] = []
    for entry in selected:
        key = str(entry).strip().lower()
        if key == "all":
            return FRAMEWORK_KEYS
        if key in FRAMEWORK_KEYS:
            kind: FrameworkKind = key  # type: ignore[assignment]
            if kind not in expanded:
                expanded.append(kind)
    return tuple(expanded)


def map_vulnerability_to_uae_frameworks(
    cwe_id: str | None,
    owasp_category: str | None = None,
    *,
    frameworks: Sequence[str] | None = None,
) -> ComplianceMappings:
    """Map a vulnerability to its UAE compliance framework controls.

    ``cwe_id`` is any supported form (``CWE-89``, ``cwe: 89``, ``89``).
    ``owasp_category`` is an OWASP Top 10 Web (2021) or API (2023) id
    (``A03:2021 Injection``, ``A3``, ``API1:2023 ...``). Families derived
    from both identifiers are unioned and deduplicated per framework.

    ``frameworks`` optionally filters the output (default: all five
    frameworks, in canonical order). Returns a mapping with at least one
    control per returned framework, or an empty mapping when neither
    identifier is recognized.
    """
    families = families_for_cwe(cwe_id)
    families += tuple(f for f in families_for_owasp(owasp_category) if f not in families)

    keys = resolve_framework_keys(frameworks)
    if not families or not keys:
        return {}

    mappings: ComplianceMappings = {}
    for key in keys:
        controls: list[ComplianceControl] = []
        seen: set[str] = set()
        for family in families:
            for control in _CONTROLS_BY_FAMILY.get(family, {}).get(key, ()):
                if control.control_id in seen:
                    continue
                seen.add(control.control_id)
                controls.append(control)
        if controls:
            mappings[key] = controls
    return mappings


def framework_display_names() -> dict[str, str]:
    """Framework key -> display name (for report section titles)."""
    registry = framework_registry()
    return {key: registry[key].name for key in FRAMEWORK_KEYS}


__all__ = [
    "ComplianceControl",
    "ComplianceMappings",
    "framework_display_names",
    "map_vulnerability_to_uae_frameworks",
    "mappings_to_dict",
    "normalise_cwe",
    "normalise_owasp_category",
    "resolve_framework_keys",
]
