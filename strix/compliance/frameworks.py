"""UAE compliance frameworks registry and control-structure metadata.

Each entry describes a published UAE / emirate information-security (or
data-protection) framework an organization in scope may be expected to map
findings against. Control references used throughout ``strix.compliance``
are the ones the published standards themselves use:

- **NESA IAS** - management families ``M1``-``M6`` and technical families
  ``T1``-``T9``, prior to v2 rebasing onto ISO/IEC 27001:2022 (sub-controls
  carry the ISO control number in the cross-reference, e.g. ``T7 (8.28)``).
- **DESC ISR v3.1** - thirteen domains ``D1``-``D13`` (Governance: D1-D3,
  Operation: D4-D8, Assurance: D9-D13).
- **ADDA / ADISSC** — Abu Dhabi Information Security Standards v2, twelve
  domains; the published standard numbers individual control
  specifications as ``SG.x`` (Security Governance), ``AC.x`` (Access
  Control), etc., so mappings reference the domain code plus requirement
  wording.
- **UAE CSC** — National Cloud Security Policy (NCSP), National Internet
  of Things Security Policy (NIP) and the CSC UAE IA Standard (ISO/IEC
  27001:2022 / NIST SP 800-53 / CIS-aligned). Cloud and IoT policies state
  principle-level requirements; the IA Standard provides implementable
  controls.
- **UAE PDPL** — Federal Decree-Law No. 45/2021 articles (e.g. ``Art. 20``
  security of processing, ``Art. 9`` breach notification, ``Art. 21``
  DPIA).
"""

from __future__ import annotations

from strix.compliance.models import ComplianceFramework, FrameworkKind


_FRAMEWORKS: dict[FrameworkKind, ComplianceFramework] = {
    "adda": ComplianceFramework(
        key="adda",
        name="Abu Dhabi Information Security Standards (ADSS)",
        version="v2",
        authority=(
            "Abu Dhabi Digital Authority (ADDA) / ADSIC / Department of "
            "Government Enablement"
        ),
        jurisdiction=(
            "All Abu Dhabi Government Entities and business partners handling "
            "government information"
        ),
        reference="ADSS v2 — Abu Dhabi Information Security Standards (ADSIC/ADDA)",
        domains=(
            "Information Security Governance (SG)",
            "Personnel Security (PS)",
            "Physical and Environmental Security (PE)",
            "Asset Management (AM)",
            "Access Control (AC)",
            "Human Resource Security (HR)",
            "Network & Communications Security (CN)",
            "Cryptography (CR)",
            "Operations Management (OM)",
            "Information Systems Acquisition, Development & Maintenance (SD)",
            "Information Security Incident Management (IR)",
            "Business Continuity (BC)",
            "Compliance & Legal (CM)",
            "Third-Party Security (TP)",
            "Security Audit & Monitoring (LG)",
        ),
    ),
    "nesa": ComplianceFramework(
        key="nesa",
        name="UAE Information Assurance Standards (IAS)",
        version="v1 (v2 rebased on ISO/IEC 27001:2022)",
        authority="National Electronic Security Authority (NESA) / UAE Cyber Security Council",
        jurisdiction="UAE critical national infrastructure, federal entities, and sector entities",
        reference="UAE Information Assurance Regulation / IAS (NESA, NIAF)",
        domains=(
            "M1 Strategy and Planning",
            "M2 Information Security Risk Management",
            "M3 Awareness and Training",
            "M4 Human Resources Security",
            "M5 Compliance",
            "M6 Performance Evaluation and Improvement",
            "T1 Information Asset Management",
            "T2 Physical and Environmental Security",
            "T3 Operations Management",
            "T4 Communications / Network Security",
            "T5 Access Control",
            "T6 Third-Party Security",
            "T7 IS Acquisition, Development and Maintenance",
            "T8 Information Security Incident Management",
            "T9 Information Systems Continuity Management",
        ),
    ),
    "desc": ComplianceFramework(
        key="desc",
        name="Dubai Information Security Regulation (ISR)",
        version="v3.1",
        authority="Dubai Electronic Security Center (DESC), Digital Dubai",
        jurisdiction=(
            "All Dubai Government Entities, their employees, consultants, "
            "contractors and suppliers"
        ),
        reference="DESC Information Security Regulation (ISR) v3.1, Dubai Law No. 11 of 2014",
        domains=(
            "D1 Information Security Management and Governance",
            "D2 Information and Information Assets Management",
            "D3 Information Security Risk Management",
            "D4 Incident and Problem Management",
            "D5 Access Control",
            "D6 Operation, Systems and Communication Management",
            "D7 Business Continuity Planning",
            "D8 Information Systems Acquisition, Development and Management",
            "D9 Compliance Management",
            "D10 Human Resources Security",
            "D11 Physical and Environmental Security",
            "D12 Third Party Management",
            "D13 Monitoring, Audit and Review",
        ),
    ),
    "csc": ComplianceFramework(
        key="csc",
        name="UAE Cybersecurity Council Cloud & IoT Security Package",
        version="2023 (NCSP, NIP) + IA Standard",
        authority="UAE Cyber Security Council",
        jurisdiction=(
            "UAE federal government entities, critical information "
            "infrastructure, cloud service providers and IoT providers"
        ),
        reference=(
            "National Cloud Security Policy (2023); National Policy for Internet "
            "of Things (IoT) Security (2023); UAE IA Standard (CSC)"
        ),
        domains=(
            "NCSP-1 Secure cloud adoption and risk assessment",
            "NCSP-2 Data security and privacy in cloud services",
            "NCSP-3 Secure cloud architecture and operations",
            "NCSP-4 Incident response and cloud business resilience",
            "NCSP-5 Cloud procurement and service provider assurance",
            "NIP-1 IoT security by design and device lifecycle",
            "NIP-2 Secure IoT communication and data protection",
            "NIP-3 IoT identity, access and authentication",
            "NIP-4 IoT vulnerability management and patching",
            "NIP-5 Risk-appropriate IoT security measures (CII)",
            "IA Standard — ISO/IEC 27001:2022-aligned controls (CSC)",
        ),
    ),
    "pdpl": ComplianceFramework(
        key="pdpl",
        name="Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data (UAE PDPL)",
        version="2021 (with Executive Regulations)",
        authority="UAE Data Protection Office",
        jurisdiction=(
            "All controllers and processors of personal data in the UAE "
            "(excluding DIFC/ADGM free zones)"
        ),
        reference="Federal Decree-Law No. 45 of 2021 on the Protection of Personal Data",
        domains=(
            "Art. 9 Reporting a Personal Data Breach",
            (
                "Art. 20 Security of Personal Data (encryption, "
                "pseudonymisation, CIA, availability, testing)"
            ),
            "Art. 21 Personal Data Protection Impact Assessment",
            "Data subject rights and consent (Arts. 4-13)",
            "Cross-border transfer and processing restrictions",
        ),
    ),
}


def framework_registry() -> dict[FrameworkKind, ComplianceFramework]:
    """Return the registry of supported UAE compliance frameworks."""
    return dict(_FRAMEWORKS)


def get_framework(key: FrameworkKind) -> ComplianceFramework:
    """Look up one framework by its key (``adda``, ``nesa``, ``desc``, ``csc``, ``pdpl``)."""
    return _FRAMEWORKS[key]
