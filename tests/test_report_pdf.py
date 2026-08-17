"""Tests for building and encrypting the viewer PDF report."""

from __future__ import annotations

import json
from io import BytesIO
from typing import TYPE_CHECKING

import pytest
from pypdf import PdfReader
from pypdf.errors import WrongPasswordError

from strix.interface.viewer.report_pdf import (
    build_encrypted_report,
    encrypt_pdf,
    generate_password,
    generate_report_pdf,
)


if TYPE_CHECKING:
    from pathlib import Path


def _make_run(base: Path, name: str = "sample") -> Path:
    run_dir = base / "strix_runs" / name
    run_dir.mkdir(parents=True)
    record = {
        "run_name": name,
        "targets_info": [{"original": "https://example.com"}],
        "scan_mode": "deep",
        "status": "completed",
        "start_time": "2026-01-01T00:00:00Z",
        "end_time": "2026-01-01T01:02:03Z",
        "scan_results": {
            "executive_summary": "Summary with an ampersand & an <angle> bracket.",
            "recommendations": "Patch things.",
        },
    }
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    vulns = [
        {
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "User input reaches the query.",
            "impact": "Full database read.",
            "technical_analysis": "Details here.",
            "poc_description": "Send a crafted parameter.",
            "poc_script_code": "print('exploit')",
            "evidence": "HTTP 500 with SQL error.",
            "remediation_steps": ["Use parameterized queries", "Validate input"],
            "target": "https://example.com",
            "endpoint": "/login",
            "method": "POST",
        },
        {"title": "Informational note", "severity": "info"},
    ]
    (run_dir / "vulnerabilities.json").write_text(json.dumps(vulns), encoding="utf-8")
    return run_dir


def test_generate_report_pdf_has_pdf_header(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_generate_report_pdf_orders_findings_highest_severity_first(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    # Deliberately rewrite the index in discovery order (low severity first)
    # to prove the PDF sorts on its own.
    vulns = json.loads((run_dir / "vulnerabilities.json").read_text(encoding="utf-8"))
    vulns.reverse()
    (run_dir / "vulnerabilities.json").write_text(json.dumps(vulns), encoding="utf-8")

    pdf = generate_report_pdf(run_dir)
    reader = PdfReader(BytesIO(pdf))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    findings = text[text.index("Findings") :]
    assert findings.index("SQL Injection") < findings.index("Informational note")


def _link_dest_pages(reader: PdfReader) -> dict[int, list[int]]:
    """Map each page index to the page indices its Link annotations point at.

    reportlab resolves named destinations at save time, so each link
    annotation carries a ``/Dest [page_ref /Fit]`` array rather than a name.
    """
    targets: dict[int, list[int]] = {}
    for index, page in enumerate(reader.pages):
        annots = page.get("/Annots")
        if not annots:
            continue
        for annot in annots:
            dest = annot.get_object().get("/Dest")
            if not isinstance(dest, list) or not dest:
                continue
            for dest_index, dest_page in enumerate(reader.pages):
                if dest_page.indirect_reference == dest[0]:
                    targets.setdefault(index, []).append(dest_index)
                    break
    return targets


def test_generate_report_pdf_has_clickable_table_of_contents(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    reader = PdfReader(BytesIO(pdf))

    pages = [page.extract_text() or "" for page in reader.pages]
    toc_index = next(i for i, page in enumerate(pages) if "Table of Contents" in page)
    toc_text = pages[toc_index]
    assert "SQL Injection" in toc_text
    assert "Informational note" in toc_text
    assert "CRITICAL" in toc_text

    dests = _link_dest_pages(reader)
    links = dests.get(toc_index, [])
    assert len(links) >= 3
    # Every TOC link must actually jump to a later section/finding page.
    assert all(target > toc_index for target in links)
    targets_text = [pages[target] for target in set(links)]
    assert any("Executive Summary" in text for text in targets_text)
    assert any("Findings" in text for text in targets_text)
    assert any("SQL Injection" in text for text in targets_text)


def _outline_titles(entries: object) -> list[str]:
    titles: list[str] = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict):
            title = entry.get("/Title")
            if title:
                titles.append(title)
        elif isinstance(entry, list):
            titles.extend(_outline_titles(entry))
        elif hasattr(entry, "title") and getattr(entry, "title"):  # noqa: B009 - entry is object
            titles.append(getattr(entry, "title"))  # noqa: B009
    return titles


def _outline_pages(reader: PdfReader) -> dict[str, int]:
    """Map outline titles to the page index their bookmark points at."""
    targets: dict[str, int] = {}
    for entry in _outline_items(reader.outline):
        page_ref = entry.get("/Page")
        if not page_ref:
            continue
        for index, page in enumerate(reader.pages):
            if page.indirect_reference == page_ref:
                targets[entry["/Title"]] = index
                break
    return targets


def _outline_items(entries: object) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict):
            items.append(entry)
            kids = entry.get("/Kids")
            if kids:
                items.extend(_outline_items([kid.get_object() for kid in kids]))
        elif isinstance(entry, list):
            items.extend(_outline_items(entry))
    return items


def test_generate_report_pdf_outline_bookmarks_are_registered(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    reader = PdfReader(BytesIO(pdf))
    titles = _outline_titles(reader.outline)
    assert "Table of Contents" in titles
    assert "Executive Summary" in titles
    assert "Findings" in titles
    assert any(title.startswith("1. ") for title in titles)

    pages = [page.extract_text() or "" for page in reader.pages]
    outline_pages = _outline_pages(reader)
    toc_index = next(i for i, text in enumerate(pages) if "Table of Contents" in text)
    assert outline_pages["Executive Summary"] > toc_index
    assert "Executive Summary" in pages[outline_pages["Executive Summary"]]
    assert "Findings" in pages[outline_pages["Findings"]]


def test_generate_password_is_long_and_random() -> None:
    first = generate_password()
    second = generate_password()
    assert len(first) >= 20
    assert first != second


def test_encrypt_pdf_roundtrip(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    pdf = generate_report_pdf(run_dir)
    password = generate_password()
    encrypted = encrypt_pdf(pdf, password)

    reader = PdfReader(BytesIO(encrypted))
    assert reader.is_encrypted
    assert reader.decrypt(password)
    # A correct password unlocks the pages.
    assert len(reader.pages) >= 1


def test_wrong_password_is_rejected(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path)
    encrypted = encrypt_pdf(generate_report_pdf(run_dir), "correct-horse-battery")
    with pytest.raises(WrongPasswordError):
        PdfReader(BytesIO(encrypted), password="not-the-password")  # nosec B106


def test_build_encrypted_report(tmp_path: Path) -> None:
    run_dir = _make_run(tmp_path, name="run-42")
    pdf_bytes, password, filename = build_encrypted_report(run_dir)

    assert filename == "strix-report-run-42.pdf"
    assert len(password) >= 20
    reader = PdfReader(BytesIO(pdf_bytes))
    assert reader.is_encrypted
    assert reader.decrypt(password)
