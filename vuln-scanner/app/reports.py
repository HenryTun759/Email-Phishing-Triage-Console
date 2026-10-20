from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import mm


def build_scan_pdf(scan) -> BytesIO:
    out = BytesIO()
    doc = SimpleDocTemplate(out, pagesize=A4, rightMargin=15*mm, leftMargin=15*mm, topMargin=15*mm, bottomMargin=15*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("LabVuln Security Assessment Report", styles["Title"]), Spacer(1, 8)]
    story.append(Paragraph(f"Scan #{scan.id} — {scan.target.name} ({scan.target.host}:{scan.target.port})", styles["Heading2"]))
    story.append(Paragraph(f"Status: {scan.status} | Findings: {len(scan.findings)}", styles["BodyText"]))
    story.append(Spacer(1, 12))
    rows = [["Severity", "CVSS", "Finding", "Evidence", "Remediation"]]
    for f in sorted(scan.findings, key=lambda x: x.cvss_score or 0, reverse=True):
        rows.append([f.severity.upper(), f"{f.cvss_score:.1f}" if f.cvss_score is not None else "—", f.title, f.evidence[:180], f.remediation[:220]])
    if len(rows) == 1:
        rows.append(["—", "—", "No findings", "No issues were identified by the enabled checks.", "Continue routine scanning and patch management."])
    table = Table(rows, repeatRows=1, colWidths=[20*mm, 15*mm, 42*mm, 52*mm, 48*mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#172033")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), .25, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 7),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    story.append(table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Scope: authorized lab assessment only. This report contains results from non-destructive checks and is not a substitute for a comprehensive penetration test.", styles["Italic"]))
    doc.build(story)
    out.seek(0)
    return out
