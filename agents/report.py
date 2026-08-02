"""
Incident Report
----------------
Turns the Warden Agent's raw incident log (a .jsonl file of individual
scan events) into a proper, presentable PDF report — the kind of thing
a real security team would print out or attach to an email, not just a
list of JSON objects.
"""

from io import BytesIO
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_incident_report_pdf(entries: list[dict]) -> BytesIO:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=20, textColor="#14171c",
    )
    meta_style = ParagraphStyle(
        "ReportMeta", parent=styles["Normal"], fontSize=9.5, textColor="#5b6577",
    )
    section_style = ParagraphStyle(
        "SectionHead", parent=styles["Heading2"], fontSize=13, spaceBefore=18, spaceAfter=8,
    )

    story = []
    story.append(Paragraph("DocGuard AI — Sentinel", title_style))
    story.append(Paragraph("Warden Agent Incident Report", styles["Heading3"]))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(f"Generated: {generated_at}", meta_style))
    story.append(Spacer(1, 16))

    total = len(entries)
    threats = sum(1 for e in entries if e.get("verdict") == "THREAT")
    clean = total - threats

    story.append(Paragraph("Summary", section_style))
    summary_table = Table(
        [
            ["Total documents processed", str(total)],
            ["Threats detected", str(threats)],
            ["Clean documents", str(clean)],
        ],
        colWidths=[260, 120],
    )
    summary_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Incident Log", section_style))

    if not entries:
        story.append(Paragraph("No incidents recorded yet.", styles["Normal"]))
    else:
        table_data = [["Timestamp (UTC)", "File", "Verdict", "Threat Score", "Anomalies"]]
        for e in entries:
            ts = e.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                pass
            table_data.append([
                ts,
                e.get("file", ""),
                e.get("verdict", ""),
                str(e.get("threat_score", "")),
                str(e.get("anomaly_count", "")),
            ])

        log_table = Table(table_data, colWidths=[110, 170, 60, 70, 70], repeatRows=1)
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#14171c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ]
        for row_idx, e in enumerate(entries, start=1):
            if e.get("verdict") == "THREAT":
                style_commands.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), colors.HexColor("#c0392b")))
            else:
                style_commands.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), colors.HexColor("#1f7a8c")))
        log_table.setStyle(TableStyle(style_commands))
        story.append(log_table)

    doc.build(story)
    buffer.seek(0)
    return buffer
