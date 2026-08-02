"""
Remediator
----------
Takes the clean (threat-free) text lines the Scout Agent extracted and
rebuilds a brand-new, standard PDF from scratch. We don't try to "edit
out" the bad parts of the original file — we throw the whole contaminated
file structure away and generate a fresh one. That's what makes this a
zero-trust remediation instead of a patch.
"""

from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def generate_patched_pdf(clean_lines: list[str]) -> BytesIO:
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(
        pdf_buffer, pagesize=letter,
        rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40,
    )
    styles = getSampleStyleSheet()
    normal_style = ParagraphStyle(
        "CleanText", parent=styles["Normal"],
        fontSize=10, leading=14, textColor="#000000",
    )

    story = []
    for line in clean_lines:
        if line:
            story.append(Paragraph(line, normal_style))
            story.append(Spacer(1, 6))

    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer
