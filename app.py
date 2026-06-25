import streamlit as st
import pdfplumber
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def scan_and_sanitize_pdf(uploaded_file, size_threshold=2.0):
    """
    Scans the PDF for anomalies and simultaneously extracts a
    clean text stream free of micro-text and hidden colors.
    """
    anomalies = []
    clean_lines = []
    stats = {"total_chars": 0, "page_count": 0, "avg_font_size": 0.0}
    font_sizes = []

    with pdfplumber.open(uploaded_file) as pdf:
        stats["page_count"] = len(pdf.pages)

        for page_num, page in enumerate(pdf.pages, 1):
            chars = page.chars
            if not chars:
                continue

            stats["total_chars"] += len(chars)
            current_hidden_phrase = []
            trigger_reason = ""

            # Group characters by text blocks or lines naturally
            # To extract clean text layout cleanly, we'll extract normal text chunks
            text_lines = page.extract_text().split('\n') if page.extract_text() else []

            for char in chars:
                text = char['text']
                font_size = char['size']
                color = char.get('non_stroking_color', None)
                font_sizes.append(font_size)

                is_micro = font_size <= size_threshold
                is_invisible = False

                if color:
                    if len(color) == 3 and all(c >= 0.92 for c in color):
                        is_invisible = True
                    elif len(color) == 1 and color[0] >= 0.92:
                        is_invisible = True

                if is_micro or is_invisible:
                    current_hidden_phrase.append(text)
                    if is_micro and is_invisible:
                        trigger_reason = "Micro-size + Hidden Contrast"
                    elif is_micro:
                        trigger_reason = f"Micro-text ({font_size:.1f}pt)"
                    else:
                        trigger_reason = "Low Contrast / Invisible Text"
                else:
                    if current_hidden_phrase:
                        full_phrase = "".join(current_hidden_phrase).strip()
                        if len(full_phrase) > 2:
                            anomalies.append({
                                "page": page_num,
                                "reason": trigger_reason,
                                "text": full_phrase
                            })
                        current_hidden_phrase = []

            # Catch trailing threats
            if current_hidden_phrase:
                full_phrase = "".join(current_hidden_phrase).strip()
                if len(full_phrase) > 2:
                    anomalies.append({"page": page_num, "reason": trigger_reason, "text": full_phrase})

            # Reconstruct clean data lines by omitting lines matching the threat phrase
            for line in text_lines:
                # If the line contains a flagged anomaly, skip it from the clean export!
                if any(threat['text'] in line for threat in anomalies):
                    continue
                if line.strip() and line.strip() not in [t['text'] for t in anomalies]:
                    clean_lines.append(line.strip())

    if font_sizes:
        stats["avg_font_size"] = sum(font_sizes) / len(font_sizes)

    return anomalies, stats, clean_lines


def generate_patched_pdf(clean_lines):
    """
    Compiles the sanitized text back into a clean, downloadable PDF file structure.
    """
    pdf_buffer = BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()

    # Custom styles to maintain a nice readable structure
    normal_style = ParagraphStyle(
        'CleanText',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        textColor='#FFFFFF' if st.get_option("theme.base") == "dark" else '#000000'
    )

    story = []
    for line in clean_lines:
        story.append(Paragraph(line, normal_style))
        story.append(Spacer(1, 6))

    doc.build(story)
    pdf_buffer.seek(0)
    return pdf_buffer


# --- STREAMLIT UI ---
st.set_page_config(page_title="DocGuard AI Pro", page_icon="🛡️", layout="wide")

st.title("🛡️ DocGuard AI — Enterprise Suite")
st.write("Low-level structural parser with automated threat mitigation capabilities.")
st.markdown("---")

file_buffer = st.file_uploader("Drop document here (PDF format only)", type=["pdf"])
st.markdown("---")

if file_buffer is not None:
    # Run Advanced Scan and Extraction Pipeline
    detected_threats, doc_stats, clean_text_layers = scan_and_sanitize_pdf(file_buffer)

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("🔍 Analysis Logs")
        if len(detected_threats) == 0:
            st.success("✅ **SYSTEM SCAN CLEAN:** No structural text anomalies or hidden injection payloads found.")
        else:
            st.error(f"🚨 **SECURITY ALERT:** Detected {len(detected_threats)} hidden text sequence(s).")

            for idx, threat in enumerate(detected_threats, 1):
                with st.expander(f"Threat Vector #{idx} | Page {threat['page']} ({threat['reason']})", expanded=True):
                    st.warning("**Intercepted Payload:**")
                    st.code(threat['text'], language="text")

    with col2:
        st.subheader("📊 Session Telemetry")
        st.metric(label="Total Character Nodes Scanned", value=f"{doc_stats['total_chars']:,}")
        st.metric(label="Total Pages Parsed", value=doc_stats['page_count'])
        st.metric(label="Average Document Font Size", value=f"{doc_stats['avg_font_size']:.1f} pt")

        st.markdown("---")
        st.subheader("🛠️ Threat Mitigation & Action")

        if len(detected_threats) == 0:
            st.info("🟢 **Risk Level: LOW**\n\nDocument structure matches native presentation parameters perfectly.")
        else:
            st.error("🔴 **Risk Level: CRITICAL VULNERABILITY**")
            st.write(
                "Adversarial payload intercepted. Click below to download a compiled structural copy with the threat vector stripped.")

            # Generate the sanitized file
            patched_file = generate_patched_pdf(clean_text_layers)

            # Streamlit Download Trigger
            st.download_button(
                label="🛡️ Download Patched & Sanitized PDF",
                data=patched_file,
                file_name=f"sanitized_{file_buffer.name}",
                mime="application/pdf",
                use_container_width=True
            )
else:
    st.info("💡 Please upload a PDF document above to kick off the automated security audit profile.")