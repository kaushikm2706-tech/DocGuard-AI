Here is the condensed text, optimized to fit perfectly under LinkedIn's 2,000-character limit while retaining every piece of high-impact technical detail.

---

Designed and developed DocGuard AI, a zero-trust document security framework engineered to neutralize indirect prompt injections within automated enterprise LLM workflows. While standard text-scrapers flatten document layouts and miss obfuscated payloads hidden in files, this system intercepts stealth threats at the raw object layer before they reach the model gateway.

Key Technical Implementations & Core Architecture:

1. Low-Level Character Object Inspection: Bypassed basic text extraction to eliminate layout data loss. Engineered an inspection pipeline using pdfplumber to analyze individual character tokens (page.chars) on a precise coordinate grid, evaluating physical rendering traits directly.
2. Visual Obfuscation Countermeasures: Programmed multi-matrix heuristic gates to evaluate RGB/CMYK color channel densities and typography scale. Successfully exposes hidden micro-text (<= 2.0 pt) and invisible, white-on-white text layers used to covertly hijack model logic.
3. Structural Annotation Verification: Implemented an annotation loop targeting the PDF’s internal /Annots dictionary (page.hyperlinks). Tracks underlying interactive hitboxes to expose malicious, masked URI redirection chains and unencrypted transport layer vulnerabilities (http://).
4. Active Reconstructive Remediation: Developed an automated sanitization pipeline via reportlab. Upon threat gate trigger, the system completely discards the contaminated file structure, extracts the legitimate text layers, and synthesizes a brand-new, standard-compliant PDF from scratch with forced high-contrast black text models.
5. Volatile In-Memory Architecture: Optimized throughput and minimized local system exploit surfaces by routing the entire ingestion, parsing, and remediation pipeline cleanly through in-memory byte streams (io.BytesIO) rather than saving temporary files to disk.

Technical Architecture: Python, Streamlit Production Cloud, pdfplumber, ReportLab, GitHub, PyCharm IDE.
