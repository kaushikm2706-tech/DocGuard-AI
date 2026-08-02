"""
DocGuard AI: Sentinel — Flask backend

Routes:
  GET  /                 -> the UI (templates/index.html)
  POST /api/scan         -> upload a PDF, get back Scout's findings
                            + Interrogator's plain-English narratives
                            + an Attack Replay script per anomaly
  POST /api/sanitize     -> upload a PDF, get back the cleaned PDF file
  POST /api/warden/start -> start the Warden Agent (folder watcher)
  POST /api/warden/stop  -> stop the Warden Agent
  GET  /api/warden/log   -> the Warden's incident log (for the live feed)
"""

import os
import json
import uuid
from io import BytesIO
from flask import Flask, request, jsonify, send_file, render_template

from agents.scout import scan
from agents.interrogator import interrogate
from agents.remediator import generate_patched_pdf
from agents.replay import simulate_naive_compliance
from agents.report import generate_incident_report_pdf
from agents.warden import Warden, LOG_PATH, WATCH_DIR

app = Flask(__name__)

# One shared Warden instance for the whole app (single-user demo scope).
_warden = Warden()

# Short-lived, in-memory-only cache: after a batch scan, we hold each
# file's raw bytes just long enough for the person to click "download
# sanitized" on any flagged result without re-uploading it. Nothing here
# ever touches disk, and it's cleared/replaced on every new batch scan —
# it's a convenience cache for the current session, not storage.
_batch_cache = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    file_bytes = file.read()

    result = scan(file_bytes)

    # For each anomaly: get the Interrogator's plain-English narrative
    # AND the Attack Replay script, so the frontend has everything it
    # needs in one response.
    enriched_anomalies = []
    for anomaly in result["anomalies"]:
        narrative = interrogate(anomaly["text"])
        replay = simulate_naive_compliance(anomaly["text"])
        enriched_anomalies.append({
            **anomaly,
            "narrative": narrative["narrative"],
            "narrative_mode": narrative["mode"],
            "replay": replay,
        })

    return jsonify({
        "threat_score": result["threat_score"],
        "stats": result["stats"],
        "anomalies": enriched_anomalies,
        "clean_line_count": len([l for l in result["clean_lines"] if l]),
        "filename": file.filename,
    })


@app.route("/api/scan/batch", methods=["POST"])
def api_scan_batch():
    """
    Same forensic pipeline as /api/scan, but for multiple files at once.
    Expects each file under the form field name 'files' (repeated).
    Returns a list of per-file results in the order they were uploaded.
    """
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files uploaded"}), 400

    _batch_cache.clear()  # only the most recent batch's files stay cached

    batch_results = []
    for file in files:
        file_bytes = file.read()
        try:
            result = scan(file_bytes)
        except Exception as e:
            batch_results.append({
                "filename": file.filename,
                "error": f"Could not parse this file: {e}",
            })
            continue

        enriched_anomalies = []
        for anomaly in result["anomalies"]:
            narrative = interrogate(anomaly["text"])
            replay = simulate_naive_compliance(anomaly["text"])
            enriched_anomalies.append({
                **anomaly,
                "narrative": narrative["narrative"],
                "narrative_mode": narrative["mode"],
                "replay": replay,
            })

        file_id = uuid.uuid4().hex
        _batch_cache[file_id] = {"filename": file.filename, "bytes": file_bytes}

        batch_results.append({
            "id": file_id,
            "filename": file.filename,
            "threat_score": result["threat_score"],
            "stats": result["stats"],
            "anomalies": enriched_anomalies,
            "clean_line_count": len([l for l in result["clean_lines"] if l]),
        })

    return jsonify({"results": batch_results})


@app.route("/api/sanitize/<file_id>")
def api_sanitize_cached(file_id):
    cached = _batch_cache.get(file_id)
    if not cached:
        return jsonify({"error": "This file is no longer available. Please re-scan the batch."}), 404

    result = scan(cached["bytes"])
    patched = generate_patched_pdf(result["clean_lines"])

    return send_file(
        patched,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"sanitized_{cached['filename']}",
    )


@app.route("/api/sanitize", methods=["POST"])
def api_sanitize():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    file_bytes = file.read()

    result = scan(file_bytes)
    patched = generate_patched_pdf(result["clean_lines"])

    return send_file(
        patched,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"sanitized_{file.filename}",
    )


@app.route("/api/warden/start", methods=["POST"])
def warden_start():
    _warden.start()
    return jsonify({"running": True, "watch_dir": WATCH_DIR})


@app.route("/api/warden/stop", methods=["POST"])
def warden_stop():
    _warden.stop()
    return jsonify({"running": False})


@app.route("/api/warden/status")
def warden_status():
    return jsonify({"running": _warden.is_running, "watch_dir": WATCH_DIR})


def _load_log_entries():
    entries = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    return entries


@app.route("/api/warden/log")
def warden_log():
    entries = _load_log_entries()
    return jsonify({"entries": entries[-50:]})  # last 50 events


@app.route("/api/warden/report/json")
def warden_report_json():
    entries = _load_log_entries()
    buffer = BytesIO(json.dumps({"entries": entries}, indent=2).encode("utf-8"))
    return send_file(
        buffer, mimetype="application/json",
        as_attachment=True, download_name="docguard_incident_report.json",
    )


@app.route("/api/warden/report/pdf")
def warden_report_pdf():
    entries = _load_log_entries()
    pdf_buffer = generate_incident_report_pdf(entries)
    return send_file(
        pdf_buffer, mimetype="application/pdf",
        as_attachment=True, download_name="docguard_incident_report.pdf",
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)