"""
Warden Agent
------------
This is the piece that turns DocGuard from a "tool you run" into an
actual AGENT: something that watches, decides, and acts on its own,
without a human clicking a button each time.

How it works, in plain English:
  1. You point it at a folder (e.g. "incoming_documents/").
  2. It sits there quietly, watching for new files to appear.
  3. The moment a PDF is dropped in, it wakes up automatically, runs
     the Scout Agent on it, and decides:
        - CLEAN  -> moves it to "cleared/"
        - THREAT -> moves the ORIGINAL dangerous file to "quarantine/"
                    and writes a sanitized replacement + an incident
                    report next to it.
  4. Every decision it makes gets logged to incident_log.jsonl so there's
     a paper trail of everything the agent has done on its own.

This file can be run two ways:
  - Imported by the Flask app, which starts it as a background thread
    when you click "Activate Warden" in the UI.
  - Run directly for a terminal-only demo: `python agents/warden.py`
"""

import os
import time
import json
import threading
from datetime import datetime, timezone
from io import BytesIO

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from agents.scout import scan
from agents.remediator import generate_patched_pdf

WATCH_DIR = "warden_workspace/incoming"
CLEARED_DIR = "warden_workspace/cleared"
QUARANTINE_DIR = "warden_workspace/quarantine"
LOG_PATH = "warden_workspace/incident_log.jsonl"

for _dir in (WATCH_DIR, CLEARED_DIR, QUARANTINE_DIR):
    os.makedirs(_dir, exist_ok=True)


def clear_workspace():
    """
    Wipes the incident log and any files that have piled up in cleared/
    and quarantine/ from previous runs — a fresh start for a demo,
    without touching whatever's currently sitting in incoming/ waiting
    to be processed. .gitkeep placeholders are preserved so the folder
    structure survives.
    """
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)

    for _dir in (CLEARED_DIR, QUARANTINE_DIR):
        for name in os.listdir(_dir):
            if name == ".gitkeep":
                continue
            path = os.path.join(_dir, name)
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except OSError:
                pass  # best-effort; a locked file here shouldn't block the rest


def _log_incident(entry: dict):
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _process_pdf(path: str, on_event=None):
    """Runs the full pipeline on one file and files it away."""
    filename = os.path.basename(path)
    try:
        with open(path, "rb") as f:
            file_bytes = f.read()
    except (FileNotFoundError, PermissionError):
        # File might still be mid-copy; caller retries.
        return

    result = scan(file_bytes)
    verdict = "THREAT" if result["threat_score"] > 0 else "CLEAN"

    if verdict == "CLEAN":
        dest = os.path.join(CLEARED_DIR, filename)
        os.replace(path, dest)
    else:
        # Quarantine the ORIGINAL dangerous file untouched (evidence).
        quarantined_path = os.path.join(QUARANTINE_DIR, filename)
        os.replace(path, quarantined_path)
        # Also drop a sanitized version next to it so the content is
        # still usable, just safe.
        sanitized = generate_patched_pdf(result["clean_lines"])
        with open(os.path.join(QUARANTINE_DIR, f"sanitized_{filename}"), "wb") as f:
            f.write(sanitized.read())

    entry = {
        "file": filename,
        "verdict": verdict,
        "threat_score": result["threat_score"],
        "anomaly_count": len(result["anomalies"]),
    }
    _log_incident(entry)
    if on_event:
        on_event(entry)


class _PDFDropHandler(FileSystemEventHandler):
    def __init__(self, on_event=None):
        self.on_event = on_event
        self._processing = set()  # guards against double-processing one path

    def _handle(self, path):
        if path in self._processing or not path.lower().endswith(".pdf"):
            return
        self._processing.add(path)
        try:
            time.sleep(0.5)  # let the file finish copying before we read it
            _process_pdf(path, self.on_event)
        finally:
            self._processing.discard(path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._handle(event.src_path)

    def on_modified(self, event):
        # Safety net: some filesystems report overwriting an existing
        # same-named file as a "modified" event rather than "created".
        if event.is_directory:
            return
        self._handle(event.src_path)


class Warden:
    """Wraps the watchdog Observer so the Flask app can start/stop it
    as a background thread from a UI button."""

    def __init__(self, on_event=None):
        self.on_event = on_event
        self._observer = None

    def start(self):
        if self._observer:
            return  # already running
        handler = _PDFDropHandler(self.on_event)
        self._observer = Observer()
        self._observer.schedule(handler, WATCH_DIR, recursive=False)
        self._observer.start()

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()
            self._observer = None

    @property
    def is_running(self):
        return self._observer is not None


if __name__ == "__main__":
    print(f"Warden Agent watching: {WATCH_DIR}")
    print("Drop a PDF in there. Press Ctrl+C to stop.")
    w = Warden(on_event=lambda e: print(f"[{e['verdict']}] {e['file']} (score {e['threat_score']})"))
    w.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        w.stop()