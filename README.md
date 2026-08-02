# DocGuard AI: Sentinel

A zero-trust document security framework that detects **and explains** hidden
prompt-injection attacks inside PDFs — built for MLH Global Hack Week: Agents.

Most PDF text scrapers flatten a document's layout and only read what's
*meant* to be seen. That's exactly the gap an attacker can exploit: hiding an
instruction in 1-point font, or in text colored the same as the page
background, so a human never notices it — but an AI system reading the file
still will. Sentinel inspects PDFs at the raw character-object layer instead,
so nothing invisible stays invisible.

## Three agents, one pipeline

| Agent | Job |
|---|---|
| **Scout** | Forensic scanner. Reads every character's font size, color, and every hyperlink's target. Outputs a weighted 0–100 Threat Score instead of a binary yes/no. |
| **Interrogator** | Explains *intent*. Takes only the isolated suspicious snippet (never the whole document) and explains, in one plain-English sentence, what the hidden payload was trying to make an AI assistant do. Uses the Gemini API if a key is configured, otherwise falls back to a local rule-based explainer — the app always works, with or without an API key. |
| **Warden** | The autonomous piece. Watches a folder continuously; the moment a PDF is dropped in, it scans, decides, and files it — clean documents to `cleared/`, dangerous ones to `quarantine/` (plus an auto-generated sanitized copy) — with zero manual clicks. |

## Running it

```bash
pip install -r requirements.txt
python server.py
```

Then open `http://localhost:5000`.

### Optional: enable live AI narratives
By default the Interrogator Agent explains threats using a local rule-based
fallback (zero setup, zero cost, works offline). To use real Gemini-powered
explanations instead:

```bash
export GEMINI_API_KEY="your-key-here"   # get a free key at aistudio.google.com
python server.py
```

### Trying the Warden Agent
1. Click **Activate Warden** in the UI.
2. Drop any PDF into `warden_workspace/incoming/`.
3. Watch the Incident Feed update automatically — no button click needed.
4. Check `warden_workspace/cleared/` or `warden_workspace/quarantine/` to see
   where it filed the document.

## Project structure

```
docguard-sentinel/
├── server.py              # Flask app + API routes
├── agents/
│   ├── scout.py            # forensic scanner + threat scoring
│   ├── interrogator.py      # plain-English threat narratives (Gemini or offline)
│   ├── remediator.py        # rebuilds a clean PDF from scratch
│   ├── replay.py            # "Attack Replay" simulation script generator
│   └── warden.py            # autonomous folder watcher
├── templates/index.html    # UI shell
├── static/style.css        # design system
└── static/script.js        # frontend logic + D3 threat graph
```

## What makes this different from a typical "PDF scanner" project
- **Threat scoring, not a binary flag** — severity is visible and tunable.
- **Interrogator explains intent**, not just location — a judge doesn't need
  to be a security expert to understand what an attack was trying to do.
- **Attack Replay** makes an invisible attack visible: a sandboxed, scripted
  side-by-side showing what a naive AI assistant would have done versus what
  Sentinel actually did — built from the real detected payload, not a canned
  demo script.
- **Warden is a real agent**, not a metaphor — it watches, decides, and acts
  with no human in the loop, which is the actual theme of this hackathon week.

## Tech stack
Python, Flask, pdfplumber, ReportLab, watchdog, vanilla JS, D3.js.
