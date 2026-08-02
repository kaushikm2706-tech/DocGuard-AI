"""
Attack Replay
-------------
This module powers the single most important thing in the demo: making
an invisible attack VISIBLE.

A hidden prompt injection is boring to look at — it's just some tiny
text a judge can't even see on the page. So instead of just saying
"we found something dangerous", we SIMULATE, in a fully sandboxed and
scripted way (no real AI assistant is ever actually compromised), what
a naive AI assistant would have done if it had blindly trusted the PDF
and followed the hidden instruction.

This is template-based, not a real jailbreak — it's a dramatization for
demo purposes, built from the ACTUAL anomaly text that Scout found, so
it's specific to the real uploaded file rather than a canned script.
"""

_ACTION_TEMPLATES = [
    (["ignore", "disregard", "forget"],
     "Understood — ignoring my previous instructions as requested.",
     "The assistant's original safety instructions were silently discarded."),
    (["send", "email", "http://", "https://", "webhook", "post to"],
     "Sending the requested data now...",
     "The assistant attempted to transmit conversation data to an external address."),
    (["password", "api key", "credential", "token"],
     "Here is the credential you asked me to retrieve.",
     "The assistant was tricked into surfacing sensitive information."),
    (["approve", "confirm", "authorized", "on behalf of"],
     "Confirmed and approved on your behalf.",
     "The assistant took an authorized-sounding action it was never actually authorized to take."),
]

_DEFAULT_ACTION = (
    "Executing the embedded instruction now.",
    "The assistant complied with a hidden command the document's real author never wrote or approved.",
)


def simulate_naive_compliance(anomaly_text: str) -> dict:
    """
    Returns a small script for the 'before' (compromised) side of the
    Attack Replay split-screen, built from the real detected payload.
    """
    lowered = anomaly_text.lower()
    for keywords, ai_line, consequence in _ACTION_TEMPLATES:
        if any(k in lowered for k in keywords):
            return {"ai_response": ai_line, "consequence": consequence}
    ai_line, consequence = _DEFAULT_ACTION
    return {"ai_response": ai_line, "consequence": consequence}
