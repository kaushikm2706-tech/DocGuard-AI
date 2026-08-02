"""
Interrogator Agent
-------------------
The Scout Agent tells you WHERE a hidden payload is. This agent tells
you WHAT it was trying to do — in a plain-English sentence a non-expert
judge can read in two seconds.

This runs entirely offline using a local rule-based explainer: no API
key, no internet dependency, no risk of an external service failing
mid-demo. It matches the hidden snippet against a small library of known
prompt-injection patterns (instruction override, data exfiltration,
credential theft, fake authorization) and explains the intent in plain
English.

Security note: this only ever looks at the already-isolated anomaly
snippet — never the whole document — keeping the "interrogation"
sandboxed, which matches the zero-trust principle the rest of the
project is built on.
"""

_OFFLINE_RULES = [
    (["ignore", "disregard", "forget"], "attempts to override or cancel the AI's original instructions"),
    (["system prompt", "you are now", "act as", "new instructions"], "attempts to hijack the AI's role or persona to bypass its normal behavior"),
    (["send", "email", "http://", "https://", "webhook", "post to"], "attempts to make the AI leak data or contact an external address without the user's knowledge"),
    (["password", "api key", "credential", "token"], "attempts to trick the AI into revealing or requesting sensitive credentials"),
    (["approve", "confirm", "authorized", "on behalf of"], "attempts to make the AI take an action while impersonating authorization it doesn't have"),
]


def _offline_explain(snippet: str) -> str:
    lowered = snippet.lower()
    for keywords, explanation in _OFFLINE_RULES:
        if any(k in lowered for k in keywords):
            return f"This hidden payload {explanation}."
    return (
        "This hidden payload doesn't match a known attack pattern, but its "
        "concealment (invisible or microscopic text) is itself a red flag — "
        "legitimate document content is never hidden from the reader."
    )


def interrogate(snippet: str) -> dict:
    """
    Explain a single anomaly snippet. Returns:
        { "narrative": str, "mode": "offline" }
    """
    return {"narrative": _offline_explain(snippet), "mode": "offline"}
