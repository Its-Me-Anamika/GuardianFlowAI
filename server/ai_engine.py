"""
ai_engine.py
-------------
Purpose: Implement a simple Retrieval-Augmented Generation (RAG) flow.
Before asking the LLM (Google Gemini) to explain a detected threat, we
first RETRIEVE the matching incident-response playbook text from the
playbooks/ folder and inject it into the prompt. This "grounds" the
explanation in our organization's specific protocols instead of
letting the model rely purely on generic training knowledge.

Set your Gemini API key as an environment variable before running:
    Windows (PowerShell):  $env:GEMINI_API_KEY="your_key_here"
"""

import os
import google.generativeai as genai

PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "playbooks")

# Maps detector.py's threat_type labels to playbook filenames.
# Anything not in this map falls back to a generic explanation.
THREAT_TYPE_TO_PLAYBOOK = {
    "cryptomining": "cryptomining.txt",
    "bruteforce": "bruteforce.txt",
    "ddos": "ddos.txt",
}

_GEMINI_CONFIGURED = False


def _configure_gemini():
    """Configure the Gemini client once, using the API key from env vars."""
    global _GEMINI_CONFIGURED
    if _GEMINI_CONFIGURED:
        return
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY environment variable not set. "
            "Set it before starting the server."
        )
    genai.configure(api_key=api_key)
    _GEMINI_CONFIGURED = True


def retrieve_playbook(threat_type: str) -> str:
    """
    RAG "Retrieval" step: load the plain-text incident response
    playbook that matches the detected threat type. Falls back to a
    generic message if no specific playbook exists for this type.
    """
    filename = THREAT_TYPE_TO_PLAYBOOK.get(threat_type)
    if not filename:
        return (
            "No specific playbook is available for this threat type. "
            "Apply general incident response best practices: isolate, "
            "investigate, remediate, and document."
        )

    filepath = os.path.join(PLAYBOOKS_DIR, filename)
    if not os.path.exists(filepath):
        return "Playbook file missing on disk."

    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()


def _build_prompt(threat_type: str, reason: str, threat_level: str, playbook_text: str) -> str:
    """
    RAG "Augmentation" step: build the final prompt that combines the
    live detection details with the retrieved playbook text.
    """
    return (
        f"Explain the following cybersecurity event in plain English.\n\n"
        f"Detected Threat Type: {threat_type}\n"
        f"Severity Level: {threat_level}\n"
        f"Detection Reason: {reason}\n\n"
        f"Use this specific incident response playbook as grounding context:\n"
        f"---\n{playbook_text}\n---\n\n"
        f"Based strictly on the playbook above, explain why this is dangerous "
        f"and recommend immediate mitigation steps. Keep the explanation "
        f"concise (5-8 sentences) and easy for a non-expert to understand. "
        f"Then list 3-5 recommended actions as short bullet points."
    )


def explain_threat(threat_type: str, reason: str, threat_level: str) -> dict:
    """
    Full RAG pipeline: retrieve the relevant playbook, augment the
    prompt with it, then generate the explanation via Gemini.

    Returns a dict with: explanation, risk, recommended_actions, playbook_used.
    """
    playbook_text = retrieve_playbook(threat_type)

    # If no threat, skip the LLM call entirely to save API quota
    if threat_type in (None, "None", "unknown_anomaly") and threat_level == "Low":
        return {
            "explanation": "No significant threat detected. System behavior is normal.",
            "risk": "None",
            "recommended_actions": [],
            "playbook_used": None,
        }

    prompt = _build_prompt(threat_type, reason, threat_level, playbook_text)

    try:
        _configure_gemini()
        model = genai.GenerativeModel("gemini-1.5-flash")
        response = model.generate_content(prompt)
        explanation_text = response.text.strip()
    except Exception as e:
        # Graceful fallback if the API key is missing or the call fails,
        # so the demo doesn't break if internet/API is unavailable.
        explanation_text = (
            f"[AI explanation unavailable: {e}]\n\n"
            f"Fallback summary from playbook:\n{playbook_text[:400]}..."
        )

    return {
        "explanation": explanation_text,
        "risk": threat_level,
        "recommended_actions": _extract_bullets(explanation_text),
        "playbook_used": THREAT_TYPE_TO_PLAYBOOK.get(threat_type, "generic"),
    }


def _extract_bullets(text: str) -> list:
    """
    Small helper to pull out bullet-style lines from the LLM response
    so the dashboard can render recommended actions as a clean list.
    """
    bullets = []
    for line in text.splitlines():
        stripped = line.strip(" -*\u2022")
        if line.strip().startswith(("-", "*", "\u2022")) and stripped:
            bullets.append(stripped)
    return bullets
