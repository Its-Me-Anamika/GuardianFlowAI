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
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "playbooks")

THREAT_TYPE_TO_PLAYBOOK = {
    "cryptomining": "cryptomining.txt",
    "bruteforce": "bruteforce.txt",
    "ddos": "ddos.txt",
}

client = OpenAI(
    api_key=os.getenv("GROQ_API_KEY"),
    base_url="https://api.groq.com/openai/v1"
)

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
    f"You are a cybersecurity SOC analyst.\n\n"

    f"Threat: {threat_type}\n"
    f"Severity: {threat_level}\n"
    f"Reason: {reason}\n\n"

    f"Playbook:\n{playbook_text}\n\n"

    "Respond ONLY in this format:\n\n"

    "Explanation:\n"
    "Write ONLY 2 short sentences explaining the threat in simple English.\n\n"

    "Actions:\n"
    "- action 1\n"
    "- action 2\n"
    "- action 3\n\n"

    "Put EACH action on a NEW LINE.\n"
    "Do NOT write everything in one paragraph.\n"
    "Do NOT use markdown (** or #).\n"
    "Do NOT use **.\n"
    "Do NOT repeat anything."
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
        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[
                {
                    "role": "system",
                    "content": "You are a cybersecurity incident response assistant."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.3
        )

        explanation_text = response.choices[0].message.content.strip()
    except Exception as e:
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
