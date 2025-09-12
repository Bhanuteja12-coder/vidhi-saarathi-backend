import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from google import genai

# --------------------------
# Load Environment Variables
# --------------------------
load_dotenv()
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_KEY:
    raise EnvironmentError("❌ GEMINI_API_KEY is missing in .env")

# --------------------------
# Initialize Gemini Client
# --------------------------
client = genai.Client(api_key=GEMINI_KEY)

# --------------------------
# Flask App Setup
# --------------------------
app = Flask(__name__)
CORS(app)

# --------------------------
# Heuristics
# --------------------------
URGENT_KEYWORDS = {"threat", "violence", "injury", "arrest", "danger", "immediately"}
DOMAINS = {
    "Criminal": {"murder", "assault", "theft", "police", "crime"},
    "Family": {"divorce", "custody", "marriage", "dowry"},
    "Consumer": {"refund", "order", "delivery", "product", "payment"},
    "Civil": {"contract", "agreement", "negligence", "property"}
}

def simple_urgency(text: str) -> str:
    text = text.lower()
    return "High" if any(kw in text for kw in URGENT_KEYWORDS) else "Medium"

def simple_domain(text: str) -> str:
    text = text.lower()
    scores = {d: 0 for d in DOMAINS}
    for domain, kws in DOMAINS.items():
        for kw in kws:
            if kw in text:
                scores[domain] += 1
    best = max(scores, key=lambda d: scores[d])
    return best if scores[best] > 0 else "General"

# --------------------------
# Conversation Memory (Optional)
# --------------------------
conversation_history = []

# --------------------------
# Routes
# --------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/classify", methods=["POST"])
def classify():
    data = request.get_json(force=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "Please provide 'text'"}), 400

    # Local heuristics
    urgency = simple_urgency(text)
    domain_guess = simple_domain(text)

    # Save history for follow-up context
    conversation_history.append(f"User: {text}")

    # Create prompt for Gemini with conversation history
    history_text = "\n".join(conversation_history[-5:])  # last 5 messages
    prompt = f"""
Conversation so far:
{history_text}

Suggested domain: {domain_guess}
Urgency: {urgency}
Task: Classify into a legal domain (Criminal, Civil, Family, Consumer, General).
Give 2–3 sentence explanation and one suggested next step.
Format output:
Domain: ...
Urgency: ...
Explanation: ...
Next step: ...
"""

    # Call Gemini API
    try:
        resp = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        ai_output = getattr(resp, "text", "No output from Gemini")
        conversation_history.append(f"AI: {ai_output}")
    except Exception as e:
        print(f"[ERROR] Gemini API call failed: {e}")
        ai_output = (
            "AI service is currently busy. "
            "Based on system analysis, here are the results. "
            "Please try again later for a detailed AI explanation."
        )

    return jsonify({
        "input": text,
        "domain_guess": domain_guess,
        "urgency": urgency,
        "ai_output": ai_output
    })

# --------------------------
# Main Entry
# --------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))