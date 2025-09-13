# app.py
import os
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from google import genai
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from passlib.hash import bcrypt

# --------------------------
# Load Environment Variables
# --------------------------
load_dotenv()
GEMINI_KEY = os.getenv("GEMINI_API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "change-this-secret")
DATABASE_URL = os.getenv("DATABASE_URL", "")  # optional: Postgres in production

if not GEMINI_KEY:
    raise EnvironmentError("❌ GEMINI_API_KEY is missing in .env")

# --------------------------
# Flask + DB + JWT Setup
# --------------------------
app = Flask(__name__)
CORS(app)  # you can restrict origins: CORS(app, origins=["https://your-frontend.vercel.app"])

# DB config: prefer DATABASE_URL else sqlite local file
if DATABASE_URL:
    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///data.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = JWT_SECRET

db = SQLAlchemy(app)
jwt = JWTManager(app)

# --------------------------
# Initialize Gemini Client
# --------------------------
client = genai.Client(api_key=GEMINI_KEY)

# --------------------------
# Models
# --------------------------
# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Lawyer(db.Model):
    __tablename__ = "lawyers"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    expertise = db.Column(db.String(100), nullable=False)  # e.g. Family, Criminal

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

class Query(db.Model):
    __tablename__ = "queries"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(100))
    urgency = db.Column(db.String(50))
    ai_output = db.Column(db.Text)
    status = db.Column(db.String(50), default="Pending")  # Pending / Answered
    assigned_lawyer_id = db.Column(db.Integer, db.ForeignKey("lawyers.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class Response(db.Model):
    __tablename__ = "responses"
    id = db.Column(db.Integer, primary_key=True)
    query_id = db.Column(db.Integer, db.ForeignKey("queries.id"), nullable=False)
    lawyer_id = db.Column(db.Integer, db.ForeignKey("lawyers.id"), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# create tables
with app.app_context():
    db.create_all()

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
    t = text.lower()
    return "High" if any(kw in t for kw in URGENT_KEYWORDS) else "Medium"

def simple_domain(text: str) -> str:
    t = text.lower()
    scores = {d: 0 for d in DOMAINS}
    for domain, kws in DOMAINS.items():
        for kw in kws:
            if kw in t:
                scores[domain] += 1
    best = max(scores, key=lambda d: scores[d])
    return best if scores[best] > 0 else "General"

# --------------------------
# Routes
# --------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# -------------
# User-facing: classify and store query
# -------------
@app.route("/api/classify", methods=["POST"])
def classify_and_store():
    data = request.get_json(force=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "Please provide 'text'"}), 400

    # heuristics
    urgency = simple_urgency(text)
    domain_guess = simple_domain(text)

    # Build prompt for Gemini
    prompt = f"""
User query: {text}
Suggested domain: {domain_guess}
Urgency: {urgency}
Task: In simple English, 2-3 sentences: 
(1) confirm the domain, 
(2) give a short explanation, 
(3) suggest one next step.
Begin lines with Domain:, Explanation:, Next step:.
"""

    # Call Gemini
    try:
        resp = client.models.generate_content(
            model="gemini-1.5-flash",
            contents=prompt
        )
        ai_output = getattr(resp, "text", str(resp))
    except Exception as e:
        print(f"[ERROR] Gemini API call failed: {e}")
        ai_output = "AI service busy. Using system analysis results."

    # Save query to DB
    q = Query(text=text, category=domain_guess, urgency=urgency, ai_output=ai_output)
    db.session.add(q)
    db.session.commit()

    return jsonify({
        "query_id": q.id,
        "input": text,
        "domain_guess": domain_guess,
        "urgency": urgency,
        "ai_output": ai_output
    })

# -------------
# Lawyer signup / login
# -------------
@app.route("/api/lawyer/signup", methods=["POST"])
def lawyer_signup():
    data = request.get_json(force=True) or {}
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    expertise = data.get("expertise")

    if not (name and email and password and expertise):
        return jsonify({"error": "name,email,password,expertise required"}), 400

    if Lawyer.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 400

    pw_hash = bcrypt.hash(password)
    lawyer = Lawyer(name=name, email=email, password_hash=pw_hash, expertise=expertise)
    db.session.add(lawyer)
    db.session.commit()
    return jsonify({"msg": "registered"})

@app.route("/api/lawyer/login", methods=["POST"])
def lawyer_login():
    data = request.get_json(force=True) or {}
    email = data.get("email")
    password = data.get("password")
    if not (email and password):
        return jsonify({"error": "email and password required"}), 400

    lawyer = Lawyer.query.filter_by(email=email).first()
    if not lawyer or not lawyer.check_password(password):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_access_token(identity=lawyer.email)
    return jsonify({
        "access_token": token,
        "lawyer": {
            "id": lawyer.id,
            "name": lawyer.name,
            "expertise": lawyer.expertise
        }
    })

# -------------
# Lawyer: get queries for their expertise
# -------------
@app.route("/api/lawyer/queries", methods=["GET"])
@jwt_required()
def lawyer_get_queries():
    email = get_jwt_identity()
    lawyer = Lawyer.query.filter_by(email=email).first()
    if not lawyer:
        return jsonify({"error": "lawyer not found"}), 404

    # queries matching expertise or already assigned
    queries = Query.query.filter(
        (Query.category == lawyer.expertise) | 
        (Query.assigned_lawyer_id == lawyer.id)
    ).order_by(Query.created_at.desc()).all()

    out = []
    for q in queries:
        out.append({
            "id": q.id,
            "text": q.text,
            "category": q.category,
            "urgency": q.urgency,
            "ai_output": q.ai_output,
            "status": q.status,
            "assigned_lawyer_id": q.assigned_lawyer_id,
            "created_at": q.created_at.isoformat()
        })
    return jsonify(out)

# -------------
# Lawyer respond to a query
# -------------
@app.route("/api/lawyer/respond/<int:query_id>", methods=["POST"])
@jwt_required()
def lawyer_respond(query_id):
    email = get_jwt_identity()
    lawyer = Lawyer.query.filter_by(email=email).first()
    if not lawyer:
        return jsonify({"error": "lawyer not found"}), 404

    q = Query.query.get(query_id)
    if not q:
        return jsonify({"error": "query not found"}), 404

    data = request.get_json(force=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "Response text required"}), 400

    # create response
    resp = Response(query_id=q.id, lawyer_id=lawyer.id, text=text)
    q.status = "Answered"
    q.assigned_lawyer_id = lawyer.id
    db.session.add(resp)
    db.session.commit()

    return jsonify({"msg": "response saved", "response_id": resp.id})

# -------------
# Optional: get single query with responses
# -------------
@app.route("/api/query/<int:query_id>", methods=["GET"])
@jwt_required()
def get_query_detail(query_id):
    q = Query.query.get(query_id)
    if not q:
        return jsonify({"error": "not found"}), 404
    responses = Response.query.filter_by(query_id=q.id).order_by(Response.created_at.asc()).all()
    return jsonify({
        "id": q.id,
        "text": q.text,
        "category": q.category,
        "ai_output": q.ai_output,
        "urgency": q.urgency,
        "status": q.status,
        "responses": [
            {
                "id": r.id,
                "lawyer_id": r.lawyer_id,
                "text": r.text,
                "created_at": r.created_at.isoformat()
            } for r in responses
        ]
    })

# --------------------------
# Main Entry
# --------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
