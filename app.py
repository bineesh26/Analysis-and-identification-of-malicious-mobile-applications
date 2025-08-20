import os
import re
import json
import uuid
import zipfile
import hashlib
import threading
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.orm import sessionmaker
from datetime import datetime


# === Try Androguard Import ===
try:
    from androguard.core.apk import APK
    ANDROGUARD_AVAILABLE = True
    print("Successfully imported Androguard.")
except ImportError as e:
    print(f"Androguard not available: {e}. Analysis will rely on fallback ZIP inspection.")
    ANDROGUARD_AVAILABLE = False

# === Config ===
ALLOWED_EXT = {'.apk'}
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__, static_folder="static")
CORS(app)

# === Database Setup ===
engine = create_engine('sqlite:///apk_analysis.db', echo=False, future=True)
Base = declarative_base()

class APKAnalysis(Base):
    __tablename__ = 'apk_analysis'
    id = Column(Integer, primary_key=True)
    scan_date = Column(String)
    file_name = Column(String, nullable=False)
    app_name = Column(String)
    package = Column(String)
    version_name = Column(String)
    version_code = Column(String)
    permissions = Column(Text)       # store as JSON string
    activities = Column(Text)
    services = Column(Text)
    receivers = Column(Text)
    providers = Column(Text)
    embedded_libs = Column(Text)
    found_urls = Column(Text)
    suspicious_strings = Column(Text)
    signature_hashes = Column(Text)
    static_score = Column(Integer)
    score = Column(Integer)
    risk_level = Column(String)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

# === Helpers ===
def is_allowed_filename(filename):
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXT

def extract_ascii_strings_from_bytes(b, min_len=4):
    strings, current = [], []
    for ch in b:
        v = ch if isinstance(ch, int) else ord(ch)
        if 32 <= v <= 126:
            current.append(chr(v))
        else:
            if len(current) >= min_len:
                strings.append(''.join(current))
            current = []
    if len(current) >= min_len:
        strings.append(''.join(current))
    return strings

def classify_permission(perm):
    p = perm.upper()
    HIGH = [
        "RECORD_AUDIO", "READ_SMS", "SEND_SMS", "CALL_PHONE", "READ_CONTACTS", 
        "WRITE_CONTACTS", "READ_CALL_LOG", "WRITE_CALL_LOG", "SYSTEM_ALERT_WINDOW", 
        "BIND_DEVICE_ADMIN", "READ_PHONE_STATE"
    ]
    MED = [
        "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "READ_EXTERNAL_STORAGE", 
        "WRITE_EXTERNAL_STORAGE", "GET_ACCOUNTS", "CAMERA"
    ]
    if any(x in p for x in HIGH):
        return "high"
    if any(x in p for x in MED):
        return "medium"
    return "low"

# === Core Analysis Functions ===
def analyze_apk_static(apk_path):
    result = {
        "app_name": "N/A", "package": "N/A", "version_name": "N/A",
        "version_code": "N/A", "permissions": [], "activities": [],
        "services": [], "receivers": [], "providers": [], "embedded_libs": [],
        "found_urls": [], "suspicious_strings": [], "signature_hashes": [],
    }

    if ANDROGUARD_AVAILABLE:
        try:
            a = APK(apk_path)
            result.update({
                "app_name": a.get_app_name() or "N/A",
                "package": a.get_package() or "N/A",
                "version_name": a.get_androidversion_name() or "N/A",
                "version_code": a.get_androidversion_code() or "N/A",
                "permissions": a.get_permissions() or [],
                "activities": a.get_activities() or [],
                "services": a.get_services() or [],
                "receivers": a.get_receivers() or [],
                "providers": a.get_providers() or [],
            })
        except Exception as e:
            print(f"Androguard parsing failed for {os.path.basename(apk_path)}: {e}")

    # Fallback ZIP inspection
    url_re = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
    suspect_keywords = [
        b"su -c", b"Runtime.getRuntime", b"Runtime.exec", b"ProcessBuilder", 
        b"DexClassLoader", b"getDeviceId", b"getSubscriberId", b"loadUrl", b"WebView"
    ]
    with zipfile.ZipFile(apk_path, 'r') as z:
        namelist = z.namelist()
        sig_files = [n for n in namelist if n.startswith("META-INF/") and (n.upper().endswith((".RSA", ".DSA", ".EC")))]
        for s in sig_files:
            try:
                data = z.read(s)
                result["signature_hashes"].append({"file": s, "sha256": hashlib.sha256(data).hexdigest()})
            except Exception: pass
        result["embedded_libs"] = [n for n in namelist if n.startswith("lib/") and n.endswith(".so")]
        found_urls, found_sus = set(), set()
        for name in namelist:
            try: data = z.read(name)
            except Exception: continue
            for m in url_re.findall(data): found_urls.add(m.decode("utf-8", errors="ignore"))
            for kw in suspect_keywords:
                if kw in data: found_sus.add(kw.decode("utf-8", errors="ignore"))
        result["found_urls"] = list(found_urls)[:200]
        result["suspicious_strings"] = list(found_sus)[:200]

    # Permissions classification
    perm_objs = [{"name": p, "risk": classify_permission(p)} for p in result.get("permissions", [])]
    result["permissions"] = perm_objs
    high_count = sum(1 for p in perm_objs if p["risk"] == "high")
    medium_count = sum(1 for p in perm_objs if p["risk"] == "medium")
    static_score = 5 + (medium_count * 10) + (high_count * 20)
    result["static_score"] = min(static_score, 100)
    return result

def aggregate_and_score(result):
    total_score = min(result.get("static_score", 0) + result.get("dynamic_score", 0), 100)
    result["score"] = total_score
    if total_score >= 75: result["risk_level"] = "Critical Risk"
    elif total_score >= 40: result["risk_level"] = "High Risk"
    else: result["risk_level"] = "Low Risk"
    return result

# === API Routes ===
@app.route("/api/upload", methods=["POST"])
def upload_apks():
    if "apk" not in request.files:
        return jsonify({"error": "No file field named 'apk' in the request"}), 400

    files = request.files.getlist("apk")
    if not files or files[0].filename == '':
        return jsonify({"error": "No files selected for upload"}), 400

    results_for_this_request = []

    for f in files:
        if f.filename == "" or not is_allowed_filename(f.filename):
            continue

        safe_name = secure_filename(f.filename)
        unique_filename = f"{uuid.uuid4()}-{safe_name}"
        save_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        f.save(save_path)

        analysis = analyze_apk_static(save_path)
        analysis = aggregate_and_score(analysis)
        analysis["file_name"] = safe_name
        analysis["scan_date"] = datetime.now().isoformat()

        # Save to DB
        record = APKAnalysis(
            file_name=analysis["file_name"],
            app_name=analysis["app_name"],
            package=analysis["package"],
            version_name=analysis["version_name"],
            version_code=analysis["version_code"],
            permissions=json.dumps(analysis["permissions"]),
            activities=json.dumps(analysis["activities"]),
            services=json.dumps(analysis["services"]),
            receivers=json.dumps(analysis["receivers"]),
            providers=json.dumps(analysis["providers"]),
            embedded_libs=json.dumps(analysis["embedded_libs"]),
            found_urls=json.dumps(analysis["found_urls"]),
            suspicious_strings=json.dumps(analysis["suspicious_strings"]),
            signature_hashes=json.dumps(analysis["signature_hashes"]),
            static_score=analysis["static_score"],
            score=analysis["score"],
            risk_level=analysis["risk_level"],
            scan_date=analysis["scan_date"]
        )
        session.add(record)
        session.commit()

        results_for_this_request.append(analysis)

    return jsonify(results_for_this_request), 200

@app.route("/api/results", methods=["GET"])
def get_results():
    all_results = session.query(APKAnalysis).all()
    return jsonify([
        {
            "file_name": r.file_name,
            "app_name": r.app_name,
            "package": r.package,
            "risk_level": r.risk_level,
            "score": r.score,
            "scan_date": r.scan_date
        } for r in all_results
    ])

# === Serve Frontend ===
@app.route("/", methods=["GET"])
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
