"""Safe, explainable security-intelligence analyzers integrated with company.db.

The module deliberately does not scan targets, execute attachments, or pretend an
external provider answered.  It produces local-analysis findings and promotes
meaningful findings into the existing ``security_events``/incident lifecycle.
"""
import base64
import ipaddress
import json
import os
import re
import sqlite3
import struct
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

from .alert_manager import ensure_security_schema

MAX_UPLOAD_BYTES = 3 * 1024 * 1024
SEVERITY = ((90, "CRITICAL"), (70, "HIGH"), (40, "MEDIUM"), (1, "LOW"), (0, "NORMAL"))
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "gq", "work", "country"}
URL_WORDS = {"login", "verify", "account", "password", "credential", "signin", "wallet", "payment"}
URGENT_WORDS = {"urgent", "immediately", "suspended", "action required", "verify now", "within 24 hours"}


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def severity_for(score):
    score = max(0, min(100, int(round(score))))
    return next(label for threshold, label in SEVERITY if score >= threshold)


def _con(path):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    ensure_security_schema(con)
    ensure_intelligence_schema(con)
    return con


def ensure_intelligence_schema(con):
    con.execute("""CREATE TABLE IF NOT EXISTS security_findings (
        id INTEGER PRIMARY KEY, security_event_id INTEGER NOT NULL, finding_type TEXT NOT NULL,
        source_label TEXT NOT NULL, target TEXT, analysis_mode TEXT NOT NULL, evidence_json TEXT,
        external_intelligence_json TEXT, created_at TEXT NOT NULL,
        FOREIGN KEY(security_event_id) REFERENCES security_events(id))""")
    con.execute("""CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY, title TEXT NOT NULL, employee_id TEXT, ip_address TEXT,
        status TEXT NOT NULL DEFAULT 'NEW', risk_score INTEGER, created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS incident_event_links (
        incident_id INTEGER NOT NULL, security_event_id INTEGER NOT NULL,
        linked_at TEXT NOT NULL, PRIMARY KEY(incident_id,security_event_id),
        FOREIGN KEY(incident_id) REFERENCES incidents(id),
        FOREIGN KEY(security_event_id) REFERENCES security_events(id))""")
    con.execute("""CREATE TABLE IF NOT EXISTS security_reports (
        id INTEGER PRIMARY KEY, report_type TEXT NOT NULL, security_event_id INTEGER,
        title TEXT NOT NULL, content_json TEXT NOT NULL, generated_by TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS security_audit_log (
        id INTEGER PRIMARY KEY, actor TEXT NOT NULL, action_type TEXT NOT NULL,
        target_type TEXT, target_id TEXT, detail TEXT, created_at TEXT NOT NULL)""")
    con.commit()


def unified_risk(primary_score, components=None, evidence=None):
    """Explainable fusion: local source remains primary; corroboration adds bounded weight."""
    components = {k: int(v) for k, v in (components or {}).items() if v is not None}
    primary = max(0, min(100, int(primary_score or 0)))
    corroborating = sorted((score for score in components.values() if score > 0), reverse=True)
    uplift = min(20, sum(max(0, score - 50) for score in corroborating[:2]) // 5)
    final = min(100, primary + uplift)
    reasons = [f"Primary local analysis risk: {primary}/100."]
    reasons += [f"{name.replace('_', ' ').title()} contributed {score}/100." for name, score in components.items() if score]
    if uplift:
        reasons.append(f"Corroborating signals increased risk by {uplift} points (capped at 20).")
    return {"risk_score": final, "severity": severity_for(final), "confidence": round(min(.95, .45 + len(evidence or []) * .08), 2), "reasons": reasons}


def _vt(kind, value):
    key = os.environ.get("VIRUSTOTAL_API_KEY")
    unavailable = {"available": False, "status": "External intelligence unavailable.", "provider": "VirusTotal"}
    if not key:
        unavailable["reason"] = "VIRUSTOTAL_API_KEY is not configured"
        return unavailable
    if kind == "url":
        ident = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{ident}"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/{kind}/{urllib.parse.quote(value, safe='')}"
    request = urllib.request.Request(endpoint, headers={"x-apikey": key, "accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            stats = json.loads(response.read().decode("utf-8"))["data"]["attributes"].get("last_analysis_stats", {})
        return {"available": True, "provider": "VirusTotal", "analysis_timestamp": utcnow(),
                "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)), "undetected": int(stats.get("undetected", 0))}
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, TimeoutError) as exc:
        unavailable["reason"] = f"VirusTotal request failed safely: {type(exc).__name__}"
        return unavailable


def analyse_url(value, external=True):
    raw = (value or "").strip()
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL.")
    host = parsed.hostname.lower().rstrip(".")
    evidence, score = [], 0
    try:
        ipaddress.ip_address(host); score += 25; evidence.append("URL uses a numeric IP address instead of a domain.")
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) > 4: score += 12; evidence.append("Domain has an unusually deep subdomain chain.")
    if host.split(".")[-1] in SUSPICIOUS_TLDS: score += 12; evidence.append("Domain uses a higher-risk top-level domain.")
    words = set(re.findall(r"[a-z]+", (host + parsed.path + " " + parsed.query).lower()))
    matched = sorted(URL_WORDS & words)
    if len(matched) >= 2: score += 14; evidence.append("Multiple credential-related terms were found: " + ", ".join(matched) + ".")
    if parsed.scheme == "http": score += 8; evidence.append("URL is not protected by HTTPS.")
    if "@" in parsed.netloc or len(raw) > 180: score += 10; evidence.append("URL structure is unusually complex.")
    if any(key in parsed.query.lower() for key in ("redirect=", "url=", "next=", "return=")):
        score += 8; evidence.append("URL includes a redirect-style query parameter.")
    external_data = _vt("url", raw) if external else {"available": False, "status": "External intelligence not requested."}
    if external_data.get("available"):
        detections = external_data["malicious"] + external_data["suspicious"]
        if detections: score += min(35, 10 + detections * 3); evidence.append(f"VirusTotal reported {detections} malicious/suspicious detections.")
    result = unified_risk(score, {"virustotal": min(100, (external_data.get("malicious", 0) + external_data.get("suspicious", 0)) * 10)}, evidence)
    result.update({"target": raw, "domain": host, "protocol": parsed.scheme, "hostname": host, "path": parsed.path or "/",
                   "query_parameters": sorted(urllib.parse.parse_qs(parsed.query)), "indicators": evidence,
                   "classification": "Possible phishing URL" if result["risk_score"] >= 70 else "Suspicious URL" if result["risk_score"] >= 40 else "No strong local threat indicators",
                   "recommendation": "Do not enter credentials; verify the destination independently." if result["risk_score"] >= 40 else "Continue to monitor; local analysis found limited indicators.", "external": external_data})
    return result


def analyse_ip(value, database_path=None, external=True):
    try: ip = ipaddress.ip_address((value or "").strip())
    except ValueError: raise ValueError("Enter a valid IP address.")
    observed = {"events": 0, "employees": [], "threats": 0, "average_risk": None}
    if database_path:
        con = _con(database_path)
        try:
            rows = con.execute("SELECT employee_id,risk_score,ai_prediction FROM security_events WHERE ip_address=?", (str(ip),)).fetchall()
            risks = [row["risk_score"] for row in rows if row["risk_score"] is not None]
            observed = {"events": len(rows), "employees": sorted({row["employee_id"] for row in rows if row["employee_id"]}),
                        "threats": sum(row["ai_prediction"] == "Threat" for row in rows), "average_risk": round(sum(risks) / len(risks)) if risks else None}
        finally: con.close()
    evidence, score = [], 0
    if ip.is_private: evidence.append("Private address; public geolocation/reputation is not applicable.")
    if observed["threats"]: score += min(40, observed["threats"] * 15); evidence.append(f"Observed in {observed['threats']} model-classified threat event(s).")
    if observed["average_risk"]: score += max(0, observed["average_risk"] - 50) // 3
    ext = _vt("ip_addresses", str(ip)) if external and not ip.is_private else {"available": False, "status": "External intelligence unavailable for private IP." if ip.is_private else "External intelligence not requested."}
    if ext.get("available") and ext["malicious"] + ext["suspicious"]:
        score += min(35, 10 + (ext["malicious"] + ext["suspicious"]) * 3); evidence.append("External reputation returned detections.")
    result = unified_risk(score, {"observed_activity": observed["average_risk"] or 0, "virustotal": (ext.get("malicious", 0) + ext.get("suspicious", 0)) * 10}, evidence)
    result.update({"target": str(ip), "ip_type": "Private" if ip.is_private else "Public", "observed": observed, "indicators": evidence,
                   "classification": "Suspicious IP activity" if result["risk_score"] >= 40 else "No strong observed threat signal", "recommendation": "Review linked events and restrict the source only after analyst confirmation." if result["risk_score"] >= 40 else "No containment action is recommended from current evidence.", "external": ext})
    return result


def analyse_email(subject, sender, recipient, body, headers="", database_path=None):
    text = " ".join((subject or "", body or "", headers or ""))
    urls = re.findall(r"https?://[^\s<>\"']+", text, flags=re.I)
    evidence, score = [], 0
    urgent = [word for word in URGENT_WORDS if word in text.lower()]
    credential = sorted(URL_WORDS & set(re.findall(r"[a-z]+", text.lower())))
    if len(urgent) >= 2: score += 18; evidence.append("Multiple urgency/pressure phrases: " + ", ".join(urgent) + ".")
    if len(credential) >= 2: score += 15; evidence.append("Credential/payment language: " + ", ".join(credential) + ".")
    if sender and "@" not in sender: score += 15; evidence.append("Sender address format is invalid.")
    sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    header_domains = re.findall(r"(?:reply-to|return-path)\s*[:=]\s*[^@\s]+@([\w.-]+)", headers or "", re.I)
    if header_domains and sender_domain and any(domain.lower() != sender_domain for domain in header_domains):
        score += 20; evidence.append("Sender domain differs from Reply-To/Return-Path evidence.")
    url_results = []
    for url in urls[:5]:
        try:
            item = analyse_url(url, external=False); url_results.append(item); score += max(0, item["risk_score"] - 45) // 2
        except ValueError: pass
    if any(item["risk_score"] >= 40 for item in url_results): evidence.append("Email contains one or more URLs with local suspicious indicators.")
    result = unified_risk(score, {"url_analysis": max([x["risk_score"] for x in url_results], default=0)}, evidence)
    result.update({"target": sender or "Email content", "urls": url_results, "indicators": evidence,
                   "classification": "Possible phishing email" if result["risk_score"] >= 65 else "Suspicious email" if result["risk_score"] >= 40 else "No strong local phishing indicators",
                   "recommendation": "Do not open links or attachments; verify the sender independently." if result["risk_score"] >= 40 else "Use normal verification procedures.", "subject": (subject or "")[:500], "sender": (sender or "")[:320], "recipient": (recipient or "")[:320]})
    return result


def analyse_image(data, filename=""):
    if not data or len(data) > MAX_UPLOAD_BYTES: raise ValueError("Provide an image up to 3 MB.")
    extracted, mode = "", "LOCAL ANALYSIS"
    try:
        from PIL import Image
        from io import BytesIO
        image = Image.open(BytesIO(data)); image.verify()
        try:
            import pytesseract
            image = Image.open(BytesIO(data)); extracted = pytesseract.image_to_string(image)[:10000]; mode = "LOCAL OCR ANALYSIS"
        except (ImportError, OSError):
            mode = "LOCAL IMAGE VALIDATION — OCR UNAVAILABLE"
    except Exception as exc: raise ValueError("Unsupported or corrupt image.") from exc
    # Reuse email language analysis without treating a single word as malicious.
    result = analyse_email("", "", "", extracted, "") if extracted else unified_risk(0, {}, [])
    result.update({"target": filename or "Uploaded image", "extracted_text": extracted, "analysis_mode": mode,
                   "classification": result.get("classification", "OCR unavailable; no text analysis performed"),
                   "recommendation": result.get("recommendation", "Install/configure an approved OCR engine to analyse image text."), "indicators": result.get("indicators", [])})
    return result


def analyse_qr(data, filename=""):
    if not data or len(data) > MAX_UPLOAD_BYTES: raise ValueError("Provide a QR image up to 3 MB.")
    decoded = ""
    try:
        import cv2
        import numpy as np
        decoded, _, _ = cv2.QRCodeDetector().detectAndDecode(cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR))
    except Exception:
        pass
    if not decoded:
        return {"target": filename or "Uploaded QR image", "decoded_content": "", "analysis_mode": "QR DECODER UNAVAILABLE OR NO QR DETECTED", "risk_score": 0, "severity": "NORMAL", "confidence": 0, "reasons": [], "indicators": [], "classification": "No QR result", "recommendation": "Use an approved QR decoder or provide a valid QR image.", "external": {"available": False, "status": "No external intelligence requested."}}
    if decoded.lower().startswith(("http://", "https://")):
        result = analyse_url(decoded, external=True); result["analysis_mode"] = "LOCAL QR DECODE + URL ANALYSIS"
    else:
        result = unified_risk(0, {}, []); result.update({"classification": "Decoded non-URL QR content", "recommendation": "Review decoded content in its business context.", "external": {"available": False, "status": "No URL reputation applicable."}, "analysis_mode": "LOCAL QR DECODE"})
    result.update({"target": filename or "Uploaded QR image", "decoded_content": decoded})
    return result


def parse_nmap_xml(data):
    """Parse authorised Nmap XML supplied by an analyst; it never starts a scan."""
    import xml.etree.ElementTree as ET
    try: root = ET.fromstring(data)
    except ET.ParseError as exc: raise ValueError("Nmap XML could not be parsed.") from exc
    hosts, evidence, score = [], [], 0
    for host in root.findall("host"):
        address = next((x.get("addr") for x in host.findall("address") if x.get("addrtype") in {"ipv4", "ipv6"}), "Unknown")
        ports = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                service = port.find("service"); name = service.get("name", "unknown") if service is not None else "unknown"
                ports.append({"port": int(port.get("portid", 0)), "protocol": port.get("protocol"), "service": name, "version": (service.get("product", "") if service is not None else "")})
                if int(port.get("portid", 0)) in {23, 21, 3389}: score += 20; evidence.append(f"Potentially risky exposed service: {name} on port {port.get('portid')}.")
        hosts.append({"host": address, "open_ports": ports})
    if not hosts: evidence.append("No completed host records were found in the supplied Nmap XML.")
    result = unified_risk(score, {}, evidence)
    result.update({"target": ", ".join(x["host"] for x in hosts[:5]) or "Authorised Nmap XML", "hosts": hosts, "indicators": evidence, "analysis_mode": "IMPORTED AUTHORISED NMAP RESULT", "classification": "Risky exposed service" if score else "No risky service detected by local rules", "recommendation": "Disable legacy services and restrict management ports after validation." if score else "Review the approved scan scope and service exposure."})
    return result


def analyse_pcap(data):
    """Small offline classic-PCAP parser (Ethernet/IPv4/TCP/UDP only); no live capture."""
    if not data or len(data) > MAX_UPLOAD_BYTES: raise ValueError("Provide a classic PCAP capture up to 3 MB.")
    if len(data) < 24: raise ValueError("Capture is too small to be a classic PCAP file.")
    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else None
    if not endian: raise ValueError("Only classic PCAP files are supported; PCAPNG is not parsed.")
    offset, protocols, conversations, evidence, score = 24, Counter(), Counter(), [], 0
    while offset + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[offset:offset + 16]); offset += 16
        frame = data[offset:offset + incl]; offset += incl
        if len(frame) < 34 or frame[12:14] != b"\x08\x00": continue
        ip_start = 14; version = frame[ip_start] >> 4
        if version != 4: continue
        ihl = (frame[ip_start] & 15) * 4
        if len(frame) < ip_start + ihl: continue
        proto = frame[ip_start + 9]; source = ".".join(map(str, frame[ip_start + 12:ip_start + 16])); dest = ".".join(map(str, frame[ip_start + 16:ip_start + 20]))
        name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"IP-{proto}"); protocols[name] += 1
        ports = ""
        if proto in {6, 17} and len(frame) >= ip_start + ihl + 4:
            sport, dport = struct.unpack("!HH", frame[ip_start + ihl:ip_start + ihl + 4]); ports = f":{sport}->{dport}"
            if dport in {23, 21}: score += 4; evidence.append(f"Observed legacy service traffic to port {dport}.")
        conversations[f"{source}{ports} → {dest}"] += 1
    if not protocols: evidence.append("No supported Ethernet/IPv4 packets were parsed.")
    if protocols.get("TCP", 0) > 10000: score += 10; evidence.append("High TCP packet volume in uploaded capture.")
    result = unified_risk(score, {}, sorted(set(evidence)))
    result.update({"target": "Uploaded packet capture", "analysis_mode": "UPLOADED CAPTURE ANALYSIS", "protocols": dict(protocols), "packet_count": sum(protocols.values()), "connections": conversations.most_common(20), "indicators": sorted(set(evidence)), "classification": "Potentially risky network pattern" if score else "No local risky pattern detected", "recommendation": "Review the listed conversations in an approved packet-analysis workflow."})
    return result


def persist_finding(database_path, finding_type, source, result, actor="admin", employee_id=None, ip_address=None):
    """Store analysis as a standard event, finding, and correlated incident when meaningful."""
    con = _con(database_path)
    try:
        now, event_id = utcnow(), str(uuid.uuid4())
        risk = int(result.get("risk_score", 0)); classification = result.get("classification", finding_type)
        description = ("; ".join(result.get("indicators") or result.get("reasons") or []) or classification)[:2000]
        con.execute("""INSERT INTO security_events(event_id,employee_id,event_type,source,severity,description,timestamp,status,metadata_json,record_type,ip_address,resource,risk_score,ai_prediction,ai_threat_type,ai_confidence,ai_reasons_json,ai_recommended_action,ai_processed_at,ai_status)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (event_id, employee_id, finding_type, source, result.get("severity", "NORMAL"), description, now, "NEW", json.dumps({"analysis_mode": result.get("analysis_mode", "LOCAL ANALYSIS"), "target": result.get("target"), "actor": actor}), "EVENT", ip_address, result.get("target"), risk, "Threat" if risk >= 70 else "Suspicious" if risk >= 40 else "Normal", classification, result.get("confidence", 0), json.dumps(result.get("reasons") or result.get("indicators") or []), result.get("recommendation"), now, result.get("analysis_mode", "LOCAL ANALYSIS")))
        event_row_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.execute("INSERT INTO security_findings(security_event_id,finding_type,source_label,target,analysis_mode,evidence_json,external_intelligence_json,created_at) VALUES(?,?,?,?,?,?,?,?)", (event_row_id, finding_type, source, result.get("target"), result.get("analysis_mode", "LOCAL ANALYSIS"), json.dumps(result), json.dumps(result.get("external") or {}), now))
        incident_id = correlate_event(con, event_row_id, classification, employee_id, ip_address, risk, now)
        con.execute("INSERT INTO security_audit_log(actor,action_type,target_type,target_id,detail,created_at) VALUES(?,?,?,?,?,?)", (actor, "ANALYSIS_CREATED", finding_type, event_id, f"{source} / {result.get('analysis_mode', 'LOCAL ANALYSIS')}", now))
        con.commit()
        return {"event_id": event_id, "security_event_id": event_row_id, "incident_id": incident_id}
    finally: con.close()


def correlate_event(con, event_row_id, title, employee_id, ip_address, risk, now):
    if risk < 40: return None
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    clauses, values = ["status NOT IN ('RESOLVED','FALSE POSITIVE')", "created_at>=?"], [cutoff]
    if employee_id: clauses.append("employee_id=?"); values.append(employee_id)
    elif ip_address: clauses.append("ip_address=?"); values.append(ip_address)
    else: return None
    row = con.execute("SELECT id FROM incidents WHERE " + " AND ".join(clauses) + " ORDER BY id DESC LIMIT 1", values).fetchone()
    if row: incident_id = row[0]; con.execute("UPDATE incidents SET risk_score=MAX(risk_score,?),updated_at=? WHERE id=?", (risk, now, incident_id))
    else:
        con.execute("INSERT INTO incidents(title,employee_id,ip_address,status,risk_score,created_at,updated_at) VALUES(?,?,?,?,?,?,?)", (title[:200], employee_id, ip_address, "NEW", risk, now, now)); incident_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.execute("INSERT OR IGNORE INTO incident_event_links(incident_id,security_event_id,linked_at) VALUES(?,?,?)", (incident_id, event_row_id, now))
    return incident_id


def generate_report(database_path, report_type, record_id, actor):
    con = _con(database_path)
    try:
        row = con.execute("SELECT * FROM security_events WHERE id=?", (record_id,)).fetchone()
        if not row: raise ValueError("Security event not found.")
        finding = con.execute("SELECT * FROM security_findings WHERE security_event_id=? ORDER BY id DESC LIMIT 1", (record_id,)).fetchone()
        content = {"date": utcnow(), "source": row["source"], "finding": row["ai_threat_type"] or row["event_type"], "evidence": json.loads(finding["evidence_json"]) if finding else row["description"], "risk": row["risk_score"], "severity": row["severity"], "recommendation": row["ai_recommended_action"] or row["recommended_action"], "status": row["status"]}
        con.execute("INSERT INTO security_reports(report_type,security_event_id,title,content_json,generated_by,created_at) VALUES(?,?,?,?,?,?)", (report_type, record_id, f"{report_type}: {content['finding']}", json.dumps(content), actor, utcnow()))
        con.execute("INSERT INTO security_audit_log(actor,action_type,target_type,target_id,detail,created_at) VALUES(?,?,?,?,?,?)", (actor, "REPORT_GENERATED", report_type, str(record_id), content['finding'], utcnow()))
        con.commit(); return content
    finally: con.close()


def copilot_answer(database_path, question, grounded_answer):
    """Optional Groq explanation layer. The supplied database-grounded context is authoritative."""
    key = os.environ.get("GROQ_API_KEY")
    if not key:
        return {"mode": "GROUNDED SECURITY AGENT", "answer": grounded_answer,
                "notice": "LLM provider is not configured; this answer uses controlled local database analytics."}
    con = _con(database_path)
    try:
        rows = con.execute("SELECT event_type,source,severity,risk_score,ai_threat_type,status,timestamp FROM security_events ORDER BY id DESC LIMIT 20").fetchall()
        context = [dict(row) for row in rows]
    finally: con.close()
    payload = {"model": os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant"), "temperature": 0.1, "max_tokens": 500,
               "messages": [{"role": "system", "content": "You are a security copilot. Use only the supplied factual context. Do not invent employees, vulnerabilities, scan results, or external intelligence. State uncertainty clearly and recommend analyst review."}, {"role": "user", "content": f"Question: {question}\nAuthoritative local answer: {grounded_answer}\nRecent event context: {json.dumps(context)}"}]}
    request = urllib.request.Request("https://api.groq.com/openai/v1/chat/completions", data=json.dumps(payload).encode(), headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            answer = json.loads(response.read().decode())["choices"][0]["message"]["content"].strip()
        return {"mode": "LLM EXPLANATION GROUNDED IN PROJECT DATA", "answer": answer, "notice": "The copilot is advisory; deterministic detections and database records remain authoritative."}
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, KeyError, TimeoutError) as exc:
        return {"mode": "GROUNDED SECURITY AGENT", "answer": grounded_answer, "notice": f"LLM provider unavailable ({type(exc).__name__}); returned controlled local analysis instead."}
