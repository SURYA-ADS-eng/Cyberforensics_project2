import streamlit as st
import pandas as pd
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import urllib.parse
from ai_engine import IntelligentAttackClassifier
from security_rules import analyze_payload_rules, sanitize_input

st.set_page_config(page_title="Real-Time Web Attack Detection WAF", layout="wide")

st.title("🛡️ Live Web Application Firewall (WAF) & Attack Interceptor")
st.caption("Department of Artificial Intelligence and Data Science | Cyber Forensics Project 2")

# Global thread-safe log list (works outside Streamlit session context)
if "GLOBAL_LOGS" not in globals():
    GLOBAL_LOGS = []

@st.cache_resource
def get_classifier():
    return IntelligentAttackClassifier()

classifier = get_classifier()

class LiveWAFHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return  # Silence raw terminal logs

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def _handle_request(self, method):
        try:
            parsed_url = urllib.parse.urlparse(self.path)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            client_ip = self.client_address[0]
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")

            body_data = ""
            if method == "POST":
                content_length = int(self.headers.get('Content-Length', 0))
                if content_length > 0:
                    body_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')

            # Extract inspected text
            inspected_str = " ".join([val for sublist in query_params.values() for val in sublist])
            if body_data:
                inspected_str += " " + body_data
            if not inspected_str.strip():
                inspected_str = parsed_url.path

            # AI & Signature Inspection
            prob, pred = classifier.predict(inspected_str)
            rule_findings = analyze_payload_rules(inspected_str)
            is_attack = bool(pred == 1 or prob >= 0.55 or len(rule_findings) > 0)

            attack_type = rule_findings[0]["Attack Type"] if rule_findings else ("ML Flagged Anomaly" if is_attack else "None")
            remediation = rule_findings[0]["Recommended Preventive Mechanism"] if rule_findings else "Enforce strict schema validation and query parameterization."

            log_entry = {
                "Time": timestamp,
                "Client IP": client_ip,
                "Method": method,
                "Target Path": parsed_url.path,
                "Inspected Payload": inspected_str[:50] + ("..." if len(inspected_str) > 50 else ""),
                "Threat Score": f"{prob * 100:.1f}%",
                "Verdict": "🚫 BLOCKED (403)" if is_attack else "✅ ALLOWED (200)",
                "Detected Attack": attack_type,
                "Countermeasure": remediation if is_attack else "None needed."
            }

            GLOBAL_LOGS.insert(0, log_entry)
            if len(GLOBAL_LOGS) > 30:
                GLOBAL_LOGS.pop()

            # Send complete response with Content-Length (fixes Windows PowerShell crash)
            if is_attack:
                resp_body = b"403 Forbidden: Malicious payload intercepted by AI WAF Gateway.\n"
                self.send_response(403)
            else:
                resp_body = b"200 OK: Request verified as clean.\n"
                self.send_response(200)

            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(resp_body)

        except Exception as e:
            try:
                err_msg = b"500 Internal Error\n"
                self.send_response(500)
                self.send_header("Content-Length", str(len(err_msg)))
                self.end_headers()
                self.wfile.write(err_msg)
            except:
                pass

# Start the background server reliably
if "server_started" not in st.session_state:
    def run_server():
        try:
            httpd = HTTPServer(('127.0.0.1', 5000), LiveWAFHandler)
            httpd.serve_forever()
        except:
            pass

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    st.session_state.server_started = True

# ==================== STREAMLIT UI ====================
st.markdown("""
> 🟢 **WAF Ingress Gateway Active on:** `http://127.0.0.1:5000`  
> Any HTTP request sent to this port is inspected live by the **TF-IDF ML Model** and **Signature Rule Engine**.
""")

col1, col2 = st.columns([1, 4])
with col1:
    if st.button("🧹 Clear Logs"):
        GLOBAL_LOGS.clear()
        st.rerun()

st.divider()

@st.fragment(run_every="1.5s")
def display_live_traffic():
    logs = list(GLOBAL_LOGS)
    if logs:
        df = pd.DataFrame(logs)
        blocked_count = sum(1 for x in logs if "BLOCKED" in x["Verdict"])
        allowed_count = sum(1 for x in logs if "ALLOWED" in x["Verdict"])
        
        m1, m2, m3 = st.columns(3)
        m1.metric("Total Intercepted Requests", len(logs))
        m2.metric("Blocked Threats (403)", blocked_count)
        m3.metric("Clean Requests Passed (200)", allowed_count)
        
        st.markdown("### 📡 Live Interception Stream")
        st.dataframe(df, use_container_width=True, height=350)
    else:
        st.info("Waiting for live incoming HTTP requests... Send a request from terminal or browser to see it appear.")

display_live_traffic()