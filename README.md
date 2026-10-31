# Intelligent Cyberattack Detection System & Web Application Firewall (WAF)

**Institution:** Velalar College of Engineering and Technology (Autonomous), Erode  
**Department:** Department of Artificial Intelligence and Data Science  
**Course Code & Title:** 22ADE62 – Cyber Forensics  
**Activity:** Project Based Learning – Activity 2 (Project 2)  
**Academic Year:** 2026  

---

## 📌 Project Overview

This project implements an **Intelligent Cyberattack Detection System & Reverse-Proxy Web Application Firewall (WAF)** prototype designed to detect common web security vulnerabilities and execute preventive countermeasures in real time.

Rather than relying purely on static keyword filtering, the system utilizes a **dual-layer hybrid inspection architecture**:
1. **Layer 1: AI / NLP Machine Learning Classifier:** Uses character-level TF-IDF vectorization and Logistic Regression to detect structural anomalies, abnormal punctuation distributions, and obfuscated exploits.
2. **Layer 2: Deterministic Rule & Signature Engine:** Employs pre-compiled regex signatures mapped to the **OWASP Top 10** and **MITRE CWE** taxonomies to identify known attack patterns and generate exact code-level countermeasures.

The application runs an active background HTTP ingress gateway on port `5000` that inspects live HTTP traffic in real time and streams forensic telemetry to an interactive **Streamlit** dashboard.

---

## 🎯 Key Features

- **Dynamic Request Parsing:** Evaluates any arbitrary endpoint, parameter key, or payload dynamically using RFC-compliant URL decoding (`urllib.parse`).
- **OWASP Vulnerability Coverage:**
  - **SQL Injection (SQLi) – CWE-89:** Identifies boolean bypasses, inline comment syntax, and `UNION SELECT` extraction attempts.
  - **Cross-Site Scripting (XSS) – CWE-79:** Detects malicious `<script>` tags, event-handler attributes (`onerror`, `onload`), and DOM injection payloads.
  - **Path Traversal / Local File Inclusion – CWE-22:** Detects directory breakout sequences (`../`, `..\`).
- **Live HTTP Ingress Proxy:** Listens on `http://127.0.0.1:5000`, intercepting incoming HTTP traffic before it reaches backend services and issuing standard RFC HTTP status codes (`200 OK` vs. `403 Forbidden`).
- **Actionable Countermeasures:** Generates code-level remediation snippets (Parameterized Queries/Prepared Statements, HTML entity encoding, and whitelist validation) for every identified attack.
- **Real-Time Forensic Telemetry:** Dynamic dashboard visualizing incoming requests, threat probability metrics, client IP origin, and verdict metrics.

---

**Running:**
1.  python -m venv venv
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
    .\venv\Scripts\Activate.ps1


2.   pip install -r requirements.txt


3.   streamlit run app.py


**Testing:**

1. Test Dynamic Benign Request
PowerShell
curl.exe "[http://127.0.0.1:5000/college/library?student_dept=aids&book_title=deep_learning](http://127.0.0.1:5000/college/library?student_dept=aids&book_title=deep_learning)"
Client Terminal Output: 200 OK: Request verified as clean.

Dashboard Log: Marked as ✅ ALLOWED (200) with low anomaly score.

2. Test SQL Injection Attack (CWE-89)
PowerShell
curl.exe "[http://127.0.0.1:5000/api/check?custom_field=test'UNION%20SELECT%201,2--](http://127.0.0.1:5000/api/check?custom_field=test'UNION%20SELECT%201,2--)"
Client Terminal Output: 403 Forbidden: Malicious payload intercepted by AI WAF Gateway.

Dashboard Log: Marked as 🚫 BLOCKED (403) with threat score >90% and parameterized query recommendation.

3. Test Cross-Site Scripting (XSS) Attack (CWE-79)
PowerShell
curl.exe "[http://127.0.0.1:5000/comment?text=](http://127.0.0.1:5000/comment?text=)<script>alert('Session_Hijacked')</script>"
Client Terminal Output: 403 Forbidden: Malicious payload intercepted by AI WAF Gateway.

Dashboard Log: Marked as 🚫 BLOCKED (403) displaying the HTML entity encoding countermeasure.

4. Test Path Traversal Attack (CWE-22)
PowerShell
curl.exe "[http://127.0.0.1:5000/download?file=../../../../etc/passwd](http://127.0.0.1:5000/download?file=../../../../etc/passwd)"
Client Terminal Output: 403 Forbidden: Malicious payload intercepted by AI WAF Gateway.

Dashboard Log: Marked as 🚫 BLOCKED (403) displaying directory restriction remediation.