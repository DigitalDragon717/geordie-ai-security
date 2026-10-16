# Geordie AI Security

**Educational Host-Level Anomaly Detection & Safe Response Platform**  
Built for the 2026 Congressional App Challenge

---

## One-Sentence Purpose
Geordie AI is an educational cybersecurity tool that detects unusual host activity using machine learning, maps findings to MITRE ATT&CK and NIST frameworks, and recommends safe, verifiable defensive actions — while never claiming to stop attacks it cannot prove it stopped.

## Target Audience
- High school and middle school students learning cybersecurity
- Teachers and cybersecurity clubs who want a hands-on, safe demonstration of anomaly detection
- Anyone who wants to understand how modern detection engines work without dangerous auto-blocking

## The Problem
Most student cybersecurity projects either:
- Only show pretty dashboards with fake data, or
- Attempt real system changes (firewall rules, process kills) without proper safety, verification, or clear limitations

This creates either “demo-ware” or risky tools. Geordie AI was built to be honest, educational, and safe by design.

## What Geordie AI Actually Does
1. Collects real host-level telemetry (network counters, connections, CPU) using `psutil`
2. Runs two machine learning models:
   - **Isolation Forest** → unsupervised anomaly detection
   - **Random Forest** → classifies the anomaly (Normal / DDoS / Port Scan / Exfiltration)
3. Calculates a risk score and maps the finding to MITRE ATT&CK and NIST controls
4. Recommends an action (or runs a dry-run by default)
5. When a real Windows Firewall rule is requested, it:
   - Attempts the rule
   - Verifies the rule was actually created
   - Clearly tells the user if Administrator rights are required
6. Logs every decision to a local SQLite audit database that can be exported

## What Geordie AI Does **Not** Do
- It does **not** inspect individual packets or attribute traffic to a remote attacker with certainty
- It does **not** automatically block live traffic unless the user turns Dry-run mode **OFF** and runs the app as Administrator
- The displayed accuracy is measured only on synthetic training data — it is **not** real-world detection performance
- SQLite logs are not cryptographically immutable

These limitations are shown clearly in the interface so users (and judges) always know what the tool can and cannot claim.

## Tech Stack
| Component              | Technology                          |
|------------------------|-------------------------------------|
| Frontend / Dashboard   | Streamlit + Plotly                  |
| Machine Learning       | scikit-learn (Isolation Forest + Random Forest) |
| Host Telemetry         | psutil                              |
| Database               | SQLite                              |
| Enforcement (Windows)  | netsh (with verification)           |
| Language               | Python 3                            |

## Project Structure