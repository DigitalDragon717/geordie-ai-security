"""Geordie AI Security – Congressional App Challenge ready version."""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import psutil
import time
import sqlite3
from datetime import datetime
from typing import List

from ai_engine import train_models, FEATURE_NAMES
from decision_engine import DecisionEngine
from enforcer import Enforcer

st.set_page_config(page_title="Geordie AI Security", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
.stApp { background-color: #0f172a; color: #e2e8f0; }
h1,h2,h3,h4 { color: #f8fafc !important; font-weight: 600 !important; }
section[data-testid="stSidebar"] { background-color: #0b1329 !important; }
.stButton>button { background-color: #334155; color: #f8fafc; border-radius: 4px; border: 1px solid #475569; width: 100%; }
.stButton>button:hover { background-color: #475569; }
</style>
""", unsafe_allow_html=True)

DB_NAME = "geordie_audit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            threat_type TEXT,
            anomaly_score REAL,
            risk_score INTEGER,
            confidence REAL,
            action_taken TEXT,
            action_verified INTEGER DEFAULT 0,
            needs_admin INTEGER DEFAULT 0,
            mitre_id TEXT,
            nist_control TEXT,
            notes TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def log_incident(source_ip, threat_type, anomaly_score, risk_score, confidence,
                 action, verified, needs_admin, mitre_id, nist_control, notes=""):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_logs
        (timestamp, source_ip, threat_type, anomaly_score, risk_score, confidence,
         action_taken, action_verified, needs_admin, mitre_id, nist_control, notes)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), source_ip, threat_type,
          anomaly_score, risk_score, confidence, action, int(verified), int(needs_admin),
          mitre_id, nist_control, notes))
    conn.commit()
    conn.close()

def get_recent_logs(limit=50):
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query(f"SELECT * FROM audit_logs ORDER BY id DESC LIMIT {limit}", conn)
    conn.close()
    return df

@st.cache_resource
def load_models():
    iso, rf, acc = train_models(2500)
    return iso, rf, round(acc * 100, 2)

iso_model, rf_model, synthetic_accuracy = load_models()
engine = DecisionEngine(iso_model, rf_model)

def collect_host_telemetry(sample_seconds: float = 1.0) -> List[float]:
    start = psutil.net_io_counters()
    time.sleep(sample_seconds)
    end = psutil.net_io_counters()
    packets = (end.packets_sent + end.packets_recv) - (start.packets_sent + start.packets_recv)
    bytes_ = (end.bytes_sent + end.bytes_recv) - (start.bytes_sent + start.bytes_recv)
    errors = (end.errin + end.errout) - (start.errin + start.errout)
    packets_per_sec = packets / sample_seconds
    bytes_per_sec = bytes_ / sample_seconds
    error_rate = errors / max(packets, 1)
    cpu = psutil.cpu_percent(interval=None)
    entropy_proxy = round(2.8 + (cpu / 30.0), 2)
    conns = psutil.net_connections(kind="inet")
    active = len([c for c in conns if c.status == "ESTABLISHED"])
    unique_ports = len({c.laddr.port for c in conns if c.laddr})
    return [float(packets_per_sec), float(bytes_per_sec), float(error_rate),
            float(entropy_proxy), float(active), float(unique_ports)]

# ---------- Sidebar ----------
st.sidebar.title("Geordie AI Controls")
st.sidebar.markdown(f"**Synthetic accuracy:** {synthetic_accuracy}%")
st.sidebar.caption("Measured only on synthetic data – not real-world performance.")
st.sidebar.divider()

dry_run = st.sidebar.toggle("Dry-run mode (recommended for safety)", value=True)
st.sidebar.caption("When ON, no firewall rules are ever created.")

run_live = st.sidebar.button("Run Live Host Scan", type="primary")
st.sidebar.divider()
st.sidebar.markdown("### Simulation")
sim_ddos = st.sidebar.button("Simulate DDoS")
sim_port = st.sidebar.button("Simulate Port Scan")
sim_exfil = st.sidebar.button("Simulate Exfiltration")
st.sidebar.divider()
st.sidebar.info("Live metrics are host aggregates (psutil). They detect baseline deviation, not individual packet attacks.")

# ---------- Header ----------
st.title("🛡️ Geordie AI Security")
st.caption("Educational host-level anomaly detection • Verified response • Congressional App Challenge")

logs = get_recent_logs(100)
total = len(logs)
high = len(logs[logs["risk_score"] > 70]) if not logs.empty else 0
verified_count = len(logs[logs["action_verified"] == 1]) if not logs.empty else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Host", "Online")
c2.metric("Events", total)
c3.metric("High Risk", high)
c4.metric("Verified Actions", verified_count)

st.divider()

tab_ops, tab_summary, tab_arch, tab_audit = st.tabs(["Live Operations", "Analyst Summary", "Model Architecture", "Audit Log"])

with tab_ops:
    st.subheader("Telemetry & Decision")

    if sim_ddos:
        features = [2650.0, 510000.0, 0.45, 1.15, 195, 3]
        source_ip = "45.33.21.112"
        label = "Simulated DDoS"
    elif sim_port:
        features = [820.0, 15500.0, 0.15, 5.7, 155, 105]
        source_ip = "185.220.101.45"
        label = "Simulated Port Scan"
    elif sim_exfil:
        features = [155.0, 1950000.0, 0.018, 7.7, 7, 2]
        source_ip = "192.168.50.88"
        label = "Simulated Exfiltration"
    else:
        features = collect_host_telemetry(1.0)
        source_ip = "127.0.0.1 (local host counters)"
        label = "Live host metrics"

    decision = engine.evaluate(features)

    verified = False
    needs_admin = False
    notes = ""
    final_action = decision["action"]

    # Enforcement path
    if decision["action"] == "RECOMMEND_FIREWALL_BLOCK":
        ok, msg, needs_admin = Enforcer.block_ip(source_ip, dry_run=dry_run)
        verified = ok
        notes = msg
        if dry_run:
            final_action = "RECOMMEND_FIREWALL_BLOCK (dry-run)"
        else:
            final_action = f"FIREWALL_BLOCK → {'VERIFIED' if ok else 'FAILED'}"

    log_incident(
        source_ip, decision["threat_type"], decision["anomaly_score"],
        decision["risk_score"], decision["confidence"], final_action,
        verified, needs_admin, decision["mitre_id"], decision["nist_control"], notes
    )

    left, right = st.columns([2, 1])
    with left:
        st.markdown(f"**Source:** `{label}`  |  **Address:** `{source_ip}`")
        feat_df = pd.DataFrame({"Feature": FEATURE_NAMES, "Value": [round(v, 3) for v in features]})
        st.dataframe(feat_df, use_container_width=True, hide_index=True)
        st.info("Live metrics = host aggregates only. Useful for baseline deviation, not packet-level attribution.")

    with right:
        st.metric("Threat", decision["threat_type"])
        st.metric("Risk", f"{decision['risk_score']}/100")
        st.metric("Confidence", f"{decision['confidence']}%")
        st.metric("Anomaly Score", decision["anomaly_score"])

        if decision["is_anomaly"]:
            st.error(f"**Action:** {final_action}")
        else:
            st.success(f"**Action:** {final_action}")

        if notes:
            st.caption(notes)

        # ===== ADMIN ELEVATION POPUP / GUIDANCE =====
        if needs_admin:
            st.warning("⚠️ Administrator privileges required")
            with st.expander("How to run with admin rights (required for real firewall rules)", expanded=True):
                st.markdown("""
                **The firewall command failed because this app is not running as Administrator.**

                ### Quick fix:
                1. Close this browser tab and the terminal window.
                2. Right-click `Run_Geordie_AI.bat`
                3. Choose **Run as administrator**
                4. Click Yes on the Windows UAC prompt
                5. Re-run the simulation / live scan

                After elevation, turn **Dry-run mode OFF** and try the DDoS simulation again.
                The rule will be created and automatically verified.
                """)
                st.code("Right-click → Run as administrator", language="text")

with tab_summary:
    st.subheader("Latest Incident")
    latest = get_recent_logs(1)
    if not latest.empty:
        row = latest.iloc[0]
        st.markdown(f"""
        **ID:** `INC-{row['id']:05d}`  
        **Time:** {row['timestamp']}  
        **Source:** `{row['source_ip']}`  
        **Threat:** {row['threat_type']}  
        **Risk:** **{row['risk_score']}/100**  
        **Action:** {row['action_taken']}  
        **Verified:** {"Yes" if row['action_verified'] else "No"}  
        **Needed Admin:** {"Yes" if row.get('needs_admin') else "No"}  
        **MITRE:** {row['mitre_id']}  
        **NIST:** {row['nist_control']}
        """)
        if row.get("notes"):
            st.code(row["notes"])
    else:
        st.info("No incidents yet.")

with tab_arch:
    st.subheader("Detection Pipeline")
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("#### Isolation Forest")
        st.write("Unsupervised anomaly detection on synthetic baseline.")
    with col_b:
        st.markdown("#### Random Forest")
        st.write(f"Supervised classification. Synthetic accuracy: **{synthetic_accuracy}%**")
    st.warning("Accuracy is synthetic only. Real-world performance is unknown.")
    fi = pd.DataFrame({"Feature": FEATURE_NAMES, "Importance": rf_model.feature_importances_})
    fi = fi.sort_values("Importance")
    fig = px.bar(fi, x="Importance", y="Feature", orientation="h", template="plotly_dark", title="Feature Importance")
    st.plotly_chart(fig, use_container_width=True)

with tab_audit:
    st.subheader("Audit Trail")
    st.caption("SQLite log – export for external archiving. Not cryptographically immutable.")
    audit = get_recent_logs(100)
    if not audit.empty:
        st.dataframe(audit, use_container_width=True)
        st.download_button("Download CSV", audit.to_csv(index=False).encode(), 
                           f"geordie_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv", "text/csv")
    else:
        st.info("Empty.")