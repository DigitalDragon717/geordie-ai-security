"""
Geordie AI Security – Premium UI Redesign
Congressional App Challenge Edition
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import psutil
import time
import sqlite3
from datetime import datetime
from typing import List

from ai_engine import train_models, FEATURE_NAMES
from decision_engine import DecisionEngine
from enforcer import Enforcer

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="Geordie AI Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# PREMIUM CYBERSECURITY THEME
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ---------- Base ---------- */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.stApp {
    background: linear-gradient(165deg, #070b14 0%, #0c1220 40%, #0a101c 100%);
    color: #e2e8f0;
}

/* ---------- Typography ---------- */
h1, h2, h3, h4 {
    font-family: 'Inter', sans-serif !important;
    letter-spacing: -0.03em !important;
    color: #f1f5f9 !important;
}

/* ---------- Sidebar ---------- */
section[data-testid="stSidebar"] {
    background: #080d18 !important;
    border-right: 1px solid #1e293b;
}

section[data-testid="stSidebar"] .stMarkdown {
    color: #94a3b8;
}

/* ---------- Buttons ---------- */
.stButton > button {
    background: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 6px;
    font-weight: 500;
    font-size: 0.9rem;
    padding: 0.55rem 1rem;
    transition: all 0.18s ease;
    width: 100%;
}

.stButton > button:hover {
    background: #334155;
    border-color: #475569;
    color: #fff;
    box-shadow: 0 0 0 1px #22d3ee33;
}

.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, #0e7490, #0891b2);
    border: 1px solid #22d3ee55;
    color: white;
}

.stButton > button[kind="primary"]:hover {
    background: linear-gradient(135deg, #0891b2, #06b6d4);
    box-shadow: 0 0 12px #22d3ee44;
}

/* ---------- Metrics ---------- */
[data-testid="stMetric"] {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 8px;
    padding: 12px 16px;
}

[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 0.8rem !important;
    font-weight: 500 !important;
}

[data-testid="stMetricValue"] {
    color: #f1f5f9 !important;
    font-weight: 600 !important;
}

/* ---------- Tabs ---------- */
.stTabs [data-baseweb="tab-list"] {
    gap: 4px;
    background: transparent;
    border-bottom: 1px solid #1e293b;
}

.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: #64748b;
    border-radius: 6px 6px 0 0;
    padding: 10px 18px;
    font-weight: 500;
}

.stTabs [aria-selected="true"] {
    background: #0f172a !important;
    color: #22d3ee !important;
    border-bottom: 2px solid #22d3ee !important;
}

/* ---------- Dataframes ---------- */
[data-testid="stDataFrame"] {
    border: 1px solid #1e293b;
    border-radius: 8px;
    overflow: hidden;
}

/* ---------- Custom Cards ---------- */
.geo-card {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
}

.geo-card-header {
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: #64748b;
    margin-bottom: 0.5rem;
}

.geo-status-normal {
    background: #052e16;
    border: 1px solid #166534;
    color: #4ade80;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    font-weight: 600;
    text-align: center;
}

.geo-status-alert {
    background: #450a0a;
    border: 1px solid #991b1b;
    color: #f87171;
    padding: 0.6rem 1rem;
    border-radius: 6px;
    font-weight: 600;
    text-align: center;
}

.geo-badge {
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.03em;
}

.geo-badge-cyan {
    background: #083344;
    color: #22d3ee;
    border: 1px solid #0e7490;
}

.geo-badge-green {
    background: #052e16;
    color: #4ade80;
    border: 1px solid #166534;
}

.geo-badge-red {
    background: #450a0a;
    color: #f87171;
    border: 1px solid #991b1b;
}

.geo-mono {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.85rem;
}

/* ---------- Divider ---------- */
hr {
    border-color: #1e293b !important;
}

/* ---------- Info / Warning boxes ---------- */
.stAlert {
    border-radius: 8px;
}
</style>
""", unsafe_allow_html=True)

# ============================================================
# DATABASE
# ============================================================
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

# ============================================================
# MODELS
# ============================================================
@st.cache_resource
def load_models():
    iso, rf, acc = train_models(2500)
    return iso, rf, round(acc * 100, 2)

iso_model, rf_model, synthetic_accuracy = load_models()
engine = DecisionEngine(iso_model, rf_model)

# ============================================================
# TELEMETRY
# ============================================================
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

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("### 🛡️ Geordie AI")
    st.caption("Host-level anomaly detection")
    
    st.markdown(f"""
    <div style="background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:12px 14px;margin:12px 0;">
        <div style="font-size:0.7rem;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;">Synthetic Accuracy</div>
        <div style="font-size:1.4rem;font-weight:600;color:#22d3ee;margin-top:2px;">{synthetic_accuracy}%</div>
        <div style="font-size:0.72rem;color:#64748b;margin-top:4px;">Synthetic data only</div>
    </div>
    """, unsafe_allow_html=True)

    dry_run = st.toggle("Dry-run mode", value=True)
    st.caption("Recommended. No firewall rules created when ON.")

    st.divider()
    
    st.markdown("**Operations**")
    run_live = st.button("Run Live Host Scan", type="primary", use_container_width=True)
    
    st.markdown("**Simulations**")
    sim_ddos = st.button("Simulate DDoS", use_container_width=True)
    sim_port = st.button("Simulate Port Scan", use_container_width=True)
    sim_exfil = st.button("Simulate Exfiltration", use_container_width=True)
    
    st.divider()
    guided_demo = st.button("▶ Guided Demo", use_container_width=True)
    
    st.divider()
    st.markdown("""
    <div style="font-size:0.75rem;color:#64748b;line-height:1.5;">
    Live metrics are host aggregates (psutil).<br>
    They detect baseline deviation, not individual packet attacks.
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# HEADER
# ============================================================
st.markdown("""
<div style="margin-bottom:0.5rem;">
    <h1 style="margin:0;font-size:1.85rem;font-weight:700;">Geordie AI Security</h1>
    <p style="margin:4px 0 0 0;color:#94a3b8;font-size:0.95rem;">
        Educational host-level anomaly detection · Verified response · Congressional App Challenge
    </p>
</div>
""", unsafe_allow_html=True)

# Top metrics
logs = get_recent_logs(100)
total = len(logs)
high = len(logs[logs["risk_score"] > 70]) if not logs.empty else 0
verified_count = len(logs[logs["action_verified"] == 1]) if not logs.empty else 0

m1, m2, m3, m4 = st.columns(4)
m1.metric("Host Status", "Online")
m2.metric("Events Logged", total)
m3.metric("High Risk", high)
m4.metric("Verified Actions", verified_count)

st.divider()

# ============================================================
# TABS
# ============================================================
tab_ops, tab_summary, tab_arch, tab_learn, tab_audit = st.tabs([
    "Live Operations", "Analyst Summary", "Model Architecture", "Learn", "Audit Log"
])

# ============================================================
# TAB 1 – LIVE OPERATIONS
# ============================================================
with tab_ops:
    # Determine what to run
    features = collect_host_telemetry(0.7)
    source_ip = "127.0.0.1 (local host counters)"
    label = "Live host metrics"
    force_decision = None

    if guided_demo:
        st.info("▶ Guided Demo: showing Normal baseline first, then a DDoS simulation.")
        features = [280, 42000, 0.01, 3.0, 15, 8]
        source_ip = "127.0.0.1"
        label = "Guided Demo – Normal Traffic"
        force_decision = engine.evaluate(features)
    elif sim_ddos:
        features = [2850.0, 620000.0, 0.48, 1.05, 220, 3]
        source_ip = "45.33.21.112"
        label = "Simulated Volumetric DDoS"
    elif sim_port:
        features = [920.0, 18500.0, 0.18, 6.1, 175, 130]
        source_ip = "185.220.101.45"
        label = "Simulated Port Scan"
    elif sim_exfil:
        features = [180.0, 2400000.0, 0.02, 7.9, 8, 2]
        source_ip = "192.168.50.88"
        label = "Simulated Data Exfiltration"
    elif run_live:
        features = collect_host_telemetry(1.0)
        source_ip = "127.0.0.1 (local host counters)"
        label = "Live host metrics"

    decision = force_decision if force_decision else engine.evaluate(features)

    # Enforcement
    verified = False
    needs_admin = False
    notes = ""
    final_action = decision["action"]

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

    # Layout
    left, right = st.columns([2.3, 1], gap="large")

    with left:
        st.markdown(f"""
        <div style="margin-bottom:12px;">
            <span class="geo-badge geo-badge-cyan">{label}</span>
            <span style="margin-left:10px;font-family:'JetBrains Mono',monospace;font-size:0.85rem;color:#94a3b8;">
                {source_ip}
            </span>
        </div>
        """, unsafe_allow_html=True)

        feat_df = pd.DataFrame({
            "Feature": FEATURE_NAMES,
            "Value": [round(v, 3) for v in features]
        })
        st.dataframe(feat_df, use_container_width=True, hide_index=True, height=260)

        st.caption("Live metrics are host aggregates only. Useful for baseline deviation, not packet-level attribution.")

    with right:
        # Threat
        st.markdown('<div class="geo-card-header">Threat Classification</div>', unsafe_allow_html=True)
        st.markdown(f"<div style='font-size:1.5rem;font-weight:600;margin-bottom:12px;'>{decision['threat_type']}</div>", unsafe_allow_html=True)

        # Risk
        risk = decision["risk_score"]
        if risk >= 70:
            risk_badge = "geo-badge-red"
            risk_label = "HIGH"
        elif risk >= 40:
            risk_badge = "geo-badge-cyan"
            risk_label = "MEDIUM"
        else:
            risk_badge = "geo-badge-green"
            risk_label = "LOW"

        st.markdown(f"""
        <div class="geo-card-header">Risk Score</div>
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;">
            <span style="font-size:1.6rem;font-weight:700;">{risk}/100</span>
            <span class="geo-badge {risk_badge}">{risk_label}</span>
        </div>
        """, unsafe_allow_html=True)

        # Confidence + Anomaly
        c1, c2 = st.columns(2)
        c1.metric("Confidence", f"{decision['confidence']}%")
        c2.metric("Anomaly", decision["anomaly_score"])

        # Action status
        st.markdown('<div class="geo-card-header" style="margin-top:8px;">Recommended Action</div>', unsafe_allow_html=True)
        if decision["threat_type"] == "Normal":
            st.markdown(f'<div class="geo-status-normal">{final_action}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="geo-status-alert">{final_action}</div>', unsafe_allow_html=True)

        if notes:
            st.caption(notes)

        if needs_admin:
            st.warning("Administrator privileges required")
            with st.expander("How to elevate"):
                st.markdown("""
                1. Close this window  
                2. Right-click `Run_Geordie_AI.bat`  
                3. Select **Run as administrator**  
                4. Turn Dry-run **OFF** and retry
                """)

# ============================================================
# TAB 2 – ANALYST SUMMARY
# ============================================================
with tab_summary:
    st.subheader("Latest Incident Briefing")
    latest = get_recent_logs(1)
    if not latest.empty:
        row = latest.iloc[0]
        st.markdown(f"""
        <div class="geo-card">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                <span class="geo-badge geo-badge-cyan">INC-{row['id']:05d}</span>
                <span style="color:#64748b;font-size:0.85rem;">{row['timestamp']}</span>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
                <div>
                    <div class="geo-card-header">Source</div>
                    <div class="geo-mono">{row['source_ip']}</div>
                </div>
                <div>
                    <div class="geo-card-header">Threat</div>
                    <div style="font-weight:600;">{row['threat_type']}</div>
                </div>
                <div>
                    <div class="geo-card-header">Risk</div>
                    <div style="font-weight:600;">{row['risk_score']}/100</div>
                </div>
                <div>
                    <div class="geo-card-header">Confidence</div>
                    <div>{row['confidence']}%</div>
                </div>
                <div>
                    <div class="geo-card-header">MITRE</div>
                    <div style="font-size:0.9rem;">{row['mitre_id']}</div>
                </div>
                <div>
                    <div class="geo-card-header">NIST</div>
                    <div style="font-size:0.9rem;">{row['nist_control']}</div>
                </div>
            </div>
            <div style="margin-top:16px;">
                <div class="geo-card-header">Action Taken</div>
                <div style="font-weight:500;">{row['action_taken']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        if row.get("notes"):
            st.code(row["notes"], language="text")
    else:
        st.info("No incidents recorded yet. Run a scan or simulation.")

# ============================================================
# TAB 3 – MODEL ARCHITECTURE
# ============================================================
with tab_arch:
    st.subheader("Detection Pipeline")

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("""
        <div class="geo-card">
            <div class="geo-card-header">Layer 1 · Anomaly Detection</div>
            <div style="font-size:1.15rem;font-weight:600;margin:6px 0;">Isolation Forest</div>
            <p style="color:#94a3b8;font-size:0.9rem;margin:0;">
                Unsupervised model that isolates unusual telemetry vectors without relying on labeled attack data.
            </p>
        </div>
        """, unsafe_allow_html=True)

    with col_b:
        st.markdown(f"""
        <div class="geo-card">
            <div class="geo-card-header">Layer 2 · Classification</div>
            <div style="font-size:1.15rem;font-weight:600;margin:6px 0;">Random Forest</div>
            <p style="color:#94a3b8;font-size:0.9rem;margin:0;">
                Supervised classifier. Synthetic hold-out accuracy: <strong style="color:#22d3ee;">{synthetic_accuracy}%</strong>
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.warning("Accuracy figures are measured only on synthetic data. They do not represent real-world detection performance.")

    fi = pd.DataFrame({
        "Feature": FEATURE_NAMES,
        "Importance": rf_model.feature_importances_
    }).sort_values("Importance")

    fig = px.bar(
        fi, x="Importance", y="Feature", orientation="h",
        template="plotly_dark",
        title="Feature Importance"
    )
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#94a3b8",
        title_font_color="#e2e8f0",
        height=300,
        margin=dict(l=10, r=10, t=40, b=10)
    )
    fig.update_traces(marker_color="#22d3ee")
    st.plotly_chart(fig, use_container_width=True)

# ============================================================
# TAB 4 – LEARN
# ============================================================
with tab_learn:
    st.subheader("How Geordie AI Works")

    st.markdown("""
    <div class="geo-card">
        <div class="geo-card-header">Design Philosophy</div>
        <p style="margin:0;color:#cbd5e1;line-height:1.6;">
            Most student cybersecurity projects either display fake data or attempt dangerous real system changes.
            Geordie AI was built to be honest, safe by default, and educational.
        </p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("""
        <div class="geo-card">
            <div class="geo-card-header">Isolation Forest</div>
            <p style="margin:0;color:#94a3b8;font-size:0.9rem;line-height:1.55;">
                Finds data points that are easy to isolate from the rest of the distribution.
                Ideal for detecting previously unseen anomalies.
            </p>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown("""
        <div class="geo-card">
            <div class="geo-card-header">Random Forest</div>
            <p style="margin:0;color:#94a3b8;font-size:0.9rem;line-height:1.55;">
                Ensemble of decision trees that classifies anomalies into
                Normal, DDoS, Port Scan, or Exfiltration.
            </p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("""
    <div class="geo-card">
        <div class="geo-card-header">Safety Architecture</div>
        <ul style="margin:8px 0 0 0;padding-left:1.1rem;color:#94a3b8;line-height:1.7;">
            <li>Dry-run mode is the default</li>
            <li>Every firewall rule is verified after creation</li>
            <li>Clear warning when Administrator rights are required</li>
            <li>No automatic process termination</li>
            <li>Full audit trail of every decision</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="geo-card">
        <div class="geo-card-header">Framework Mapping</div>
        <p style="margin:0;color:#94a3b8;font-size:0.9rem;line-height:1.55;">
            Detections are mapped to MITRE ATT&CK techniques and NIST controls
            so students learn the same language used by professional security teams.
        </p>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# TAB 5 – AUDIT LOG
# ============================================================
with tab_audit:
    st.subheader("Audit Trail")
    st.caption("Local SQLite log. Export for external archiving. Not cryptographically immutable.")

    audit = get_recent_logs(100)
    if not audit.empty:
        st.dataframe(audit, use_container_width=True, height=380)
        csv = audit.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download CSV Report",
            data=csv,
            file_name=f"geordie_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=False
        )
    else:
        st.info("Audit log is empty.")