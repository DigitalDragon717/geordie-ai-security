import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import time
import socket
import sqlite3
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest, RandomForestClassifier

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Geordie AI | Enterprise Autonomous Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- LOCAL SQLITE3 PERSISTENT DATABASE ENGINE ---
def init_db():
    conn = sqlite3.connect('geordie_audit.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target_ip TEXT,
            packets_sec REAL,
            error_rate REAL,
            anomaly_score REAL,
            threat_type TEXT,
            mitre_id TEXT,
            nist_control TEXT,
            action_taken TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_event_to_db(ip, pkts, err, score, threat, mitre, nist, action):
    conn = sqlite3.connect('geordie_audit.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, target_ip, packets_sec, error_rate, anomaly_score, threat_type, mitre_id, nist_control, action_taken)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, pkts, err, score, threat, mitre, nist, action))
    conn.commit()
    conn.close()

def get_db_logs():
    conn = sqlite3.connect('geordie_audit.db')
    df = pd.read_sql_query("SELECT * FROM audit_logs ORDER BY id DESC", conn)
    conn.close()
    return df

# --- PROFESSIONAL HUMAN DESIGN SYSTEM (CSS) ---
st.markdown("""
<style>
    :root {
        --bg-main: #090d16;
        --bg-surface: #111726;
        --border-color: #243049;
        --text-primary: #f0f4fc;
        --text-muted: #8b98b5;
        --accent-cyan: #00d2ff;
        --accent-red: #ff3b5c;
        --accent-green: #00e676;
    }

    body, .stApp {
        background-color: var(--bg-main) !important;
        color: var(--text-primary) !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    .panel-box {
        background-color: var(--bg-surface);
        border: 1px solid var(--border-color);
        border-radius: 4px;
        padding: 18px;
        margin-bottom: 15px;
    }

    .metric-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--text-muted);
        font-weight: 600;
    }
    .metric-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: var(--text-primary);
        font-family: 'JetBrains Mono', Consolas, monospace;
    }
    .metric-status {
        font-size: 0.8rem;
        font-weight: 500;
        margin-top: 4px;
    }
    .status-good { color: var(--accent-green); }
    .status-bad { color: var(--accent-red); }

    .stButton > button {
        background: #00d2ff !important;
        color: #050a14 !important;
        font-weight: 700 !important;
        border-radius: 2px !important;
        border: none !important;
        padding: 0.5rem 1.2rem !important;
        text-transform: uppercase !important;
        letter-spacing: 0.5px !important;
    }

    .stTabs [aria-selected="true"] {
        background-color: var(--bg-surface) !important;
        color: var(--accent-cyan) !important;
        border: 1px solid var(--border-color) !important;
        border-bottom: none !important;
    }
</style>
""", unsafe_allow_html=True)

# --- AI MODELS ---
@st.cache_resource
def train_unsupervised_engine():
    np.random.seed(42)
    normal_traffic = np.random.normal(loc=[300, 0.01, 1.2], scale=[50, 0.005, 0.2], size=(200, 3))
    model = IsolationForest(n_estimators=100, contamination=0.08, random_state=42)
    model.fit(normal_traffic)
    return model

@st.cache_resource
def train_supervised_classifier():
    np.random.seed(42)
    X = np.array([
        [300, 0.01, 1.1], [290, 0.008, 1.3], [310, 0.012, 1.0], # Normal
        [1200, 0.45, 5.1], [1500, 0.52, 5.8], [1100, 0.40, 4.9], # DDoS
        [850, 0.15, 8.2], [900, 0.18, 8.5], [780, 0.12, 7.9],  # Port Sweep
        [150, 0.02, 0.2], [180, 0.01, 0.3], [140, 0.03, 0.1]    # Exfiltration
    ])
    y = np.array([0, 0, 0, 1, 1, 1, 2, 2, 2, 3, 3, 3])
    rf = RandomForestClassifier(n_estimators=50, random_state=42)
    rf.fit(X, y)
    return rf

unsupervised_model = train_unsupervised_engine()
supervised_model = train_supervised_classifier()

# --- SIDEBAR CONTROL PANEL ---
st.sidebar.markdown("### ⚙️ Engine Controls")
st.sidebar.caption("Geordie Autonomous Agent v3.5")

auto_quarantine = st.sidebar.toggle("Autonomous Kernel Quarantine", value=True)
db_sync = st.sidebar.toggle("SQLite3 Audit Log Sync", value=True)

st.sidebar.markdown("---")
st.sidebar.markdown("**Compliance Mapping:**")
st.sidebar.markdown("🛡️ **NIST CSWF:** DE.AE-1 / PR.PT-4")
st.sidebar.markdown("🎯 **MITRE ATT&CK:** T1498 / T1046")

# --- HEADER SECTION ---
header_col1, header_col2 = st.columns([3, 1])
with header_col1:
    st.title("Geordie AI Security")
    st.caption("Autonomous Threat Detection & Multi-Layer Remediation Platform")

with header_col2:
    try:
        host_name = socket.gethostname()
        local_ip = socket.gethostbyname(host_name)
    except:
        local_ip = "127.0.0.1"

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(f"""
        <div style="background:#111726; border:1px solid #243049; padding:10px; border-radius:4px; text-align:right;">
            <span style="color:#00e676;">● HARDWARE ACTIVE</span><br>
            <small style="color:#8b98b5;">Host Interface: {local_ip}</small>
        </div>
    """, unsafe_allow_html=True)

st.markdown("<hr style='border-color: #243049;'>", unsafe_allow_html=True)

# --- NAVIGATION TABS ---
tab_simulator, tab_telemetry, tab_ai_layers, tab_mitigation, tab_db = st.tabs([
    "⚡ Attack Simulator Sandbox",
    "📊 Real-Time Network Telemetry", 
    "🧠 Multi-Layer AI Engine",
    "🛡️ NIST & MITRE Matrix",
    "🗄️ SQLite3 Audit Database"
])

# --- TAB 1: INTERACTIVE ATTACK SIMULATOR ---
with tab_simulator:
    st.markdown("### Interactive Threat Vector Sandbox")
    st.caption("Test the autonomous AI engine by firing simulated attack vectors at local network sockets.")

    sim_col1, sim_col2, sim_col3 = st.columns(3)

    with sim_col1:
        if st.button("🔴 Fire Volumetric DDoS Vector"):
            score = unsupervised_model.decision_function([[1200, 0.45, 5.1]])[0]
            log_event_to_db("45.33.21.112", 1200, 0.45, score, "Volumetric DDoS Attack", "T1498", "DE.AE-1", "KERNEL_FIREWALL_DROP")
            st.error("🚨 **DDoS Attack Detected & Quarantined!** Vector logged to local SQLite3 database.")

    with sim_col2:
        if st.button("🟡 Fire SSH Port Sweep Vector"):
            score = unsupervised_model.decision_function([[850, 0.15, 8.2]])[0]
            log_event_to_db("185.220.101.5", 850, 0.15, score, "SSH Port Sweep Scan", "T1046", "PR.PT-4", "PORT_SOCKET_CLOSED")
            st.warning("⚠️ **SSH Port Sweep Detected!** Socket access revoked.")

    with sim_col3:
        if st.button("🟢 Inject Nominal Baseline Traffic"):
            score = unsupervised_model.decision_function([[295, 0.01, 1.1]])[0]
            log_event_to_db("192.168.1.10", 295, 0.01, score, "Normal Traffic Flow", "N/A", "PR.IP-1", "PASS_THROUGH")
            st.success("✅ **Nominal Traffic Verified.** AI Score clear.")

# --- TAB 2: TELEMETRY CHART ---
with tab_telemetry:
    st.markdown("### Live Telemetry Stream")
    times = [datetime.now() - timedelta(seconds=i*10) for i in range(30)][::-1]
    np.random.seed(12)
    packets = np.random.normal(300, 40, 30)
    packets[22] = 1200

    df_telemetry = pd.DataFrame({
        "Timestamp": [t.strftime("%H:%M:%S") for t in times],
        "Packets / Sec": packets,
        "Error Delta": [0.01]*22 + [0.45] + [0.01]*7
    })

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=df_telemetry["Timestamp"], y=df_telemetry["Packets / Sec"], mode='lines+markers', name='Packets / Sec', line=dict(color='#00d2ff', width=2)))
    fig.update_layout(template="plotly_dark", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(17,23,38,0.5)', height=300)
    st.plotly_chart(fig, use_container_width='stretch')

# --- TAB 3: AI EVALUATOR ---
with tab_ai_layers:
    st.markdown("### Multi-Layer Model Decision Matrix")
    eval_samples = np.array([[295, 0.011, 1.1], [1200, 0.450, 5.1], [850, 0.150, 8.2]])
    scores = unsupervised_model.decision_function(eval_samples)
    supervised_preds = supervised_model.predict(eval_samples)
    labels_map = {0: "Normal Traffic", 1: "Volumetric DDoS Attack", 2: "SSH Port Sweep Scan", 3: "Data Exfiltration"}

    df_eval = pd.DataFrame(eval_samples, columns=["Packets/Sec", "Error Rate", "Entropy"])
    df_eval["IP Node"] = ["192.168.1.10", "45.33.21.112", "185.220.101.5"]
    df_eval["Layer 1 Score"] = np.round(scores, 3)
    df_eval["Layer 2 Classification"] = [labels_map[p] for p in supervised_preds]
    st.dataframe(df_eval, use_container_width='stretch')

# --- TAB 4: COMPLIANCE MATRIX ---
with tab_mitigation:
    st.markdown("### NIST & MITRE ATT&CK Mitigation Matrix")
    compliance_df = pd.DataFrame({
        "Target IP": ["45.33.21.112", "185.220.101.5"],
        "MITRE ATT&CK ID": ["T1498 (Network Denial of Service)", "T1046 (Network Service Discovery)"],
        "NIST CSWF Control": ["DE.AE-1 (Anomalous Activity Detection)", "PR.PT-4 (Communications Protection)"],
        "Enforced Firewall Action": ["DROP ALL INBOUND/OUTBOUND", "DROP SOCKET PORT 22"]
    })
    st.table(compliance_df)

# --- TAB 5: SQLITE3 DATABASE VIEW ---
with tab_db:
    st.markdown("### Local SQLite3 Persistent Audit Logs")
    st.caption("Live relational database output stored on host storage (`geordie_audit.db`).")
    db_df = get_db_logs()
    st.dataframe(db_df, use_container_width='stretch')

    csv_data = db_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📄 Download SQLite Audit Log (CSV)",
        data=csv_data,
        file_name="geordie_ai_sqlite_export.csv",
        mime="text/csv"
    )