import sys

# Must be launched with: streamlit run app.py (not: python app.py)
if __name__ == "__main__":
    try:
        from streamlit.runtime.scriptrunner_utils.script_run_context import get_script_run_ctx
        if get_script_run_ctx() is None:
            print("Open Nazca is a Streamlit app. Run with: streamlit run app.py")
            sys.exit(1)
    except Exception:
        pass

import streamlit as st
import os
import re
import html as html_module
import json
import tempfile
import traceback
import difflib
from pathlib import Path
from datetime import datetime
import time
import plotly.express as px
import pandas as pd
import plotly.graph_objects as go

from src.scanner import AICodeScanner
from src.rag_manager import RAGManager
import networkx as nx

# Page configuration
st.set_page_config(
    page_title="Open Nazca",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS for Dark Analytics Theme ---
st.markdown("""
<style>
    /* Main Background */
    .stApp {
        background-color: #000E1A; /* Very dark navy */
        color: #ffffff;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #0f172a; /* Deep Slate Sidebar */
        border-right: 1px solid #334155;
    }
    
    /* Sidebar premium buttons (Launch Scan) */
    .stButton > button {
        width: 100%;
        border-radius: 4px;
        background: linear-gradient(135deg, #4338CA 0%, #3730A3 100%); /* Deep Indigo / Corporate Blue */
        color: white;
        border: 1px solid #312E81;
        height: 44px;
        font-weight: 600;
        letter-spacing: 0.5px;
        transition: all 0.2s;
        text-transform: uppercase;
        font-size: 14px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    
    .stButton > button:hover {
        transform: translateY(-1px);
        box-shadow: 0 0 12px rgba(99, 102, 241, 0.4);
        background: linear-gradient(135deg, #4F46E5 0%, #4338CA 100%);
        border-color: #6366F1;
        color: white;
    }

    /* Download Buttons - Secondary Hierarchy */
    .stDownloadButton > button {
        width: 100%;
        border-radius: 4px;
        background-color: #1E293B !important; /* Solid Slate Gray */
        color: #94A3B8 !important; /* Muted Text */
        border: 1px solid #334155 !important;
        height: 38px;
        font-weight: 500;
        transition: all 0.2s;
    }

    .stDownloadButton > button:hover {
        background-color: #334155 !important;
        color: white !important;
        border-color: #475569 !important;
    }
    
    /* Styled Multiselect Tags (Muted Slate) */
    span[data-baseweb="tag"] {
        background-color: #334155 !important; /* Muted Slate Blue */
        color: #E2E8F0 !important;
        border: 1px solid #475569;
        border-radius: 4px;
    }
    
    /* Remove default top padding */
    .main .block-container {
        padding-top: 1rem;
        padding-bottom: 2rem;
    }

    /* Typography */
    h1, h2, h3, h4, h5, h6, p, div {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }
    
    /* Monospace for code/security terms */
    .mono-font {
        font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace !important;
    }

    h1 {
        font-size: 24px;
        font-weight: 600;
        color: #ffffff;
        margin-bottom: 0px;
    }

    h3 {
        font-size: 18px;
        font-weight: 500;
        color: #B0B8C1;
        margin-top: 0px;
    }

    /* Sidebar Elements */
    .sidebar-logo-container {
        padding: 1.5rem 1rem;
        text-align: center;
        margin-bottom: 1rem;
        border-bottom: 1px solid #1E2D3D;
    }
    
    .sidebar-header {
        color: #94A3B8;
        font-size: 11px;
        font-weight: 700;
        margin-top: 20px;
        margin-bottom: 8px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    /* Metric Cards - Cyber Style */
    div[data-testid="metric-container"] {
        background-color: #0B1120;
        border: 1px solid #1E293B;
        border-radius: 4px;
        padding: 15px;
    }

    .metric-card {
        background-color: #0B1120; /* Darker Space Blue */
        border: 1px solid #334155; /* Sharp Border */
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
        border-radius: 4px; /* Sharper corners */
        padding: 16px;
        margin-bottom: 16px;
        min-height: 160px;
        display: flex;
        flex-direction: column;
        justify-content: space-between;
        transition: all 0.2s ease;
    }
    
    .metric-card:hover {
        border-color: #6366F1; /* Indigo Border */
        box-shadow: 0 0 20px rgba(99, 102, 241, 0.2); /* Indigo Glow */
        transform: translateY(-2px);
    }
    
    .metric-card-header {
        display: flex;
        align-items: center;
        margin-bottom: 8px;
        background-color: #1E293B;
        padding: 6px 10px;
        border-radius: 4px;
        width: fit-content;
    }
    
    .metric-icon {
        margin-right: 8px;
        font-size: 14px;
    }
    
    .metric-title {
        color: #94A3B8;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .metric-value {
        font-size: 28px;
        font-weight: 700;
        color: #ffffff;
        margin: 4px 0;
        letter-spacing: 0.5px;
        text-shadow: 0 0 10px rgba(255,255,255,0.1);
        word-wrap: break-word;
        font-family: 'JetBrains Mono', monospace; /* Tech feel for numbers */
    }
    
    .metric-subtext {
        font-size: 12px;
        color: #64748B;
        margin-top: auto;
    }

    /* Status Badges - Sharper Colors */
    .badge-critical { background-color: #DC2626; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; letter-spacing: 0.5px; border: 1px solid #EF4444; box-shadow: 0 0 8px rgba(220, 38, 38, 0.4); }
    .badge-high { background-color: #EA580C; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; border: 1px solid #F97316; }
    .badge-medium { background-color: #CA8A04; color: black; padding: 2px 8px; border-radius: 3px; font-size: 11px; border: 1px solid #EAB308; }
    .badge-low { background-color: #2563EB; color: white; padding: 2px 8px; border-radius: 3px; font-size: 11px; border: 1px solid #3B82F6; }
    
    /* Navigation */
    .stRadio label {
        font-size: 15px !important;
        padding: 8px;
        color: #E2E8F0 !important;
    }
    
    /* Chart Containers */
    div[data-testid="stPlotlyChart"] {
        background-color: #0B1120;
        border: 1px solid #334155;
        border-radius: 4px;
        padding: 0px; /* Remove padding to prevent scrollbars */
        box-shadow: 0 0 10px rgba(0, 0, 0, 0.3);
        transition: all 0.2s ease;
        overflow: hidden; /* Ensure content stays inside */
    }
    
    div[data-testid="stPlotlyChart"]:hover {
        border-color: #6366F1;
        box-shadow: 0 0 15px rgba(99, 102, 241, 0.2);
    }

    /* Responsive Metrics Grid */
    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }
    
    /* Ensure content inside doesn't overflow */
    .metric-value {
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
    }
    
    /* Responsive Charts: Force wrapping on smaller screens */
    div[data-testid="stHorizontalBlock"]:has(div[data-testid="stPlotlyChart"]) {
        flex-wrap: wrap !important;
        gap: 20px !important;
    }
    
    div[data-testid="column"]:has(div[data-testid="stPlotlyChart"]) {
        min-width: 350px !important;
        flex: 1 1 350px !important;
    }

    /* Sandbox Lab Styles */
    .sandbox-console {
        background: #020617;
        border: 1px solid #1E293B;
        border-radius: 4px;
        padding: 16px;
        font-family: 'JetBrains Mono', 'Consolas', monospace;
        font-size: 12px;
        color: #94A3B8;
        max-height: 400px;
        overflow-y: auto;
        line-height: 1.6;
    }
    .sandbox-console .log-phase { color: #818CF8; font-weight: 700; }
    .sandbox-console .log-ok    { color: #34D399; }
    .sandbox-console .log-fail  { color: #F87171; }
    .sandbox-console .log-warn  { color: #FBBF24; }
    .sandbox-console .log-dim   { color: #475569; }

    .sb-badge {
        display: inline-block;
        padding: 3px 10px;
        border-radius: 3px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .sb-confirmed   { background: #991B1B; color: #FCA5A5; border: 1px solid #DC2626; }
    .sb-remediated  { background: #064E3B; color: #6EE7B7; border: 1px solid #10B981; }
    .sb-partial     { background: #713F12; color: #FDE68A; border: 1px solid #F59E0B; }
    .sb-safe        { background: #1E3A5F; color: #93C5FD; border: 1px solid #3B82F6; }
    .sb-untested    { background: #312E81; color: #C4B5FD; border: 1px solid #7C3AED; }

    .sb-file-tag {
        display: inline-block;
        background: #1E293B;
        color: #94A3B8;
        padding: 2px 8px;
        border-radius: 3px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 11px;
        margin: 2px;
        border: 1px solid #334155;
    }

    .sb-path-row {
        display: flex;
        align-items: center;
        padding: 10px 14px;
        border-bottom: 1px solid #1E293B;
        gap: 12px;
        transition: background 0.15s;
    }
    .sb-path-row:hover { background: #0F172A; }
    .sb-path-id   { color: #64748B; font-family: monospace; font-size: 12px; min-width: 50px; }
    .sb-path-name { color: #E2E8F0; flex: 1; font-size: 13px; }

</style>
""", unsafe_allow_html=True)


# --- Helper Functions ---

def get_metric_card_html(title, value, subtext, icon="📌", color="#3B82F6"):
    return f"""<div class="metric-card">
    <div class="metric-card-header">
        <span class="metric-icon" style="color: {color};">{icon}</span>
        <span class="metric-title">{title}</span>
    </div>
    <div class="metric-value">{value}</div>
    <div class="metric-subtext">{subtext}</div>
</div>"""

def render_metrics_grid(cards):
    """Render a responsive grid of metric cards."""
    html = '<div class="metrics-grid">'
    for card in cards:
        html += get_metric_card_html(**card)
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)

def aggregate_session_data():
    """Aggregate data from all scans in history."""
    if not st.session_state.scan_history:
        return {
            'total': 0, 'critical': 0, 'high': 0, 'medium': 0,
            'files_scanned': 0, 'df_trends': pd.DataFrame(),
            'df_types': pd.DataFrame(), 'df_severity': pd.DataFrame()
        }
    
    total = 0
    sev_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    trend_data = []
    type_counts = {}
    
    for entry in st.session_state.scan_history:
        results = entry['results']
        total += results['total_findings']
        
        # Severity
        for k, v in results['severity_counts'].items():
            if k in sev_counts:
                sev_counts[k] += v
        
        # Trend
        trend_data.append({
            'Time': entry['timestamp'],
            'Findings': results['total_findings'],
            'Filename': entry['filename']
        })
        
        # Types
        for finding in results['findings']:
            t = finding['vulnerability_type']
            type_counts[t] = type_counts.get(t, 0) + 1
            
    # DataFrames for charts
    df_trends = pd.DataFrame(trend_data)
    
    df_types = pd.DataFrame([
        {'Type': k, 'Count': v} for k, v in type_counts.items()
    ]).sort_values('Count', ascending=True) # Ascending for bar chart
    
    df_severity = pd.DataFrame([
        {'Severity': k, 'Count': v} for k, v in sev_counts.items() if v > 0
    ])
    
    return {
        'total': total,
        'critical': sev_counts['CRITICAL'],
        'high': sev_counts['HIGH'],
        'medium': sev_counts['MEDIUM'],
        'files_scanned': len(st.session_state.scan_history),
        'df_trends': df_trends,
        'df_types': df_types,
        'df_severity': df_severity
    }

# --- Main Application ---

def main():
    # Initialize Session State
    if 'scan_results' not in st.session_state:
        st.session_state.scan_results = None
    if 'scan_history' not in st.session_state:
        st.session_state.scan_history = []

    # --- Sidebar ---
    with st.sidebar:
        # Logo Area
        st.markdown("""
        <div class="sidebar-logo-container">
            <h1 style="font-size: 26px; font-weight: 800; letter-spacing: -1px;"><span style="color: #F43F5E;">Open </span><span style="color: #ffffff;">Nazca</span></h1>
            <p style="color: #64748B; font-size: 10px; letter-spacing: 2px; text-transform: uppercase;">Security Analytics</p>
        </div>
        """, unsafe_allow_html=True)
        
    # Zone 1: Navigation
        st.markdown('<p class="sidebar-header">Navigation</p>', unsafe_allow_html=True)
        
        # Disable navigation if scanning
        nav_disabled = st.session_state.get('is_scanning', False)
        
        page = st.radio(
            "Navigation",
            ["📊  Dashboard", "🔬  Analysis Lab", "🧪  Sandbox Lab", "📚  Knowledge Base", "📜  Scan History"],
            label_visibility="collapsed",
            disabled=nav_disabled
        )
        
        st.markdown("---")
        
        # Zone 2: Configuration (Persistent)
        st.markdown('<p class="sidebar-header">Configuration</p>', unsafe_allow_html=True)
        
        st.markdown("##### AI Analysis")
        use_llm = st.toggle(
            "Enable AI Analysis",
            value=True,
            disabled=nav_disabled,
            help="Use LLM to explain risks and suggest fixes"
        )
        
        llm_provider = st.selectbox(
            "LLM Provider",
            ["snowflake_cortex", "openai", "anthropic"],
            index=0,
            disabled=nav_disabled or not use_llm
        )
        st.markdown("##### Data Storage")
        use_snowflake = st.toggle(
            "Store in Snowflake",
            value=True,
            disabled=nav_disabled,
            help="Upload scan results and findings to Snowflake database"
        )
        
        st.markdown("##### Reports")
        report_formats = st.multiselect(
            "Formats",
            ["JSON", "HTML", "Markdown"],
            default=["JSON", "HTML"],
            disabled=nav_disabled
        )
        r_json = "JSON" in report_formats
        r_html = "HTML" in report_formats
        r_md = "Markdown" in report_formats
        
        # --- Footer ---
        st.markdown("""
        <div style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #1E293B; text-align: center;">
            <p style="color: #64748B; font-size: 12px; margin-bottom: 5px;">HOYAHACK 2026</p>
            <p style="color: #475569; font-size: 10px;">POWERED BY <span style="color: #29B5E8; font-weight: 600;">SNOWFLAKE CORTEX</span></p>
        </div>
        """, unsafe_allow_html=True)
        
    # --- Main Content ---
    
    # Dashboard Content
    if "Dashboard" in page:
        render_home_dashboard()
    elif "Analysis Lab" in page:
        render_analysis_lab(use_snowflake, use_llm, llm_provider, r_json, r_html, r_md)
    elif "Sandbox Lab" in page:
        render_sandbox_lab()
    elif "Knowledge Base" in page:
        render_knowledge_base()
    elif "History" in page:
        render_history_dashboard()

def render_knowledge_base():
    st.markdown("### 📚 Knowledge Base Management")
    st.markdown('<p style="color: #64748B;">Upload company policies and standards directly to Snowflake. The AI will strictly adhere to these documents during analysis.</p>', unsafe_allow_html=True)
    
    # Initialize Manager
    from src.rag_manager import RAGManager
    if 'rag_manager' not in st.session_state:
        st.session_state.rag_manager = RAGManager()
    
    rag = st.session_state.rag_manager
    
    # --- File Upload Section ---
    st.markdown("#### 📤 Upload Documents")
    
    if 'uploader_key' not in st.session_state:
        st.session_state.uploader_key = 0

    uploaded_files = st.file_uploader(
        "Upload Policy Files (PDF, MD, TXT)", 
        type=['pdf', 'md', 'txt'], 
        accept_multiple_files=True,
        key=f"uploader_{st.session_state.uploader_key}"
    )
    
    if uploaded_files:
        count = 0
        with st.status("Uploading documents...", expanded=True) as status:
            for uploaded_file in uploaded_files:
                st.write(f"Processing **{uploaded_file.name}**...")
                progress_bar = st.progress(0.0)
                status_text = st.empty()
                
                def update_progress(p, msg):
                    progress_bar.progress(p)
                    status_text.text(f"{int(p*100)}% - {msg}")

                # Pass bytes content and filename with progress callback
                result = rag.add_document(uploaded_file.getvalue(), uploaded_file.name, progress_callback=update_progress)
                
                progress_bar.progress(1.0)
                if "✅" in result:
                    count += 1
                    status_text.text("Done!")
                else:
                    st.error(result)
            status.update(label=f"Completed! Added {count} files.", state="complete", expanded=False)
            
        if count > 0:
            st.toast(f"Successfully uploaded {count} documents!", icon="☁️")
            st.session_state.uploader_key += 1 # Force reset of widget
            st.rerun()

    st.markdown("---")
    
    # --- Existing Files Section ---
    st.markdown("#### ☁️ Stored Documents (Snowflake)")
    
    # List directly from DB
    remote_files = rag.list_documents()
    
    if not remote_files:
        st.info("Knowledge Base is empty.")
    else:
        for filename in remote_files:
            col1, col2 = st.columns([0.8, 0.2])
            
            with col1:
                st.markdown(f"📄 **{filename}**")
                
            with col2:
                if st.button("🗑️ Delete", key=f"del_{filename}", use_container_width=True):
                    with st.spinner(f"Deleting {filename} from Snowflake..."):
                        status = rag.delete_document(filename)
                    st.toast(status, icon="🗑️")
                    st.rerun()

def render_home_dashboard():
    # Header
    st.markdown("### 📊 Security Dashboard")
    st.markdown('<p style="color: #64748B; margin-bottom: 2rem;">Aggregated security metrics and trends across all sessions.</p>', unsafe_allow_html=True)
    
    # --- METRICS (Real-time Results) ---
    metrics = aggregate_session_data()
    
    # Determine Security Rating (Highest Severity)
    if metrics['critical'] > 0:
        sec_status = "CRITICAL"
        sec_color = "#DC2626" # Ruby Red
    elif metrics['high'] > 0:
        sec_status = "HIGH"
        sec_color = "#EA580C" # Orange
    elif metrics['medium'] > 0:
        sec_status = "MEDIUM"
        sec_color = "#EAB308"
    elif metrics['total'] > 0:
        sec_status = "LOW"
        sec_color = "#3B82F6"
    else:
        sec_status = "SAFE"
        sec_color = "#10B981" # Green
    
    # Metrics Grid
    render_metrics_grid([
        {"title": "Total Findings", "value": f"{metrics['total']:,}", "subtext": "Session Cumulative", "icon": "📌", "color": "#F43F5E"},
        {"title": "Critical Issues", "value": f"{metrics['critical']}", "subtext": "Immediate Action", "icon": "🔥", "color": "#DC2626"},
        {"title": "High Severity", "value": f"{metrics['high']}", "subtext": "Major Issues", "icon": "⚠️", "color": "#EA580C"},
        {"title": "Files Scanned", "value": f"{metrics['files_scanned']}", "subtext": "Total Files", "icon": "📂", "color": "#EAB308"},
        {"title": "Security Rating", "value": sec_status, "subtext": "System Status", "icon": "🛡️", "color": sec_color}
    ])
    
    # --- 3. CHARTS (Deep Dive) ---
    # Only show if there is data
    if metrics['total'] > 0:
        st.markdown("### 📈 Security Insights")
        g1, g2, g3 = st.columns(3)
        
        # Chart Design Helpers
        chart_bg = "#0B1120"
        
        # Chart 1: Trend Line (Findings over Time)
        with g1:
            if not metrics['df_trends'].empty:
                fig1 = px.line(metrics['df_trends'], x="Time", y="Findings", markers=True, title="<b>FINDINGS TREND</b>")
                fig1.update_traces(line_color='#6366F1', line_width=3) # Electric Indigo Graph
                fig1.update_layout(
                    paper_bgcolor=chart_bg,
                    plot_bgcolor=chart_bg,
                    font={'color': '#A0AEBC'},
                    title_font={'size': 14, 'color': '#A0AEBC'},
                    margin=dict(l=40, r=20, t=60, b=40),
                    height=320,
                    xaxis=dict(showgrid=False, title=None),
                    yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', title='Count')
                )
                st.plotly_chart(fig1, key="trend_chart", on_select="ignore", selection_mode="points", width="stretch")

        # Chart 2: Bar Chart (Vulnerability Types)
        with g2:
            if not metrics['df_types'].empty:
                fig2 = px.bar(metrics['df_types'], x="Count", y="Type", orientation='h', title="<b>VULNERABILITY TYPES</b>")
                fig2.update_traces(marker_color='#0EA5E9')
                fig2.update_layout(
                    paper_bgcolor=chart_bg,
                    plot_bgcolor=chart_bg,
                    font={'color': '#A0AEBC'},
                    title_font={'size': 14, 'color': '#A0AEBC'},
                    margin=dict(l=20, r=20, t=60, b=40),
                    height=320,
                    xaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', title=None),
                    yaxis=dict(showgrid=False, title=None)
                )
                st.plotly_chart(fig2, key="type_chart", on_select="ignore", selection_mode="points", width="stretch")

        # Chart 3: Pie Chart (Severity Distribution)
        with g3:
            if not metrics['df_severity'].empty:
                fig3 = px.pie(metrics['df_severity'], values='Count', names='Severity', 
                              color='Severity',
                              title="<b>SEVERITY DISTRIBUTION</b>",
                              color_discrete_map={
                                  'CRITICAL': '#DC2626',
                                  'HIGH': '#EA580C',
                                  'MEDIUM': '#EAB308',
                                  'LOW': '#3B82F6'
                              })
                fig3.update_traces(textposition='inside', textinfo='percent+label', textfont_color='white')
                fig3.update_layout(
                    paper_bgcolor=chart_bg,
                    plot_bgcolor=chart_bg,
                    font={'color': '#ffffff'},
                    title_font={'size': 14, 'color': '#A0AEBC'},
                    margin=dict(l=20, r=20, t=60, b=40),
                    height=320,
                    showlegend=False
                )
                st.plotly_chart(fig3, key="sev_chart", on_select="ignore", selection_mode="points", width="stretch")
    else:
        # Empty State
        st.info("👆 Go to the 'Analysis Lab' page to upload code and start collecting data.")

def render_analysis_lab(use_snowflake, use_llm, llm_provider, r_json, r_html, r_md):
    st.markdown("### 🔬 Security Analysis Lab")
    st.markdown('<p style="color: #64748B;">Upload code to detect vulnerabilities, secrets, and injection risks.</p>', unsafe_allow_html=True)
    
    
    # Hero Upload Section
    st.markdown('<div class="upload-container">', unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload Code File", 
        type=['py', 'js', 'jsx', 'ts', 'tsx', 'java', 'go', 'rs', 'rb', 'php'], 
        label_visibility="collapsed", 
        disabled=st.session_state.get('is_scanning', False)
    )
    st.markdown('</div>', unsafe_allow_html=True)

    # Supported Languages Badges
    st.markdown("""
    <div style="display: flex; justify-content: center; flex-wrap: wrap; gap: 10px; margin-top: 10px; margin-bottom: 20px;">
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #3B82F6;">🐍</span> Python
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #FACC15;">📜</span> JS
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #61DAFB;">⚛️</span> JSX
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #3178C6;">📘</span> TS
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #61DAFB;">⚛️</span> TSX
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #F97316;">☕</span> Java
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #0EA5E9;">🐹</span> Go
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #F74C00;">🦀</span> Rust
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #CC342D;">💎</span> Ruby
        </span>
        <span style="display: flex; align-items: center; gap: 5px; font-size: 11px; color: #E2E8F0; background: #1E293B; padding: 4px 10px; border-radius: 20px; border: 1px solid #334155;">
            <span style="color: #777BB4;">🐘</span> PHP
        </span>
    </div>
    """, unsafe_allow_html=True)
    
    if uploaded_file:
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            # Check if scanning
            is_scanning = st.session_state.get('is_scanning', False)
            
            if is_scanning:
                with st.spinner("🕵️ Analysis in progress... Please wait."):
                    perform_scan(uploaded_file, use_snowflake, use_llm, llm_provider, r_json, r_html, r_md)
                    st.session_state.is_scanning = False
                    st.rerun()
            else:
                 if st.button("🚀 Launch Security Scan", width="stretch", type="primary"):
                    st.session_state.is_scanning = True
                    st.rerun()

    if st.session_state.scan_results:
        st.markdown("---")
        st.markdown("#### 🔍 Latest Analysis Results")
        render_scan_results_detailed(st.session_state.scan_results)


# --- Result Rendering Helper ---

def render_scan_results_detailed(results):
    """Render the full results view (Findings Table + Details)."""
    # Summary Metrics for THIS scan (Responsive Grid)
    render_metrics_grid([
        {"title": "Total Findings", "value": f"{results['total_findings']}", "subtext": "Issues Detected", "icon": "📌", "color": "#F43F5E"},
        {"title": "Critical Issues", "value": f"{results['severity_counts'].get('CRITICAL', 0)}", "subtext": "Immediate Action", "icon": "🔥", "color": "#DC2626"},
        {"title": "Scan Duration", "value": f"{results['scan_duration_ms']}ms", "subtext": "Processing Time", "icon": "⏱️", "color": "#3B82F6"}
    ])
    
    # --- Download Reports ---
    report_paths = results.get('report_paths', {})
    if report_paths:
        st.markdown('</div>', unsafe_allow_html=True) 
        st.markdown("<h5 style='text-align: center; margin-top: 10px; margin-bottom: 20px;'>📥 Download Reports</h5>", unsafe_allow_html=True)
        
        # Center the buttons using spacers
        n = len(report_paths)
        if n == 1:
            cols = st.columns([5, 2, 5])
            button_cols = [cols[1]]
        elif n == 2:
            cols = st.columns([3, 2, 2, 3])
            button_cols = cols[1:3]
        elif n == 3:
            cols = st.columns([2, 2, 2, 2, 2])
            button_cols = cols[1:4]
        else:
            button_cols = st.columns(n)
        
        for i, (fmt, path_str) in enumerate(report_paths.items()):
            try:
                path = Path(path_str)
                if path.exists():
                    with open(path, "rb") as f:
                        file_data = f.read()
                    
                    # Icons for formats
                    f_icon = "📄"
                    if fmt == 'html': f_icon = "🌐"
                    if fmt == 'json': f_icon = "⚙️"
                    if fmt == 'markdown': f_icon = "📝"
                    
                    with button_cols[i]:
                        st.download_button(
                            label=f"{f_icon} {fmt.upper()}",
                            data=file_data,
                            file_name=path.name,
                            mime="text/html" if fmt == 'html' else ("application/json" if fmt == 'json' else "text/markdown"),
                            key=f"dl_{fmt}_{results.get('scan_id', 'unknown')}_{i}",
                            use_container_width=True
                        )
            except Exception as e:
                pass


    # Detailed Findings Table
    if results.get('findings'):
        # Transform findings for dataframe
        df_findings = pd.DataFrame([
            {
                "Type": f['vulnerability_type'],
                "Severity": f['severity'],
                "Verdict": f.get('verdict_status', ''),
                "Line": f.get('line_number', 'N/A'),
                "Description": f['description'],
                "Detector": f['detector_name']
            }
            for f in results['findings']
        ])
        
        st.dataframe(
            df_findings,
            width="stretch",
            column_config={
                "Severity": st.column_config.TextColumn(
                    "Severity",
                    help="Severity Level",
                    validate="^(CRITICAL|HIGH|MEDIUM|LOW)$"
                )
            },
            hide_index=True
        )
        
        # Expandable Details
        for finding in results['findings']:
            import html as html_module
            sev_class = f"badge-{finding['severity'].lower()}"
            # SECURITY FIX: Escape all user-derived content before HTML embedding
            safe_severity = html_module.escape(finding['severity'])
            safe_vuln_type = html_module.escape(finding['vulnerability_type'])
            safe_line = html_module.escape(str(finding.get('line_number', 'N/A')))
            safe_desc = html_module.escape(finding['description'])
            verdict_status = finding.get('verdict_status', '')
            verdict_reason = finding.get('verdict_reason', '')
            verdict_html = f'<span style="color:#94A3B8;font-size:12px;">Verdict: <strong>{html_module.escape(verdict_status)}</strong>' + (f' — {html_module.escape(verdict_reason)}' if verdict_reason else '') + '</span>' if verdict_status else ''
            st.markdown(f"""
            <div style="background: #0F2744; padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #334155;">
                <span class="{sev_class}">{safe_severity}</span>
                <span style="color: #A0AEBC; margin-left: 10px; font-weight: 600;">{safe_vuln_type}</span>
                <span style="float: right; color: #64748B; font-size: 12px;">Line {safe_line}</span>
                <p style="color: #E2E8F0; margin-top: 10px; font-size: 14px;">{safe_desc}</p>
                {verdict_html}
            </div>
            """, unsafe_allow_html=True)
            
            # Hidden by default code expander
            with st.expander("View Code & Fix"):
                 st.markdown("**Vulnerable Code:**")
                 st.code(finding.get('code_snippet', ''), language='python')
                 
                 if finding.get('risk_explanation'):
                    st.markdown("**🔍 AI Risk Analysis:**")
                    st.info(finding['risk_explanation'])
                    
                 if finding.get('suggested_fix'):
                    st.markdown("**🛠️ Suggested Remediation:**")
                    st.code(finding['suggested_fix'], language='python')

@st.dialog("Scan Details", width="large")
def view_scan_details(filename, date, results):
    st.markdown(f"**File:** `{filename}` | **Scanned:** `{date}`")
    st.markdown("---")
    render_scan_results_detailed(results)

def render_history_dashboard():
    if not st.session_state.scan_history:
        st.info("No scan history available.")
        return
        
    history_df = pd.DataFrame([
        {
            "Filename": h['filename'],
            "Date": h['timestamp'],
            "Total Issues": h['results']['total_findings'],
            "Critical": h['results']['severity_counts'].get('CRITICAL', 0)
        }
        for h in st.session_state.scan_history
    ])
    
    st.markdown("#### Scan History")
    st.info("💡 **Tip:** Select a row to view full analysis details.")
    
    # Use selection to trigger popup
    event = st.dataframe(
        history_df, 
        width="stretch",
        on_select="rerun", 
        selection_mode="single-row",
        key="history_table"
    )
    
    if len(event.selection.rows) > 0:
        index = event.selection.rows[0]
        selected_scan = st.session_state.scan_history[index]
        view_scan_details(
            selected_scan['filename'], 
            selected_scan['timestamp'],
            selected_scan['results']
        )

def perform_scan(uploaded_file, use_snowflake, use_llm, llm_provider, r_json, r_html, r_md):
    # Prepare formats
    formats = []
    if r_json: formats.append('json')
    if r_html: formats.append('html')
    if r_md: formats.append('markdown')
    
    # Progress Bar
    progress_bar = st.progress(0)
    
    try:
        # Create temp directory
        temp_dir = Path('temp_scans')
        temp_dir.mkdir(exist_ok=True)
        
        # Save file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_name = Path(uploaded_file.name).stem
        extension = Path(uploaded_file.name).suffix
        tmp_path = str(temp_dir / f"{base_name}_{timestamp}{extension}")
        
        with open(tmp_path, 'wb') as f:
            f.write(uploaded_file.read())
            
        progress_bar.progress(30)
        
        # Scanner Init
        scanner = AICodeScanner(
            use_snowflake=use_snowflake,
            use_llm_analysis=use_llm,
            llm_provider=llm_provider
        )
        
        progress_bar.progress(60)
        
        # Scan
        results = scanner.scan_file(
            file_path=tmp_path,
            scanned_by="web_user",
            generate_reports=True,
            report_formats=formats
        )
        
        scanner.close()
        
        # SECURITY FIX: Ensure temp file cleanup with logging, always execute in finally-like pattern
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception as cleanup_err:
            import logging
            logging.getLogger(__name__).warning(f"Failed to clean up temp file {tmp_path}: {cleanup_err}")
             
        progress_bar.progress(100)
        time.sleep(0.5)
        progress_bar.empty()
        
        st.session_state.scan_results = results
        st.success("Analysis Complete")
        
        # Add to history
        scan_entry = {
            'filename': uploaded_file.name,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'results': results
        }
        st.session_state.scan_history.append(scan_entry)
        
    except Exception as e:
        # SECURITY FIX: Sanitize error messages to prevent credential leakage
        import logging
        logging.getLogger(__name__).error(f"Scan failed: {str(e)}")
        # Show generic message to user, not raw exception which may contain credentials
        st.error("Scan failed. Please check the application logs for details or verify your configuration.")

# ================================================================
#  SANDBOX VERIFICATION LAB  —  User-Uploaded Code Testing
# ================================================================

STATUS_BADGE = {
    "vulnerable": '<span class="sb-badge sb-confirmed">CONFIRMED REACHABLE</span>',
    "fixed":      '<span class="sb-badge sb-remediated">REACHABILITY ELIMINATED</span>',
    "partial":    '<span class="sb-badge sb-partial">UNVERIFIABLE</span>',
    "clean":      '<span class="sb-badge sb-safe">CLEAN</span>',
    "manual":     '<span class="sb-badge sb-untested">REQUIRES MANUAL REVIEW</span>',
}

# ── Analysis pipeline imports ─────────────────────────────────
from src.analysis.taint_tracker import TaintTracker
from src.analysis.attack_graph import AttackGraph, AttackPath
from src.analysis.sink_classifier import SinkClassifier
from src.analysis.reachability import (
    ReachabilityVerifier, ReachabilityResult, ReachabilityStatus,
)
from src.analysis.remediator import FunctionalRemediator


# ── Classify findings using library-accurate sink data when available ──

# Fallback maps for pattern-detected findings without AST analysis
_ENTRY_MAP = {
    'hardcoded': 'Source Code', 'secret': 'Source Code', 'password': 'Source Code',
    'api key': 'Source Code', 'token': 'Source Code', 'credential': 'Source Code',
    'prompt': 'User Input', 'injection': 'User Input',
    'dangerous': 'Dynamic Input', 'eval': 'Dynamic Input', 'exec': 'Dynamic Input',
    'system': 'System Interface', 'shell': 'System Interface', 'privileged': 'System Interface',
}
_SINK_MAP = {
    'hardcoded': 'Credential Exposure', 'secret': 'Credential Exposure',
    'password': 'Credential Exposure', 'api key': 'Credential Exposure',
    'token': 'Credential Exposure', 'credential': 'Credential Exposure',
    'prompt': 'LLM / AI Service', 'injection': 'LLM / AI Service',
    'dangerous': 'Code Execution', 'eval': 'Code Execution', 'exec': 'Code Execution',
    'system': 'OS / Shell Access', 'shell': 'OS / Shell Access', 'privileged': 'OS / Shell Access',
}


def _classify_finding(finding_dict):
    """Classify a finding into (entry_category, sink_category).

    Prefers library-accurate sink data from the analysis pipeline.
    Falls back to keyword matching for pattern-only findings.
    """
    # If attack path data is present, use it directly
    apath = finding_dict.get('attack_path')
    if apath:
        src = apath.get('source', {})
        sink = apath.get('sink', {})
        entry = src.get('name', 'Input')
        sink_name = sink.get('name', 'Sensitive Operation')
        # Use SinkClassifier for accurate category
        info = SinkClassifier.classify(sink_name)
        if info:
            return entry, info.vulnerability_type
        return entry, sink_name

    # Fallback: keyword-based classification
    vl = (finding_dict if isinstance(finding_dict, str)
          else finding_dict.get('vulnerability_type', '')).lower()
    entry, sink = 'Input', 'Sensitive Operation'
    for kw, label in _ENTRY_MAP.items():
        if kw in vl:
            entry = label
            break
    for kw, label in _SINK_MAP.items():
        if kw in vl:
            sink = label
            break
    return entry, sink


def _sb_log(lines, container, msg, level="info"):
    """Append a styled log line and refresh the console."""
    prefix_map = {
        "info":  '<span class="log-dim">[INFO]</span> ',
        "ok":    '<span class="log-ok">[PASS]</span> ',
        "fail":  '<span class="log-fail">[FAIL]</span> ',
        "warn":  '<span class="log-warn">[WARN]</span> ',
        "phase": '<span class="log-phase">[PHASE]</span> ',
    }
    ts = datetime.now().strftime("%H:%M:%S.") + f"{datetime.now().microsecond // 1000:03d}"
    lines.append(f'<span class="log-dim">{ts}</span>  {prefix_map.get(level, "")}{html_module.escape(msg)}')
    display = "\n".join(lines[-28:])
    container.markdown(f'<div class="sandbox-console">{display}</div>', unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────
#  MAIN PAGE
# ────────────────────────────────────────────────────────────────

def render_sandbox_lab():
    """Sandbox Verification Lab — scan, fix, and verify user-uploaded code."""

    st.markdown("### 🧪 Sandbox Verification Lab")
    st.markdown(
        '<p style="color:#64748B;">Upload code files to scan for vulnerabilities, '
        'auto-generate fixes, apply them in an isolated sandbox, and re-scan to verify. '
        'All execution is local.</p>',
        unsafe_allow_html=True,
    )

    if "sb_results" not in st.session_state:
        st.session_state.sb_results = None

    # ── file upload ─────────────────────────────────────────────
    uploaded = st.file_uploader(
        "Upload code files to test",
        type=["py", "js", "ts", "java", "go", "rb", "php", "jsx", "tsx", "c", "cpp", "rs"],
        accept_multiple_files=True,
        key="sb_uploader",
    )

    if uploaded:
        st.markdown(
            '<div style="display:flex;flex-wrap:wrap;gap:6px;margin:8px 0;">'
            + ''.join(f'<span class="sb-file-tag">{html_module.escape(f.name)}</span>' for f in uploaded)
            + '</div>',
            unsafe_allow_html=True,
        )

    # ── launch bar ──────────────────────────────────────────────
    c1, c2, c3 = st.columns([1, 2, 1])
    with c2:
        run_btn = st.button(
            "🚀  LAUNCH SANDBOX VERIFICATION",
            use_container_width=True,
            type="primary",
            disabled=not uploaded,
        )

    if run_btn and uploaded:
        st.session_state.sb_results = _execute_sandbox_on_user_code(uploaded)
        st.rerun()

    if st.session_state.sb_results is None:
        st.info(
            "Upload one or more code files, then press **Launch** to: "
            "scan for vulnerabilities → auto-generate fixes → apply in sandbox → "
            "re-scan to verify. All execution is local and isolated."
        )
        return

    res = st.session_state.sb_results

    # ── results tabs ────────────────────────────────────────────
    tab_exec, tab_graph, tab_blast, tab_conf, tab_map = st.tabs([
        "📜  Execution Log",
        "🗺️  Attack-Path Graph",
        "💥  Blast Radius",
        "🎯  Confidence",
        "🗺️  Map Analysis",
    ])
    with tab_exec:
        _render_execution_replay(res)
    with tab_graph:
        _render_dynamic_attack_graph(res)
    with tab_blast:
        _render_blast_radius_dynamic(res)
    with tab_conf:
        _render_confidence_panel_dynamic(res)
    with tab_map:
        _render_map_analysis(res)


# ────────────────────────────────────────────────────────────────
#  LIVE SANDBOX EXECUTION ON USER CODE
# ────────────────────────────────────────────────────────────────

def _execute_sandbox_on_user_code(uploaded_files):
    """Run the full Identify → Analyse → Verify → Remediate → Re-verify
    pipeline on user-uploaded code.

    Workflow:
      Phase 0 — Sandbox setup
      Phase 1 — Detection (pattern-based)
      Phase 2 — Analysis (AST taint tracking → attack-path graph → reachability)
      Phase 3 — Remediation (functional diffs only)
      Phase 4 — Re-verification (re-analyse fixed code, compare paths)
      Phase 5 — Summary
    """
    console = st.empty()
    lines = []
    progress = st.progress(0, text="Initializing sandbox…")
    results = {
        "files": {},
        "totals_before": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "totals_after":  {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        "total_fixes": 0,
        "total_functional_fixes": 0,
        "total_rejected_fixes": 0,
        "log_lines": [],
    }

    def log(msg, level="info"):
        _sb_log(lines, console, msg, level)

    # ── PHASE 0 — SETUP ────────────────────────────────────────
    log("=" * 60, "phase")
    log("PHASE 0 - Sandbox Environment Setup", "phase")
    log("=" * 60, "phase")
    time.sleep(0.2)

    sandbox_dir = Path(tempfile.mkdtemp(prefix="llmcheck_sb_"))
    log(f"Sandbox root: {sandbox_dir}")

    file_data = {}
    for uf in uploaded_files:
        content = uf.read().decode('utf-8', errors='replace')
        uf.seek(0)
        fpath = sandbox_dir / uf.name
        fpath.write_text(content)
        file_data[uf.name] = {"content": content, "path": str(fpath)}
        log(f"  Staged: {uf.name}  ({len(content.splitlines())} lines, {len(content)} bytes)")
    time.sleep(0.15)

    from src.ingestion.code_ingestion import CodeIngestion
    from src.detectors import (
        PromptInjectionDetector,
        HardcodedSecretsDetector,
        OverprivilegedToolsDetector,
        WeakRandomDetector,
        WeakHashDetector,
        XPathInjectionDetector,
        XXEDetector,
        DeserializationDetector,
        SecureCookieDetector,
        TrustBoundaryDetector,
        LDAPInjectionDetector,
        UnsafeReflectionDetector,
        CryptoMisuseDetector,
        TOCTOUDetector,
        MemorySafetyDetector,
        TypeConfusionDetector,
        LogInjectionDetector,
        XSSDetector,
        EvasionPatternsDetector,
        OperationalSecurityDetector,
    )

    ingestion = CodeIngestion(max_file_size_mb=10)
    detectors = [
        PromptInjectionDetector(enabled=True),
        HardcodedSecretsDetector(enabled=True),
        OverprivilegedToolsDetector(enabled=True),
        WeakRandomDetector(enabled=True),
        WeakHashDetector(enabled=True),
        XPathInjectionDetector(enabled=True),
        XXEDetector(enabled=True),
        DeserializationDetector(enabled=True),
        SecureCookieDetector(enabled=True),
        TrustBoundaryDetector(enabled=True),
        LDAPInjectionDetector(enabled=True),
        UnsafeReflectionDetector(enabled=True),
        CryptoMisuseDetector(enabled=True),
        TOCTOUDetector(enabled=True),
        MemorySafetyDetector(enabled=True),
        TypeConfusionDetector(enabled=True),
        LogInjectionDetector(enabled=True),
        XSSDetector(enabled=True),
        EvasionPatternsDetector(enabled=True),
        OperationalSecurityDetector(enabled=True),
    ]
    taint_tracker = TaintTracker()
    reachability_verifier = ReachabilityVerifier()
    remediator = FunctionalRemediator()

    def _deduplicate_items(items):
        """Keep one finding per (line, type, sink_api), preferring stronger status/confidence."""
        def _rank(status):
            order = {
                "Confirmed Reachable": 4,
                "Requires Manual Review": 3,
                "Unverifiable": 2,
                "Reachability Eliminated": 1,
            }
            return order.get(status or "", 0)

        unique = {}
        alias_map = {
            "attribute injection": "mass assignment",
        }
        for item in items:
            normalized = alias_map.get(
                str(item.get("vulnerability_type", "")).lower(),
                str(item.get("vulnerability_type", "")).lower(),
            )
            key = (
                item.get("line_number"),
                normalized,
                item.get("sink_api", ""),
            )
            if key not in unique:
                unique[key] = item
                continue
            cur = unique[key]
            if _rank(item.get("reachability_status")) > _rank(cur.get("reachability_status")):
                unique[key] = item
                continue
            if (
                _rank(item.get("reachability_status")) == _rank(cur.get("reachability_status"))
                and float(item.get("confidence", 0)) > float(cur.get("confidence", 0))
            ):
                unique[key] = item
        return list(unique.values())

    log(
        f"Loaded: CodeIngestion + {len(detectors)} detectors + taint tracker + "
        "reachability verifier",
        "ok",
    )
    progress.progress(8, text="Sandbox ready")

    # ── PHASE 1 — DETECTION ────────────────────────────────────
    log("", "info")
    log("=" * 60, "phase")
    log("PHASE 1 - Detection (pattern-based)", "phase")
    log("=" * 60, "phase")
    time.sleep(0.15)

    all_before = {}
    all_findings_objs_before = {}  # keep Finding objects for analysis
    step = 0
    total_steps = len(file_data)
    for fname, fdata in file_data.items():
        step += 1
        log(f"  [{step}/{total_steps}] Scanning: {fname}", "phase")
        fd = ingestion.ingest_file(fdata["path"])
        findings = []
        for det in detectors:
            hits = det.detect(fd['code_content'], fd['language'], fd['file_name'])
            if hits:
                log(f"    {det.name}: {len(hits)} finding(s)", "warn")
                findings.extend(hits)
            else:
                log(f"    {det.name}: clean", "ok")
            time.sleep(0.06)

        all_findings_objs_before[fname] = findings
        flist = _deduplicate_items([x.to_dict() for x in findings])
        all_before[fname] = flist
        for item in flist:
            sev = item.get('severity', 'MEDIUM').lower()
            results["totals_before"][sev] = results["totals_before"].get(sev, 0) + 1
            results["totals_before"]["total"] += 1

    tb = results["totals_before"]["total"]
    log(f"  TOTAL: {tb} vulnerabilities across {len(file_data)} file(s)",
        "fail" if tb > 0 else "ok")
    progress.progress(25, text=f"Found {tb} vulnerabilities")

    # NOTE: Do NOT short-circuit here. Pattern detectors may find 0
    # issues (e.g. SQL injection, XSS, path traversal are NOT detected
    # by pattern rules).  The AST taint-analysis pipeline in Phase 2
    # is the primary detection mechanism for those vulnerability classes.

    # ── PHASE 2 — ANALYSIS (taint → graph → reachability) ─────
    log("", "info")
    log("=" * 60, "phase")
    log("PHASE 2 - Static Analysis (taint tracking, attack graphs, reachability)", "phase")
    log("=" * 60, "phase")
    time.sleep(0.15)

    attack_paths_before_all = {}
    reach_results_before_all = {}

    for fname, fdata in file_data.items():
        fd = ingestion.ingest_file(fdata["path"])
        lang = fd.get('language', '')
        attack_paths = []
        reach_results = []

        if lang == 'python':
            log(f"  [{fname}] Running AST taint analysis...", "info")
            nodes, edges = taint_tracker.analyse(fname, fdata["content"])
            if nodes:
                graph = AttackGraph()
                graph.add_nodes_and_edges(nodes, edges)
                attack_paths = graph.enumerate_attack_paths()
                log(f"    Graph: {graph.node_count} nodes, {graph.edge_count} edges, "
                    f"{len(attack_paths)} attack paths", "ok")

                reach_results = reachability_verifier.verify_paths(
                    attack_paths, fdata["content"], fname
                )
                # Log reachability summary
                status_counts = {}
                for r in reach_results:
                    s = r.status.value
                    status_counts[s] = status_counts.get(s, 0) + 1
                for status, count in status_counts.items():
                    lvl = "fail" if status == "Confirmed Reachable" else "ok"
                    log(f"    {status}: {count}", lvl)

                # Enrich pattern findings with analysis data,
                # or CREATE new findings when the AST pipeline detects
                # paths that pattern detectors missed entirely.
                for rr in reach_results:
                    sink_line = rr.path.sink.line
                    matched = False
                    for fd_item in all_before.get(fname, []):
                        if fd_item.get('line_number') == sink_line:
                            fd_item['reachability_status'] = rr.status.value
                            fd_item['reachability_reasoning'] = rr.reasoning
                            fd_item['attack_path'] = rr.path.to_dict()
                            fd_item['sink_api'] = rr.path.sink.name
                            # Upgrade classification if library-accurate
                            sink_info = SinkClassifier.classify(rr.path.sink.name)
                            if sink_info:
                                fd_item['vulnerability_type'] = sink_info.vulnerability_type
                                fd_item['severity'] = sink_info.severity
                                fd_item['cwe_id'] = sink_info.cwe_id
                            matched = True
                            break

                    if not matched:
                        # No pattern finding on this sink line — create
                        # a new finding from AST analysis.
                        sink_info = SinkClassifier.classify(rr.path.sink.name)
                        new_item = {
                            'detector_name': 'StaticAnalysisPipeline',
                            'vulnerability_type': rr.path.vulnerability_type,
                            'severity': rr.path.severity,
                            'line_number': sink_line,
                            'code_snippet': rr.path.sink.detail,
                            'description': (
                                f"Tainted data from {rr.path.source.name} "
                                f"(line {rr.path.source.line}) reaches "
                                f"{rr.path.sink.name}() at line {sink_line}."
                            ),
                            'confidence': 0.9,
                            'cwe_id': rr.path.cwe_id if hasattr(rr.path, 'cwe_id') else '',
                            'reachability_status': rr.status.value,
                            'reachability_reasoning': rr.reasoning,
                            'attack_path': rr.path.to_dict(),
                            'sink_api': rr.path.sink.name,
                        }
                        if sink_info:
                            new_item['vulnerability_type'] = sink_info.vulnerability_type
                            new_item['severity'] = sink_info.severity
                            new_item['cwe_id'] = sink_info.cwe_id
                        all_before.setdefault(fname, []).append(new_item)
                        log(f"    AST finding: L{sink_line} {new_item['vulnerability_type']} "
                            f"({rr.status.value})", "fail")
            else:
                log(f"    No taint nodes found - pattern results only", "info")
        else:
            log(f"  [{fname}] AST analysis not supported for {lang} - pattern results only", "info")

        attack_paths_before_all[fname] = attack_paths
        reach_results_before_all[fname] = reach_results
        time.sleep(0.06)

    # Recalculate totals after Phase 2 AST enrichment + dedup
    results["totals_before"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for fname, items in list(all_before.items()):
        deduped = _deduplicate_items(items)
        all_before[fname] = deduped
        for item in deduped:
            sev = item.get('severity', 'MEDIUM').lower()
            results["totals_before"][sev] = results["totals_before"].get(sev, 0) + 1
            results["totals_before"]["total"] += 1

    tb = results["totals_before"]["total"]
    log(f"  TOTAL after analysis: {tb} vulnerabilities across {len(file_data)} file(s)",
        "fail" if tb > 0 else "ok")
    progress.progress(40, text="Analysis complete")

    # Short-circuit AFTER AST analysis if still nothing found
    if tb == 0:
        log("", "info")
        log("No vulnerabilities detected by pattern or AST analysis.", "ok")
        for fname in file_data:
            results["files"][fname] = {
                "findings_before": [], "findings_after": [], "fixes": [],
                "original_code": file_data[fname]["content"],
                "fixed_code": file_data[fname]["content"],
                "attack_paths_before": [p.to_dict() for p in attack_paths_before_all.get(fname, [])],
                "attack_paths_after": [],
                "reachability_before": [r.to_dict() for r in reach_results_before_all.get(fname, [])],
                "reachability_after": [],
            }
        results["log_lines"] = lines
        progress.progress(100, text="Done - no issues found")
        time.sleep(0.4)
        progress.empty()
        import shutil
        shutil.rmtree(sandbox_dir, ignore_errors=True)
        return results

    # ── PHASE 3 — FUNCTIONAL REMEDIATION ──────────────────────
    log("", "info")
    log("=" * 60, "phase")
    log("PHASE 3 - Functional Remediation (code changes only, no comment-only fixes)", "phase")
    log("=" * 60, "phase")
    time.sleep(0.15)

    fixed_files = {}
    total_fixes = 0
    total_functional = 0
    total_rejected = 0
    for fname, reach_results in reach_results_before_all.items():
        original = file_data[fname]["content"]

        if not reach_results:
            # No taint paths — still apply pattern-based fixes (Weak Hash, Debug, YAML, etc.)
            pattern_findings = all_before.get(fname, [])
            fixed_code, diffs = remediator.remediate(original, [], findings=pattern_findings)
            fix_dicts = [d.to_dict() for d in diffs]
            fixed_files[fname] = {"code": fixed_code, "fixes": fix_dicts}
            for d in diffs:
                if d.is_functional:
                    total_functional += 1
                    log(f"    L{d.line_number}: {d.description}", "ok")
                else:
                    total_rejected += 1
            log(f"  {fname}: no taint paths; applied {len([d for d in diffs if d.is_functional])} pattern fix(es)", "info")
            continue

        log(f"  [{fname}] Applying functional fixes for {len(reach_results)} paths + pattern findings...", "phase")
        pattern_findings = all_before.get(fname, [])
        fixed_code, diffs = remediator.remediate(original, reach_results, findings=pattern_findings)
        fix_dicts = [d.to_dict() for d in diffs]
        fixed_files[fname] = {"code": fixed_code, "fixes": fix_dicts}

        for d in diffs:
            if d.is_functional:
                total_functional += 1
                log(f"    L{d.line_number}: {d.description}", "ok")
            else:
                total_rejected += 1
                reason = d.rejection_reason or "No automated fix"
                log(f"    L{d.line_number}: GUIDANCE - {reason}", "warn")
            time.sleep(0.05)

    # Also handle files that only had pattern findings (no AST paths)
    for fname in file_data:
        if fname not in fixed_files:
            fixed_files[fname] = {"code": file_data[fname]["content"], "fixes": []}

    total_fixes = total_functional
    results["total_fixes"] = total_fixes
    results["total_functional_fixes"] = total_functional
    results["total_rejected_fixes"] = total_rejected
    log(f"  {total_functional} functional fix(es) applied, {total_rejected} guided option(s)", "ok")
    progress.progress(60, text="Remediation complete")

    # ── PHASE 4 — RE-VERIFICATION ─────────────────────────────
    log("", "info")
    log("=" * 60, "phase")
    log("PHASE 4 - Re-verification (re-analyse fixed code, compare attack paths)", "phase")
    log("=" * 60, "phase")
    time.sleep(0.15)

    all_after = {}
    attack_paths_after_all = {}
    reach_results_after_all = {}

    for fname, fdata_fixed in fixed_files.items():
        fixed_path = sandbox_dir / f"fixed_{fname}"
        fixed_path.write_text(fdata_fixed["code"])

        fd = ingestion.ingest_file(str(fixed_path))

        # Re-run pattern detectors
        findings = []
        for det in detectors:
            findings.extend(det.detect(fd['code_content'], fd['language'], fd['file_name']))
        flist = _deduplicate_items([x.to_dict() for x in findings])
        all_after[fname] = flist
        for item in flist:
            sev = item.get('severity', 'MEDIUM').lower()
            results["totals_after"][sev] = results["totals_after"].get(sev, 0) + 1
            results["totals_after"]["total"] += 1

        # Re-run taint analysis on fixed code
        attack_paths_after = []
        reach_results_after = []
        if fd.get('language') == 'python':
            nodes, edges = taint_tracker.analyse(f"fixed_{fname}", fdata_fixed["code"])
            if nodes:
                graph = AttackGraph()
                graph.add_nodes_and_edges(nodes, edges)
                attack_paths_after = graph.enumerate_attack_paths()
                reach_results_after = reachability_verifier.verify_paths(
                    attack_paths_after, fdata_fixed["code"], fname
                )
                # Add AST-derived findings to after-totals (same logic as Phase 2)
                for rr in reach_results_after:
                    sink_line = rr.path.sink.line
                    already = any(
                        fi.get('line_number') == sink_line
                        for fi in all_after.get(fname, [])
                    )
                    if not already:
                        sink_info = SinkClassifier.classify(rr.path.sink.name)
                        new_item = {
                            'detector_name': 'StaticAnalysisPipeline',
                            'vulnerability_type': (sink_info.vulnerability_type
                                                   if sink_info else rr.path.vulnerability_type),
                            'severity': (sink_info.severity
                                         if sink_info else rr.path.severity),
                            'line_number': sink_line,
                            'code_snippet': rr.path.sink.detail,
                            'description': (
                                f"Tainted data from {rr.path.source.name} "
                                f"(line {rr.path.source.line}) reaches "
                                f"{rr.path.sink.name}() at line {sink_line}."
                            ),
                            'confidence': 0.9,
                            'cwe_id': (sink_info.cwe_id if sink_info else ''),
                            'reachability_status': rr.status.value,
                            'reachability_reasoning': rr.reasoning,
                            'attack_path': rr.path.to_dict(),
                            'sink_api': rr.path.sink.name,
                        }
                        all_after.setdefault(fname, []).append(new_item)

        attack_paths_after_all[fname] = attack_paths_after
        reach_results_after_all[fname] = reach_results_after

        # Compare attack paths
        before_paths = attack_paths_before_all.get(fname, [])
        comparison = AttackGraph.compare(before_paths, attack_paths_after)
        elim = len(comparison["eliminated"])
        remain = len(comparison["remaining"])
        introduced = len(comparison["introduced"])

        if elim > 0:
            log(f"  {fname}: {elim} attack path(s) eliminated, {remain} remaining", "ok")
        if introduced > 0:
            log(f"  {fname}: {introduced} new path(s) introduced (side effect)", "warn")
        if remain > 0 and elim == 0:
            log(f"  {fname}: {remain} path(s) still present", "warn")
        if remain == 0 and elim > 0:
            log(f"  {fname}: all attack paths eliminated", "ok")

        time.sleep(0.06)

    # Recalculate totals after Phase 4 AST enrichment + dedup
    results["totals_after"] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    for fname, items in list(all_after.items()):
        deduped = _deduplicate_items(items)
        all_after[fname] = deduped
        for item in deduped:
            sev = item.get('severity', 'MEDIUM').lower()
            results["totals_after"][sev] = results["totals_after"].get(sev, 0) + 1
            results["totals_after"]["total"] += 1

    ta = results["totals_after"]["total"]
    log(f"  TOTAL remaining: {ta}  (was {tb})", "ok" if ta < tb else "warn")
    progress.progress(85, text="Re-verification complete")

    # ── PHASE 5 — SUMMARY ──────────────────────────────────────
    log("", "info")
    log("=" * 60, "phase")
    log("SANDBOX VERIFICATION COMPLETE", "phase")
    log("=" * 60, "phase")
    reduction = ((tb - ta) / tb * 100) if tb > 0 else 0
    log(f"  Vulnerabilities before:     {tb}")
    log(f"  Vulnerabilities after:      {ta}")
    log(f"  Functional fixes applied:   {total_functional}")
    log(f"  Guided options generated:   {total_rejected}")
    log(f"  Reachability reduction:     {reduction:.1f}%")

    import shutil
    shutil.rmtree(sandbox_dir, ignore_errors=True)
    progress.progress(100, text="Done")
    time.sleep(0.4)
    progress.empty()

    # assemble result data
    for fname in file_data:
        before_paths = attack_paths_before_all.get(fname, [])
        after_paths = attack_paths_after_all.get(fname, [])
        before_reach = reach_results_before_all.get(fname, [])
        after_reach = reach_results_after_all.get(fname, [])

        results["files"][fname] = {
            "findings_before": all_before.get(fname, []),
            "findings_after":  all_after.get(fname, []),
            "fixes":           fixed_files.get(fname, {}).get("fixes", []),
            "original_code":   file_data[fname]["content"],
            "fixed_code":      fixed_files.get(fname, {}).get("code", ""),
            "attack_paths_before": [p.to_dict() for p in before_paths],
            "attack_paths_after":  [p.to_dict() for p in after_paths],
            "reachability_before": [r.to_dict() for r in before_reach],
            "reachability_after":  [r.to_dict() for r in after_reach],
        }
    results["log_lines"] = lines
    return results


# ────────────────────────────────────────────────────────────────
#  TAB 1 — EXECUTION LOG
# ────────────────────────────────────────────────────────────────

def _render_execution_replay(res):
    """Render stored log + per-file result cards with code comparison."""

    # full console
    st.markdown("#### Terminal Output")
    display = "\n".join(res.get("log_lines", []))
    st.markdown(
        f'<div class="sandbox-console" style="max-height:520px;">{display}</div>',
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # per-file details
    for fname, fdata in res["files"].items():
        nb = len(fdata["findings_before"])
        na = len(fdata["findings_after"])
        fixes = fdata.get("fixes", [])
        nf_func = sum(1 for f in fixes if f.get("is_functional", False))
        nf_guidance = sum(1 for f in fixes if not f.get("is_functional", True))
        fix_by_line = {}
        for fix in fixes:
            fix_by_line.setdefault(fix.get("line_number"), []).append(fix)

        eliminated = max(0, nb - na)
        with st.expander(
            f"**{fname}** -- {nb} before → {na} after re-scan ({eliminated} eliminated) | "
            f"{nf_func} auto-fix(es), {nf_guidance} guidance-only",
            expanded=(nb > 0),
        ):
            if nb == 0:
                st.success("No vulnerabilities found in this file.")
                continue

            # --- Remaining after re-scan (by severity) ---
            if na > 0:
                remaining_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for f in fdata.get("findings_after", []):
                    sev = (f.get("severity") or "MEDIUM").upper()
                    if sev in remaining_by_sev:
                        remaining_by_sev[sev] += 1
                st.warning(
                    f"**After re-scan of fixed code:** {na} findings still reported — "
                    f"Critical: {remaining_by_sev['CRITICAL']}, High: {remaining_by_sev['HIGH']}, "
                    f"Medium: {remaining_by_sev['MEDIUM']}, Low: {remaining_by_sev['LOW']}. "
                    "Only a few issue types get auto-fixes; the rest need guided or manual remediation."
                )

            # --- findings table with reachability status ---
            st.markdown("##### Findings (before remediation)")
            sev_colors = {
                "CRITICAL": "#DC2626", "HIGH": "#EA580C",
                "MEDIUM": "#EAB308", "LOW": "#3B82F6",
            }
            reach_colors = {
                "Confirmed Reachable": "#DC2626",
                "Reachability Eliminated": "#10B981",
                "Unverifiable": "#F59E0B",
                "Requires Manual Review": "#EA580C",
            }
            for f in fdata["findings_before"]:
                sev = f.get('severity', 'MEDIUM')
                sc = sev_colors.get(sev, "#64748B")
                entry, sink = _classify_finding(f)
                reach_status = f.get('reachability_status', '')
                rc = reach_colors.get(reach_status, "#64748B")
                reach_badge = (
                    f'<span style="color:{rc};font-weight:600;font-size:10px;">'
                    f'[{html_module.escape(reach_status)}]</span> '
                ) if reach_status else ''

                # Attack path line
                apath = f.get('attack_path')
                path_html = ''
                if apath:
                    src = apath.get('source', {})
                    sink_p = apath.get('sink', {})
                    xforms = apath.get('transforms', [])
                    chain = f"{html_module.escape(src.get('name','?'))}"
                    for t in xforms:
                        chain += f" -> {html_module.escape(t.get('name','?'))}"
                    chain += f" -> {html_module.escape(sink_p.get('name','?'))}"
                    path_html = (
                        f'<br/><span style="color:#475569;font-size:10px;">'
                        f'Path: {chain}</span>'
                    )
                else:
                    path_html = (
                        f'<br/><span style="color:#475569;font-size:10px;">'
                        f'Path: {html_module.escape(entry)} -> '
                        f'<span class="sb-file-tag">{html_module.escape(fname)}</span> -> '
                        f'{html_module.escape(sink)}</span>'
                    )

                st.markdown(
                    f'<div style="padding:6px 10px;margin:3px 0;background:#0B1120;'
                    f'border-left:3px solid {sc};border-radius:0 4px 4px 0;font-size:12px;">'
                    f'<span style="color:{sc};font-weight:700;">{html_module.escape(sev)}</span> '
                    f'{reach_badge}'
                    f'<span style="color:#E2E8F0;">{html_module.escape(f.get("vulnerability_type",""))}</span> '
                    f'<span style="color:#64748B;"> -- Line {f.get("line_number","?")}</span>'
                    f'{" -- Sink: " + html_module.escape(f.get("sink_api","")) if f.get("sink_api") else ""}'
                    f'<br/>'
                    f'<span style="color:#94A3B8;font-size:11px;">'
                    f'{html_module.escape(f.get("description","")[:200])}</span>'
                    f'{path_html}</div>',
                    unsafe_allow_html=True,
                )

                # --- root cause + fix rationale + 3-tier options ---
                matched_fixes = fix_by_line.get(f.get("line_number"), [])
                primary_fix = matched_fixes[0] if matched_fixes else None
                options = _build_fix_options_for_finding(f, primary_fix)
                why_exists = _explain_why_vulnerability_exists(f)
                why_fix_works = _explain_why_fix_works(f, primary_fix)

                st.markdown(
                    f'<div style="padding:8px 10px;margin:4px 0 10px 0;background:#111827;'
                    f'border:1px solid #1f2937;border-radius:6px;font-size:12px;">'
                    f'<div style="color:#FBBF24;font-weight:700;margin-bottom:4px;">Why this exists</div>'
                    f'<div style="color:#CBD5E1;margin-bottom:6px;">{html_module.escape(why_exists)}</div>'
                    f'<div style="color:#34D399;font-weight:700;margin-bottom:4px;">Why the fix works</div>'
                    f'<div style="color:#CBD5E1;margin-bottom:8px;">{html_module.escape(why_fix_works)}</div>'
                    f'<div style="color:#A78BFA;font-weight:700;margin-bottom:4px;">Fix options</div>'
                    f'<div style="color:#E2E8F0;">'
                    f'<div><strong>1) Quick Fix</strong>: {html_module.escape(options["quick"])}</div>'
                    f'<div><strong>2) Proper Fix</strong>: {html_module.escape(options["proper"])}</div>'
                    f'<div><strong>3) Architectural Fix</strong>: {html_module.escape(options["architectural"])}</div>'
                    f'</div></div>',
                    unsafe_allow_html=True,
                )

            # --- fixes applied (functional diffs only) ---
            if fixes:
                st.markdown("##### Remediation Diffs")
                for fix in fixes:
                    is_func = fix.get("is_functional", False)
                    if is_func:
                        st.markdown(
                            f'**Line {fix.get("line_number", "?")}** '
                            f'`{html_module.escape(fix.get("vulnerability_type",""))}` -- '
                            f'{html_module.escape(fix.get("description",""))}'
                        )
                    else:
                        reason = fix.get("rejection_reason", "Non-functional change")
                        st.markdown(
                            f'**Line {fix.get("line_number", "?")}** '
                            f'Guided options provided -- {html_module.escape(reason)}'
                        )

            # --- code comparison ---
            st.markdown("##### Side-by-Side Remediation View")
            st.caption("Markers: 🚨 vulnerable line, ✅ safe line, + added (green), - removed (red), ~ modified (yellow)")
            lang = fname.rsplit('.', 1)[-1] if '.' in fname else 'text'
            lang_map = {"py": "python", "js": "javascript", "ts": "typescript",
                        "rb": "ruby", "rs": "rust", "go": "go", "java": "java",
                        "php": "php", "c": "c", "cpp": "cpp"}
            lang = lang_map.get(lang, lang)

            col1, col2 = st.columns(2)
            vuln_lines = {f.get("line_number") for f in fdata["findings_before"] if f.get("line_number")}
            before_html, after_html = _build_side_by_side_marked_diff(
                fdata["original_code"], fdata["fixed_code"], max_lines=1200,
                vuln_lines=vuln_lines,
            )
            with col1:
                st.markdown("*Original Vulnerable Code*")
                st.markdown(before_html, unsafe_allow_html=True)
            with col2:
                st.markdown("*Remediated Safe Code*")
                st.markdown(after_html, unsafe_allow_html=True)

            # --- re-verification result ---
            if na == 0 and nb > 0:
                st.success(f"All {nb} attack paths eliminated after remediation.")
            elif na < nb:
                st.warning(
                    f"Reachability reduced: {nb - na} path(s) eliminated, "
                    f"{na} remaining -- manual review needed."
                )
            elif na == nb:
                st.error(f"All {na} findings persist -- manual remediation required.")


def _build_side_by_side_marked_diff(
    original_code: str, fixed_code: str, max_lines: int = 1200,
    vuln_lines: set | None = None,
):
    """Build colored side-by-side diff views with visual markers.

    When original == fixed (no auto-patch), highlights vulnerable lines
    in the original column so the user still sees red markers.
    """
    before_lines = original_code.splitlines()
    after_lines = fixed_code.splitlines()
    has_changes = original_code != fixed_code

    before_view: list[str] = []
    after_view: list[str] = []
    vuln_lines = vuln_lines or set()

    def _span(prefix: str, text: str, color: str) -> str:
        return f'<span style="color:{color};">{html_module.escape(prefix + text)}</span>'

    if has_changes:
        sm = difflib.SequenceMatcher(a=before_lines, b=after_lines)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if len(before_view) > max_lines:
                break
            if tag == "equal":
                for ol, nl in zip(before_lines[i1:i2], after_lines[j1:j2]):
                    before_view.append(_span("   ", ol, "#94A3B8"))
                    after_view.append(_span("   ", nl, "#94A3B8"))
            elif tag == "replace":
                oc, nc = before_lines[i1:i2], after_lines[j1:j2]
                for idx in range(max(len(oc), len(nc))):
                    if idx < len(oc):
                        before_view.append(_span("- 🚨 ", oc[idx], "#F87171"))
                    if idx < len(nc):
                        after_view.append(_span("+ ✅ ", nc[idx], "#34D399"))
            elif tag == "delete":
                for ol in before_lines[i1:i2]:
                    before_view.append(_span("- 🚨 ", ol, "#F87171"))
            elif tag == "insert":
                for nl in after_lines[j1:j2]:
                    after_view.append(_span("+ ✅ ", nl, "#34D399"))
    else:
        # No auto-fix was applied — still mark vulnerable lines red.
        for idx, line in enumerate(before_lines):
            ln = idx + 1
            if ln in vuln_lines:
                before_view.append(_span("🚨 ", line, "#F87171"))
                after_view.append(_span("🚨 ", line, "#F87171"))
            else:
                before_view.append(_span("   ", line, "#94A3B8"))
                after_view.append(_span("   ", line, "#94A3B8"))

    for view in (before_view, after_view):
        if len(view) > max_lines:
            view[max_lines:] = ['<span style="color:#64748B;">... truncated ...</span>']

    _wrap = (
        '<div style="background:#0B1120;border:1px solid #1F2937;border-radius:6px;'
        'padding:8px;max-height:520px;overflow:auto;font-family:monospace;font-size:12px;">'
        "<pre style='margin:0;white-space:pre-wrap;'>{}</pre></div>"
    )
    return _wrap.format("<br/>".join(before_view)), _wrap.format("<br/>".join(after_view))


def _build_fix_options_for_finding(finding: dict, fix: dict | None) -> dict:
    """Return quick/proper/architectural remediation options per finding."""
    vuln = (finding.get("vulnerability_type") or "").lower()
    line = finding.get("line_number", "?")
    quick = (
        fix.get("description")
        if fix and fix.get("description")
        else "Apply strict input validation at the sink and add an explicit guard condition."
    )
    proper = "Refactor to safe APIs with structured parameterization and centralized validation."
    architectural = "Move the risky operation behind a dedicated security service with policy enforcement and allowlists."

    if "sql injection" in vuln:
        proper = "Replace string-built queries with parameterized statements for every DB call."
        architectural = "Introduce a repository/ORM layer that forbids raw SQL string interpolation."
    elif "command injection" in vuln:
        proper = "Use argument arrays with subprocess.run(..., shell=False) and strict allowlists."
        architectural = "Replace shell execution with internal job/task APIs."
    elif "code execution" in vuln:
        proper = "Use a restricted interpreter/sandbox with explicit operation allowlists."
        architectural = "Eliminate dynamic code execution by moving logic to typed command handlers."
    elif "path traversal" in vuln:
        proper = "Normalize path and enforce base-directory containment checks before file access."
        architectural = "Use storage abstraction with opaque file IDs instead of user-provided paths."
    elif "xss" in vuln:
        proper = "Enable contextual output encoding and framework auto-escaping by default."
        architectural = "Adopt a trusted template/component pipeline with strict CSP."
    elif "open redirect" in vuln:
        proper = "Validate redirect targets against a strict allowlist of hosts/paths."
        architectural = "Use server-side route keys instead of user-supplied redirect URLs."
    elif "unsafe file upload" in vuln:
        proper = "Use secure_filename + extension/MIME checks + malware scanning + size limits."
        architectural = "Move uploads to isolated object storage with async scanning and signed URL access."
    elif "information disclosure" in vuln:
        proper = "Return redacted metadata only; remove environment/version details from responses."
        architectural = "Centralize error/diagnostic handling with tiered disclosure policies."
    elif "memory exhaustion" in vuln:
        proper = "Clamp user-controlled sizes and enforce per-request quotas."
        architectural = "Apply upstream rate limiting plus worker memory ceilings and queue backpressure."
    elif "format string" in vuln:
        proper = "Treat format strings as static constants; pass user data only as values."
        architectural = "Use safe templating with strict schema-driven rendering."
    elif "debug mode enabled" in vuln:
        proper = "Read debug setting from environment and default to False in all deployed environments."
        architectural = "Enforce production runtime guardrails in deployment pipeline/infra policy."

    return {"quick": quick, "proper": proper, "architectural": architectural}


def _explain_why_vulnerability_exists(finding: dict) -> str:
    desc = finding.get("description", "")
    if desc:
        return desc
    return "Untrusted input reaches a sensitive operation without sufficient validation, escaping, or policy checks."


def _explain_why_fix_works(finding: dict, fix: dict | None) -> str:
    if fix and fix.get("description"):
        return str(fix.get("description"))
    vuln = (finding.get("vulnerability_type") or "").lower()
    if "injection" in vuln:
        return "The fix separates code/command/query structure from untrusted data, blocking attacker-controlled interpretation."
    if "debug" in vuln or "disclosure" in vuln:
        return "The fix removes sensitive runtime exposure and disables unsafe runtime features."
    return "The fix adds a security boundary (validation, allowlist, or safer API) before the risky sink."


# ────────────────────────────────────────────────────────────────
#  TAB 2 — DYNAMIC ATTACK-PATH GRAPH
# ────────────────────────────────────────────────────────────────

def _render_dynamic_attack_graph(res):
    """Build a Sankey diagram from attack-path graph data (real data flow)
    with fallback to pattern-based classification."""
    from collections import Counter

    st.markdown("#### Attack-Path Flow -- Before vs After Remediation")

    # Collect (source, file, sink) triples from attack-path data or findings
    paths_before = []
    paths_after = []
    for fname, fdata in res["files"].items():
        # Prefer real attack-path data from the analysis pipeline
        for ap in fdata.get("attack_paths_before", []):
            src_name = ap.get("source", {}).get("name", "Input")
            sink_name = ap.get("sink", {}).get("name", "Sensitive Operation")
            # Use library-accurate classification
            info = SinkClassifier.classify(sink_name)
            sink_label = info.vulnerability_type if info else sink_name
            paths_before.append((src_name, fname, sink_label))
        for ap in fdata.get("attack_paths_after", []):
            src_name = ap.get("source", {}).get("name", "Input")
            sink_name = ap.get("sink", {}).get("name", "Sensitive Operation")
            info = SinkClassifier.classify(sink_name)
            sink_label = info.vulnerability_type if info else sink_name
            paths_after.append((src_name, fname, sink_label))

        # Fallback: if no attack-path data, use pattern findings
        if not fdata.get("attack_paths_before"):
            for f in fdata["findings_before"]:
                entry, sink = _classify_finding(f)
                paths_before.append((entry, fname, sink))
        if not fdata.get("attack_paths_after"):
            for f in fdata["findings_after"]:
                entry, sink = _classify_finding(f)
                paths_after.append((entry, fname, sink))

    if not paths_before:
        st.success("No attack paths found -- uploaded code appears clean.")
        return

    mode = st.radio("View", ["Before Remediation", "After Remediation"],
                    horizontal=True, key="sb_graph_mode")
    is_after = mode == "After Remediation"

    # build unique node lists: sources | files | sinks
    entries = sorted(set(p[0] for p in paths_before))
    files   = sorted(set(p[1] for p in paths_before))
    sinks   = sorted(set(p[2] for p in paths_before))

    labels = entries + files + sinks
    n_e = len(entries)
    n_f = len(files)
    entry_idx = {e: i for i, e in enumerate(entries)}
    file_idx  = {f: i + n_e for i, f in enumerate(files)}
    sink_idx  = {s: i + n_e + n_f for i, s in enumerate(sinks)}

    node_colors = (
        ["#4338CA"] * n_e +   # source -- indigo
        ["#0369A1"] * n_f +   # file   -- blue
        ["#9F1239"] * len(sinks)  # sink -- rose
    )

    src, tgt, vals, colors = [], [], [], []

    if not is_after:
        edge_counts = Counter()
        for entry, fname, sink in paths_before:
            edge_counts[(entry_idx[entry], file_idx[fname])] += 1
            edge_counts[(file_idx[fname], sink_idx[sink])] += 1
        for (s, t), v in edge_counts.items():
            src.append(s); tgt.append(t); vals.append(v)
            colors.append("rgba(220,38,38,0.45)")
    else:
        before_counts = Counter()
        for entry, fname, sink in paths_before:
            before_counts[(entry_idx[entry], file_idx[fname])] += 1
            before_counts[(file_idx[fname], sink_idx[sink])] += 1
        after_counts = Counter()
        for entry, fname, sink in paths_after:
            after_counts[(entry_idx.get(entry, 0), file_idx.get(fname, 0))] += 1
            after_counts[(file_idx.get(fname, 0), sink_idx.get(sink, 0))] += 1

        for (s, t), v in before_counts.items():
            remaining = after_counts.get((s, t), 0)
            eliminated = v - remaining
            if remaining > 0:
                src.append(s); tgt.append(t); vals.append(remaining)
                colors.append("rgba(220,38,38,0.45)")
            if eliminated > 0:
                src.append(s); tgt.append(t); vals.append(eliminated)
                colors.append("rgba(16,185,129,0.22)")

    fig = go.Figure(go.Sankey(
        arrangement="snap",
        node=dict(
            pad=18, thickness=22, label=labels,
            color=node_colors, line=dict(color="#1E293B", width=1),
        ),
        link=dict(source=src, target=tgt, value=vals, color=colors),
    ))
    fig.update_layout(
        paper_bgcolor="#020617", plot_bgcolor="#020617",
        font=dict(color="#94A3B8", size=12),
        height=max(360, 120 + 50 * n_f),
        margin=dict(l=10, r=10, t=35, b=10),
        title=dict(
            text=f"Attack Paths -- {'After' if is_after else 'Before'} Remediation",
            font=dict(size=14, color="#94A3B8"),
        ),
    )
    st.plotly_chart(fig, use_container_width=True, key=f"sankey_{mode}")

    # legend
    st.markdown("""
    <div style="display:flex;gap:20px;justify-content:center;margin-top:8px;font-size:12px;color:#64748B;">
        <span><span style="display:inline-block;width:14px;height:14px;background:rgba(220,38,38,0.5);border-radius:2px;vertical-align:middle;margin-right:4px;"></span> Confirmed Reachable</span>
        <span><span style="display:inline-block;width:14px;height:14px;background:rgba(16,185,129,0.3);border-radius:2px;vertical-align:middle;margin-right:4px;"></span> Reachability Eliminated</span>
    </div>
    """, unsafe_allow_html=True)

    # detail table — attack path detail with reachability status (use after-status when available)
    st.markdown("---")
    st.markdown("#### Attack Path Detail")
    for fname, fdata in res["files"].items():
        reach_before = fdata.get("reachability_before", [])
        reach_after = fdata.get("reachability_after", [])
        # Build key -> after status for paths that still exist after remediation
        after_by_key = {}
        for rd in reach_after:
            path_info = rd.get("path", {})
            sink_info = path_info.get("sink", {})
            src_info = path_info.get("source", {})
            key = (sink_info.get("line"), src_info.get("line"), path_info.get("vulnerability_type", ""))
            after_by_key[key] = rd.get("status", "")

        if reach_before:
            for rd in reach_before:
                path_info = rd.get("path", {})
                status = rd.get("status", "")
                src_info = path_info.get("source", {})
                sink_info = path_info.get("sink", {})
                transforms = path_info.get("transforms", [])

                # If we have after-results, show after status (so fixed paths show green)
                key = (sink_info.get("line"), src_info.get("line"), path_info.get("vulnerability_type", ""))
                if after_by_key:
                    status = after_by_key.get(key, "Reachability Eliminated")

                chain = html_module.escape(src_info.get("name", "?"))
                for t in transforms:
                    chain += f' -> {html_module.escape(t.get("name", "?"))}'
                chain += f' -> {html_module.escape(sink_info.get("name", "?"))}'

                badge_key = {
                    "Confirmed Reachable": "vulnerable",
                    "Reachability Eliminated": "fixed",
                    "Unverifiable": "partial",
                    "Requires Manual Review": "manual",
                }.get(status, "partial")
                badge = STATUS_BADGE.get(badge_key, "")

                st.markdown(
                    f'<div class="sb-path-row">'
                    f'<span class="sb-path-id">'
                    f'{html_module.escape(path_info.get("severity",""))}</span>'
                    f'<span class="sb-path-name">{chain}'
                    f' <span class="sb-file-tag">{html_module.escape(fname)}'
                    f':{sink_info.get("line","?")}</span></span>'
                    f'<span style="min-width:180px;text-align:right;">{badge}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
        else:
            # Fallback to pattern-based findings
            for f in fdata.get("findings_before", []):
                entry, sink = _classify_finding(f)
                fixed = not any(
                    af.get('vulnerability_type') == f.get('vulnerability_type')
                    and af.get('line_number') == f.get('line_number')
                    for af in fdata.get("findings_after", [])
                )
                badge = STATUS_BADGE["fixed"] if fixed else STATUS_BADGE["vulnerable"]
                st.markdown(
                    f'<div class="sb-path-row">'
                    f'<span class="sb-path-id">'
                    f'{html_module.escape(f.get("severity",""))}</span>'
                    f'<span class="sb-path-name">{html_module.escape(entry)} -> '
                    f'<span class="sb-file-tag">{html_module.escape(fname)}'
                    f':{f.get("line_number","?")}</span> -> '
                    f'{html_module.escape(sink)}</span>'
                    f'<span style="min-width:180px;text-align:right;">{badge}</span>'
                    f'</div>',
                    unsafe_allow_html=True,
                )


# ────────────────────────────────────────────────────────────────
#  TAB 3 — BLAST RADIUS
# ────────────────────────────────────────────────────────────────

def _render_blast_radius_dynamic(res):
    """Quantify the before / after reduction in the user's code."""

    st.markdown("#### Blast Radius Reduction")
    st.markdown(
        '<p style="color:#64748B;">How much of the uploaded code\'s attack surface '
        'was reduced by automated remediation.</p>',
        unsafe_allow_html=True,
    )

    tb = res["totals_before"]["total"]
    ta = res["totals_after"]["total"]
    nf = res["total_fixes"]
    reduction = ((tb - ta) / tb * 100) if tb > 0 else 0

    # metrics row
    render_metrics_grid([
        {"title": "Before", "value": str(tb), "subtext": "Total vulnerabilities",
         "icon": "🔓", "color": "#DC2626"},
        {"title": "Fixes Applied", "value": str(nf), "subtext": "Auto-remediated",
         "icon": "🔧", "color": "#6366F1"},
        {"title": "After", "value": str(ta), "subtext": "Remaining issues",
         "icon": "🛡️", "color": "#10B981" if ta < tb else "#F59E0B"},
        {"title": "Reduction", "value": f"{reduction:.0f}%",
         "subtext": "Vulnerability decrease", "icon": "📉", "color": "#10B981"},
    ])

    st.markdown("---")

    # ── severity breakdown bar chart ────────────────────────────
    st.markdown("##### By Severity")
    sevs = ["critical", "high", "medium", "low"]
    sev_colors = {"critical": "#DC2626", "high": "#EA580C",
                  "medium": "#EAB308", "low": "#3B82F6"}

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="Before", x=[s.title() for s in sevs],
        y=[res["totals_before"].get(s, 0) for s in sevs],
        marker_color=[sev_colors[s] for s in sevs], opacity=0.85,
    ))
    fig.add_trace(go.Bar(
        name="After", x=[s.title() for s in sevs],
        y=[res["totals_after"].get(s, 0) for s in sevs],
        marker_color=[sev_colors[s] for s in sevs], opacity=0.35,
    ))
    fig.update_layout(
        barmode='group',
        paper_bgcolor="#0B1120", plot_bgcolor="#0B1120",
        font=dict(color="#94A3B8"), height=320,
        margin=dict(l=40, r=20, t=30, b=40),
        legend=dict(orientation="h", y=1.12),
        yaxis=dict(gridcolor="#1E293B"),
    )
    st.plotly_chart(fig, use_container_width=True, key="sev_bars")

    # ── type breakdown bar chart ────────────────────────────────
    from collections import Counter
    types_b = Counter()
    types_a = Counter()
    for fdata in res["files"].values():
        for f in fdata["findings_before"]:
            types_b[f.get("vulnerability_type", "Unknown")] += 1
        for f in fdata["findings_after"]:
            types_a[f.get("vulnerability_type", "Unknown")] += 1

    if types_b:
        st.markdown("##### By Vulnerability Type")
        all_types = sorted(types_b.keys())
        fig2 = go.Figure()
        fig2.add_trace(go.Bar(
            name="Before", x=all_types,
            y=[types_b[t] for t in all_types],
            marker_color="#DC2626", opacity=0.85,
        ))
        fig2.add_trace(go.Bar(
            name="After", x=all_types,
            y=[types_a.get(t, 0) for t in all_types],
            marker_color="#10B981", opacity=0.7,
        ))
        fig2.update_layout(
            barmode='group',
            paper_bgcolor="#0B1120", plot_bgcolor="#0B1120",
            font=dict(color="#94A3B8", size=11), height=320,
            margin=dict(l=40, r=20, t=30, b=100),
            legend=dict(orientation="h", y=1.12),
            xaxis=dict(tickangle=-30),
            yaxis=dict(gridcolor="#1E293B"),
        )
        st.plotly_chart(fig2, use_container_width=True, key="type_bars")

    # ── donut summary ───────────────────────────────────────────
    if tb > 0:
        eliminated = tb - ta
        fig3 = go.Figure(go.Pie(
            labels=["Fixed", "Remaining"],
            values=[eliminated, ta],
            hole=0.6,
            marker=dict(colors=["#10B981", "#DC2626"]),
            textinfo="label+value",
            textfont=dict(color="white", size=13),
        ))
        fig3.update_layout(
            paper_bgcolor="#0B1120", plot_bgcolor="#0B1120",
            font=dict(color="#94A3B8"), height=300,
            margin=dict(l=20, r=20, t=10, b=20),
            showlegend=False,
            annotations=[dict(
                text=f"{reduction:.0f}%<br>fixed",
                x=0.5, y=0.5,
                font=dict(size=22, color="white"), showarrow=False,
            )],
        )
        st.plotly_chart(fig3, use_container_width=True, key="donut_blast")


# ────────────────────────────────────────────────────────────────
#  TAB 4 — CONFIDENCE PANEL
# ────────────────────────────────────────────────────────────────

def _render_confidence_panel_dynamic(res):
    """Trust-gradient classification panel using reachability analysis."""

    st.markdown("#### Trust-Gradient Classification")
    st.markdown(
        '<p style="color:#64748B;">Each vulnerability path is classified by '
        'static reachability analysis. These are evidence-based verdicts, '
        'not exploit simulations.</p>',
        unsafe_allow_html=True,
    )

    confirmed_reachable = []
    reachability_eliminated = []
    unverifiable = []
    manual_review = []
    side_effects = []

    for fname, fdata in res["files"].items():
        # Prefer reachability data from the analysis pipeline
        reach_before = fdata.get("reachability_before", [])
        reach_after = fdata.get("reachability_after", [])

        if reach_before:
            # Use analysis-pipeline classifications
            after_keys = set()
            for ra in reach_after:
                p = ra.get("path", {})
                after_keys.add((
                    p.get("source", {}).get("name"),
                    p.get("sink", {}).get("name"),
                    p.get("sink", {}).get("line"),
                ))

            for rb in reach_before:
                p = rb.get("path", {})
                status = rb.get("status", "")
                src_name = p.get("source", {}).get("name", "?")
                sink_name = p.get("sink", {}).get("name", "?")
                sink_line = p.get("sink", {}).get("line", "?")
                label = (f"{fname}:{sink_line} -- "
                         f"{src_name} -> {sink_name}  "
                         f"[{p.get('severity','?')}]")

                key = (src_name, sink_name, sink_line)
                path_eliminated = key not in after_keys

                if path_eliminated:
                    reachability_eliminated.append(
                        label + "  (path no longer exists after remediation)")
                elif status == "Confirmed Reachable":
                    confirmed_reachable.append(label)
                elif status == "Reachability Eliminated":
                    reachability_eliminated.append(label)
                elif status == "Unverifiable":
                    unverifiable.append(label)
                elif status == "Requires Manual Review":
                    manual_review.append(label)

            # Check for new paths introduced by fixes
            before_keys = set()
            for rb in reach_before:
                p = rb.get("path", {})
                before_keys.add((
                    p.get("source", {}).get("name"),
                    p.get("sink", {}).get("name"),
                    p.get("sink", {}).get("line"),
                ))
            for ra in reach_after:
                p = ra.get("path", {})
                key = (
                    p.get("source", {}).get("name"),
                    p.get("sink", {}).get("name"),
                    p.get("sink", {}).get("line"),
                )
                if key not in before_keys:
                    side_effects.append(
                        f"{fname}:{p.get('sink',{}).get('line','?')} -- "
                        f"new path: {key[0]} -> {key[1]}  (introduced by fix)"
                    )
        else:
            # Fallback: re-scan comparison for pattern-only findings
            after_keys = {
                (f.get('vulnerability_type'), f.get('line_number'))
                for f in fdata.get("findings_after", [])
            }
            fix_lines = {
                fix.get('line_number', fix.get('line', 0))
                for fix in fdata.get("fixes", [])
                if fix.get("is_functional", True)
            }

            for f in fdata.get("findings_before", []):
                key = (f.get('vulnerability_type'), f.get('line_number'))
                ln = f.get('line_number', 0)
                label = (f"{fname}:{ln} -- "
                         f"{f.get('vulnerability_type','')}  "
                         f"[{f.get('severity','?')}]")

                reach_status = f.get('reachability_status', '')
                if key not in after_keys:
                    reachability_eliminated.append(label)
                elif reach_status == "Confirmed Reachable":
                    confirmed_reachable.append(label)
                elif reach_status == "Unverifiable":
                    unverifiable.append(label)
                elif reach_status == "Requires Manual Review":
                    manual_review.append(label)
                elif ln in fix_lines:
                    unverifiable.append(
                        label + "  (fix applied but reachability not eliminated)")
                else:
                    manual_review.append(
                        label + "  (no automated fix available)")

    levels = [
        ("Confirmed Reachable -- tainted data reaches sink with no sanitiser",
         "#DC2626", "#991B1B", confirmed_reachable),
        ("Reachability Eliminated -- attack path broken by remediation or sanitiser",
         "#10B981", "#059669", reachability_eliminated),
        ("Unverifiable -- path exists but sanitisation cannot be proven statically",
         "#F59E0B", "#D97706", unverifiable),
        ("Requires Manual Review -- reachability depends on runtime context",
         "#6366F1", "#4F46E5", manual_review),
        ("Side Effects -- new attack paths introduced by remediation",
         "#7C3AED", "#6D28D9", side_effects),
    ]

    for title, color, border, items in levels:
        if not items:
            continue
        st.markdown(
            f'<div style="background:#0B1120;border:1px solid {border};'
            f'border-radius:4px;padding:16px;margin-bottom:16px;">'
            f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">'
            f'<div style="width:12px;height:12px;border-radius:50%;background:{color};"></div>'
            f'<span style="color:#E2E8F0;font-weight:600;font-size:14px;">{title}</span>'
            f'<span style="color:#64748B;font-size:12px;margin-left:auto;">'
            f'{len(items)} items</span></div>'
            + "".join(
                f'<div style="color:#94A3B8;font-size:12px;padding:4px 0 4px 20px;'
                f'border-left:2px solid {border};margin-left:5px;margin-bottom:4px;">'
                f'{html_module.escape(item)}</div>'
                for item in items
            )
            + '</div>',
            unsafe_allow_html=True,
        )

    if not any(items for _, _, _, items in levels):
        st.success("No vulnerabilities were found -- nothing to classify.")

    # summary metrics
    st.markdown("---")
    st.markdown("#### Summary")
    total = (len(confirmed_reachable) + len(reachability_eliminated)
             + len(unverifiable) + len(manual_review) + len(side_effects))
    render_metrics_grid([
        {"title": "Confirmed Reachable", "value": str(len(confirmed_reachable)),
         "subtext": "Active attack paths", "icon": "X", "color": "#DC2626"},
        {"title": "Reachability Eliminated",
         "value": str(len(reachability_eliminated)),
         "subtext": "Paths broken by fix", "icon": "ok", "color": "#10B981"},
        {"title": "Unverifiable", "value": str(len(unverifiable)),
         "subtext": "Cannot prove statically", "icon": "?", "color": "#F59E0B"},
        {"title": "Manual Review", "value": str(len(manual_review)),
         "subtext": "Runtime-dependent", "icon": "!", "color": "#6366F1"},
    ])


# ────────────────────────────────────────────────────────────────
#  TAB 5 — MAP ANALYSIS (Level 1: file tree → Level 2: vulnerability DAG)
# ────────────────────────────────────────────────────────────────

def _render_map_analysis(res):
    """Two-level map: (1) file tree with nodes red if vulnerable;
    (2) per-file vulnerability flow as a tree/DAG (source → transform → sink)."""
    if "map_analysis_selected_file" not in st.session_state:
        st.session_state.map_analysis_selected_file = None

    files_data = res.get("files", {})
    if not files_data:
        st.info("No file data from the sandbox run.")
        return

    file_names = list(files_data.keys())

    # ── Level 1: File tree (root → files), nodes red if has vulns ──
    st.markdown("#### Level 1 — Uploaded files")
    st.markdown(
        '<p style="color:#64748B;">Each node is an uploaded file. '
        '<span style="color:#DC2626;">Red</span> = has vulnerabilities; '
        '<span style="color:#10B981;">Green</span> = clean. '
        'Select a file below to open its vulnerability map.</p>',
        unsafe_allow_html=True,
    )

    G1 = nx.DiGraph()
    root_id = "Uploaded files"
    G1.add_node(root_id, has_vuln=False, is_root=True)
    for fname in file_names:
        fdata = files_data[fname]
        has_vuln = (
            len(fdata.get("findings_before", [])) > 0
            or len(fdata.get("attack_paths_before", [])) > 0
        )
        G1.add_node(fname, has_vuln=has_vuln, is_root=False)
        G1.add_edge(root_id, fname)

    # Tree layout: root at top, files in a row below
    pos1 = {root_id: (0.5, 1.0)}
    n = len(file_names)
    for i, fname in enumerate(file_names):
        pos1[fname] = ((i + 1) / (n + 1), 0.0) if n else (0.5, 0.0)

    # Build edge traces (lines)
    edge_x1, edge_y1 = [], []
    for u, v in G1.edges():
        x0, y0 = pos1[u]
        x1, y1 = pos1[v]
        edge_x1.extend([x0, x1, None])
        edge_y1.extend([y0, y1, None])

    node_x1 = [pos1[n][0] for n in G1.nodes()]
    node_y1 = [pos1[n][1] for n in G1.nodes()]
    node_colors1 = []
    node_labels1 = []
    for n in G1.nodes():
        node_labels1.append(n)
        if G1.nodes[n].get("is_root"):
            node_colors1.append("#64748B")  # slate for root
        else:
            node_colors1.append("#DC2626" if G1.nodes[n].get("has_vuln") else "#10B981")

    fig1 = go.Figure()
    fig1.add_trace(
        go.Scatter(
            x=edge_x1, y=edge_y1,
            mode="lines",
            line=dict(color="#475569", width=2, dash="dot"),
            hoverinfo="none",
        )
    )
    fig1.add_trace(
        go.Scatter(
            x=node_x1, y=node_y1,
            mode="markers+text",
            text=node_labels1,
            textposition="bottom center",
            textfont=dict(size=11, color="#E2E8F0"),
            marker=dict(
                size=32,
                color=node_colors1,
                line=dict(color="#1E293B", width=2),
                symbol="circle",
            ),
            customdata=node_labels1,
            hovertemplate="%{customdata}<extra></extra>",
        )
    )
    fig1.update_layout(
        showlegend=False,
        margin=dict(l=20, r=20, t=30, b=80),
        height=280,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False, range=[-0.05, 1.05]),
        yaxis=dict(visible=False, range=[-0.15, 1.15]),
    )

    st.plotly_chart(fig1, use_container_width=True, key="map_level1")

    # File selector (drives Level 2)
    selected = st.selectbox(
        "Select file to view vulnerability map (Level 2)",
        options=file_names,
        index=file_names.index(st.session_state.map_analysis_selected_file)
        if st.session_state.map_analysis_selected_file in file_names
        else 0,
        key="map_file_select",
    )
    st.session_state.map_analysis_selected_file = selected

    # ── Level 2: Per-file vulnerability DAG (source → transform → sink) ──
    st.markdown("---")
    st.markdown(f"#### Level 2 — Vulnerability flow: **{selected}**")
    fdata = files_data[selected]
    paths = fdata.get("attack_paths_before", [])

    if not paths:
        st.info(
            f"No attack-path data for **{selected}**. "
            "This file has no taint paths from the static analysis pipeline."
        )
        return

    # Build one DAG from all paths: nodes = source, transforms, sink (unique by id)
    G2 = nx.DiGraph()
    node_severity = {}
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def _node_id(role, name, line):
        return f"{role}:{name}:{line}"

    for ap in paths:
        src = ap.get("source", {})
        sink = ap.get("sink", {})
        transforms = ap.get("transforms", [])
        sev = ap.get("severity", "MEDIUM")
        sev_level = severity_order.get(sev, 0)

        sid = _node_id("source", src.get("name", "?"), src.get("line", 0))
        G2.add_node(sid, label=src.get("name", "?"), line=src.get("line"), role="source")
        node_severity[sid] = max(node_severity.get(sid, 0), sev_level)

        prev = sid
        for t in transforms:
            tid = _node_id("transform", t.get("name", "?"), t.get("line", 0))
            G2.add_node(tid, label=t.get("name", "?"), line=t.get("line"), role="transform")
            node_severity[tid] = max(node_severity.get(tid, 0), sev_level)
            G2.add_edge(prev, tid)
            prev = tid

        kid = _node_id("sink", sink.get("name", "?"), sink.get("line", 0))
        G2.add_node(kid, label=sink.get("name", "?"), line=sink.get("line"), role="sink")
        node_severity[kid] = max(node_severity.get(kid, 0), sev_level)
        G2.add_edge(prev, kid)

    # Layered layout: source(s) left, transform(s) middle, sink(s) right (tree-like)
    layers = {"source": 0, "transform": 1, "sink": 2}
    for n in G2.nodes():
        r = G2.nodes[n].get("role", "transform")
        G2.nodes[n]["layer"] = layers.get(r, 1)
    try:
        pos2 = nx.multipartite_layout(G2, subset_key="layer", align="horizontal")
    except Exception:
        pos2 = nx.spring_layout(G2, seed=42, k=1.2)

    # Scale to [0,1] for consistency
    xs = [pos2[n][0] for n in G2.nodes()]
    ys = [pos2[n][1] for n in G2.nodes()]
    min_x, max_x = min(xs), max(xs) or 1
    min_y, max_y = min(ys), max(ys) or 1
    for n in G2.nodes():
        x, y = pos2[n][0], pos2[n][1]
        pos2[n] = (
            (x - min_x) / (max_x - min_x + 1e-9),
            (y - min_y) / (max_y - min_y + 1e-9),
        )

    edge_x2, edge_y2 = [], []
    for u, v in G2.edges():
        x0, y0 = pos2[u]
        x1, y1 = pos2[v]
        edge_x2.extend([x0, x1, None])
        edge_y2.extend([y0, y1, None])

    node_x2 = [pos2[n][0] for n in G2.nodes()]
    node_y2 = [pos2[n][1] for n in G2.nodes()]
    node_labels2 = []
    node_colors2 = []
    for n in G2.nodes():
        lab = G2.nodes[n].get("label", n)
        line = G2.nodes[n].get("line", "")
        node_labels2.append(f"{lab}\n(L{line})" if line else lab)
        sev_level = node_severity.get(n, 0)
        if sev_level >= 4:
            node_colors2.append("#DC2626")
        elif sev_level >= 3:
            node_colors2.append("#EA580C")
        elif sev_level >= 2:
            node_colors2.append("#CA8A04")
        else:
            node_colors2.append("#10B981")

    fig2 = go.Figure()
    fig2.add_trace(
        go.Scatter(
            x=edge_x2, y=edge_y2,
            mode="lines",
            line=dict(color="#475569", width=2),
            hoverinfo="none",
        )
    )
    fig2.add_trace(
        go.Scatter(
            x=node_x2, y=node_y2,
            mode="markers+text",
            text=node_labels2,
            textposition="top center",
            textfont=dict(size=10, color="#E2E8F0"),
            marker=dict(
                size=28,
                color=node_colors2,
                line=dict(color="#1E293B", width=2),
                symbol="circle",
            ),
            hovertemplate="%{text}<extra></extra>",
        )
    )
    fig2.update_layout(
        showlegend=False,
        margin=dict(l=20, r=20, t=30, b=100),
        height=400,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    st.plotly_chart(fig2, use_container_width=True, key="map_level2")

    st.markdown(
        '<div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:8px;font-size:12px;color:#64748B;">'
        '<span><span style="display:inline-block;width:10px;height:10px;background:#DC2626;'
        'border-radius:50%;vertical-align:middle;margin-right:4px;"></span> Critical</span>'
        '<span><span style="display:inline-block;width:10px;height:10px;background:#EA580C;'
        'border-radius:50%;vertical-align:middle;margin-right:4px;"></span> High</span>'
        '<span><span style="display:inline-block;width:10px;height:10px;background:#CA8A04;'
        'border-radius:50%;vertical-align:middle;margin-right:4px;"></span> Medium</span>'
        '<span><span style="display:inline-block;width:10px;height:10px;background:#10B981;'
        'border-radius:50%;vertical-align:middle;margin-right:4px;"></span> Low / source</span>'
        '</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
