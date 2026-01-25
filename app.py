import streamlit as st
import sys
import os
from pathlib import Path
from datetime import datetime
import time
import plotly.express as px
import pandas as pd
import plotly.graph_objects as go

from src.scanner import AICodeScanner
from src.rag_manager import RAGManager

# Page configuration
st.set_page_config(
    page_title="LLMCheck Security Analytics",
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
            <h1 style="color: #F43F5E; font-size: 26px; font-weight: 800; letter-spacing: -1px;">LLM<span style="color: #ffffff;">CHECK</span></h1>
            <p style="color: #64748B; font-size: 10px; letter-spacing: 2px; text-transform: uppercase;">Security Analytics</p>
        </div>
        """, unsafe_allow_html=True)
        
    # Zone 1: Navigation
        st.markdown('<p class="sidebar-header">Navigation</p>', unsafe_allow_html=True)
        
        # Disable navigation if scanning
        nav_disabled = st.session_state.get('is_scanning', False)
        
        page = st.radio(
            "Navigation",
            ["📊  Dashboard", "🔬  Analysis Lab", "📚  Knowledge Base", "📜  Scan History"],
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
    uploaded_files = st.file_uploader(
        "Upload Policy Files (PDF, MD, TXT)", 
        type=['pdf', 'md', 'txt'], 
        accept_multiple_files=True
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
            sev_class = f"badge-{finding['severity'].lower()}"
            st.markdown(f"""
            <div style="background: #0F2744; padding: 15px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #334155;">
                <span class="{sev_class}">{finding['severity']}</span>
                <span style="color: #A0AEBC; margin-left: 10px; font-weight: 600;">{finding['vulnerability_type']}</span>
                <span style="float: right; color: #64748B; font-size: 12px;">Line {finding.get('line_number', 'N/A')}</span>
                <p style="color: #E2E8F0; margin-top: 10px; font-size: 14px;">{finding['description']}</p>
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
        
        # Cleanup
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
             pass
             
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
        st.error(f"Scan failed: {str(e)}")

if __name__ == "__main__":
    main()
