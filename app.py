import streamlit as st
import sys
import os
from pathlib import Path
from datetime import datetime
import time
import plotly.express as px
import pandas as pd
import plotly.express as px
import pandas as pd

# Add parent directory to path to import src modules
sys.path.insert(0, str(Path(__file__).parent))

from src.scanner import AICodeScanner

# Page configuration
st.set_page_config(
    page_title="LLMCheck - AI Code Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Custom CSS for Glassmorphism and Premium Feel
st.markdown("""
<style>
    /* Global Font */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }
    
    code {
        font-family: 'JetBrains Mono', monospace;
    }

    /* Background and Glassmorphism */
    .stApp {
        background-color: #0e1117;
        background-image: radial-gradient(circle at 50% 10%, #2e1065 0%, #0e1117 50%);
        background-attachment: fixed;
    }
    
    .glass-card {
        background: rgba(255, 255, 255, 0.05);
        backdrop-filter: blur(10px);
        -webkit-backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 15px;
        padding: 2rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        margin-bottom: 2rem;
    }

    /* Header Styling */
    .main-header {
        text-align: center;
        padding: 2rem 0;
        margin-bottom: 2rem;
    }
    
    .main-header h1 {
        background: linear-gradient(90deg, #a78bfa 0%, #f472b6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-size: 3.5rem;
        font-weight: 800;
        margin-bottom: 1rem;
    }
    
    .main-header p {
        color: #d1d5db;
        font-size: 1.2rem;
        max-width: 600px;
        margin: 0 auto;
    }

    /* Upload Area */
    .upload-area {
        border: 2px dashed #4c1d95;
        border-radius: 15px;
        padding: 3rem;
        text-align: center;
        background: rgba(30, 27, 75, 0.3);
        transition: all 0.3s ease;
    }
    
    .upload-area:hover {
        border-color: #7c3aed;
        background: rgba(30, 27, 75, 0.5);
    }

    /* Language Grid */
    .lang-container {
        display: flex;
        justify-content: center;
        margin-top: 2rem;
        width: 100%;
    }
    
    .lang-grid {
        display: grid;
        grid-template-columns: repeat(6, 1fr);
        gap: 1.5rem;
        text-align: center;
        max-width: 800px;
    }

    @media (max-width: 768px) {
        .lang-grid {
            grid-template-columns: repeat(3, 1fr);
        }
    }
    
    .lang-item {
        background: rgba(255, 255, 255, 0.05);
        border-radius: 12px;
        padding: 1.2rem;
        border: 1px solid rgba(255, 255, 255, 0.05);
        transition: all 0.3s ease;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        cursor: default;
    }
    
    .lang-item:hover {
        transform: translateY(-5px);
        border-color: #8b5cf6;
        background: rgba(255, 255, 255, 0.1);
        box-shadow: 0 4px 15px rgba(139, 92, 246, 0.2);
    }
    
    .lang-icon {
        font-size: 2rem;
        margin-bottom: 0.5rem;
    }
    
    .lang-name {
        font-size: 0.9rem;
        color: #e5e7eb;
        font-weight: 600;
    }

    /* Custom Buttons */
    .stButton button {
        background: linear-gradient(135deg, #7c3aed 0%, #db2777 100%);
        color: white;
        border: none;
        padding: 0.75rem 2rem;
        border-radius: 10px;
        font-weight: 600;
        transition: all 0.3s ease;
        width: 100%;
    }
    
    .stButton button:hover {
        transform: scale(1.02);
        box-shadow: 0 4px 15px rgba(124, 58, 237, 0.4);
    }

    /* Progress Bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #7c3aed 0%, #db2777 100%);
    }

    /* Metrics */
    div[data-testid="stMetricValue"] {
        font-size: 2rem;
        color: #f3e8ff;
    }
    
    div[data-testid="stMetricLabel"] {
        color: #a5b4fc;
    }
    
    /* Expander */
    .streamlit-expanderHeader {
        background-color: rgba(255, 255, 255, 0.02);
        border-radius: 10px;
    }

    /* File Uploader */
    div[data-testid="stFileUploader"] {
        padding: 1rem;
        border-radius: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scan_history' not in st.session_state:
    st.session_state.scan_history = []

# Main Layout
def main():
    # Header
    st.markdown("""
        <div class="main-header">
            <h1>LLMCheck</h1>
            <p>Enterprise-grade security scanning for AI-generated code.
            Detect prompt injections, secrets, and high-risk patterns instantly.</p>
        </div>
    """, unsafe_allow_html=True)

    # Main Container
    with st.container():
        # Centering the scan area
        col1, col2, col3 = st.columns([1, 6, 1])
        with col2:
             # Settings (Always Visible)
            with st.container(border=True):
                st.markdown("#### ⚙️ Advanced Configuration & Settings")
                c1, c2, c3 = st.columns(3)
                with c1:
                    use_snowflake = st.checkbox("💾 Save to Snowflake DB", value=False, help="Persist results for audit trails")
                    use_llm = st.checkbox("🧠 Enable AI Analysis", value=True, help="Use LLM to explain risks")
                with c2:
                    if use_llm:
                        llm_provider = st.selectbox("LLM Model", ["snowflake_cortex", "openai", "anthropic"])
                        st.caption("Selected Provider: " + llm_provider)
                    else:
                        llm_provider = "snowflake_cortex"
                        st.text("AI Analysis Disabled")
                with c3:
                    st.markdown("##### Report Formats")
                    r_json = st.checkbox("JSON", value=True)
                    r_html = st.checkbox("HTML", value=True)
                    r_md = st.checkbox("Markdown", value=False)

            # File Upload
            st.markdown("### 📤 Upload Code for Analysis")
            uploaded_file = st.file_uploader(
                "Upload Code",
                type=['py', 'js', 'jsx', 'ts', 'tsx', 'java', 'go', 'rs', 'rb', 'php'],
                help="Drag and drop your code file here",
                label_visibility="collapsed"
            )

            if uploaded_file:
                st.success(f"Ready to scan: **{uploaded_file.name}** ({uploaded_file.size} bytes)")
                
                # Use a column layout for the button to control width if needed, or full width
                if st.button("🚀 Start Security Audit"):
                    perform_scan(uploaded_file, use_snowflake, use_llm, llm_provider, r_json, r_html, r_md)
            
            
            # Supported Languages Grid (Only show if no results yet, to keep it clean)
            if not st.session_state.scan_results and not uploaded_file:
                st.markdown("""
                <div class="lang-container">
                    <div class="lang-grid">
                        <div class="lang-item"><div class="lang-icon">🐍</div><div class="lang-name">Python</div></div>
                        <div class="lang-item"><div class="lang-icon">📜</div><div class="lang-name">JavaScript</div></div>
                        <div class="lang-item"><div class="lang-icon">📘</div><div class="lang-name">TypeScript</div></div>
                        <div class="lang-item"><div class="lang-icon">☕</div><div class="lang-name">Java</div></div>
                        <div class="lang-item"><div class="lang-icon">🔷</div><div class="lang-name">Go</div></div>
                        <div class="lang-item"><div class="lang-icon">🦀</div><div class="lang-name">Rust</div></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    # Results Section
    if st.session_state.scan_results:
        display_results(st.session_state.scan_results)

def perform_scan(uploaded_file, use_snowflake, use_llm, llm_provider, r_json, r_html, r_md):
    # Prepare formats
    formats = []
    if r_json: formats.append('json')
    if r_html: formats.append('html')
    if r_md: formats.append('markdown')
    
    # Progress Bar
    progress_bar = st.progress(0)
    status_text = st.empty()
    
    # Fake progress simulation for UX
    for i in range(1, 30):
        time.sleep(0.01)
        progress_bar.progress(i)
    
    status_text.markdown("**Initializing scanner parameters...**")

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
            
        progress_bar.progress(50)
        status_text.markdown("**Analyzing code structure and dependencies...**")
        
        # Scanner Init
        scanner = AICodeScanner(
            use_snowflake=use_snowflake,
            use_llm_analysis=use_llm,
            llm_provider=llm_provider
        )
        
        progress_bar.progress(70)
        status_text.markdown("**Querying security models and pattern matching...**")
        
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
        status_text.markdown("**✅ Analysis Complete!**")
        time.sleep(0.5)
        
        # Clear progress bar
        status_text.empty()
        progress_bar.empty()
        
        st.session_state.scan_results = results
        
        # Add to history
        scan_entry = {
            'filename': uploaded_file.name,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'results': results
        }
        st.session_state.scan_history.append(scan_entry)
        
    except Exception as e:
        st.error(f"Scan failed: {str(e)}")

def display_results(results):
    # Centering the results area to match the main upload area
    col1, col2, col3 = st.columns([1, 6, 1])
    with col2:
        st.markdown("---")
        
        # Tabs for Audit and Graph
        tab_audit, tab_graph = st.tabs(["📋 Audit Findings", "📈 Trends & Analysis"])
        
        with tab_audit:
            st.header("📊 Audit Results")
            
            # Validation Check
            if not results.get('success', False):
                 st.error(f"Analysis Failed: {results.get('error')}")
                 return
    
            # Metrics
            c1, c2, c3, c4 = st.columns(4)
            with c1: st.metric("Total Issues", results['total_findings'])
            with c2: st.metric("Critical", results['severity_counts'].get('CRITICAL', 0), delta_color="inverse")
            with c3: st.metric("High", results['severity_counts'].get('HIGH', 0), delta_color="inverse")
            with c4: st.metric("Medium", results['severity_counts'].get('MEDIUM', 0), delta_color="off")
    
            # Detailed List
            if results['total_findings'] > 0:
                st.subheader("Detected Vulnerabilities")
                
                # Severity Filter
                cols = st.columns([3, 1])
                with cols[1]:
                    severity_filter = st.multiselect(
                        "Filter Severity",
                        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                    )
                
                filtered_findings = [f for f in results['findings'] if f['severity'] in severity_filter]
                
                if not filtered_findings:
                    st.info("No findings match the selected severity filter.")
                
                for finding in filtered_findings:
                    severity = finding['severity']
                    
                    # Dynamic badge color based on severity
                    badge_color = {
                        "CRITICAL": "#dc2626", # Red 600
                        "HIGH": "#ea580c",     # Orange 600
                        "MEDIUM": "#ca8a04",   # Yellow 600
                        "LOW": "#2563eb"       # Blue 600
                    }.get(severity, "#4b5563")
    
                    with st.expander(f"{finding['vulnerability_type']} (Line {finding.get('line_number', '?')})"):
                        st.markdown(f'<span style="background-color: {badge_color}; padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white;">{severity}</span>', unsafe_allow_html=True)
                        st.markdown(f"**Detector:** {finding['detector_name']}")
                        
                        st.markdown("#### Description")
                        st.write(finding['description'])
                        
                        st.markdown("#### Code")
                        st.code(finding.get('code_snippet', ''), language='python')
                        
                        if finding.get('risk_explanation'):
                            st.markdown("#### 🧠 AI Risk Analysis")
                            st.info(finding['risk_explanation'])
                        
                        if finding.get('suggested_fix'):
                            st.markdown("#### ✅ Recommended Fix")
                            st.success(finding['suggested_fix'])
            else:
                st.markdown("""
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: 12px; padding: 2rem; text-align: center; margin: 2rem 0;">
                    <h2 style="color: #34d399; margin-bottom: 0.5rem;">✅ No Security Issues Found</h2>
                    <p style="color: #d1d5db;">Your code passed all enabled security checks.</p>
                </div>
                """, unsafe_allow_html=True)
            
            # Downloads
            if results.get('report_paths'):
                st.markdown("---")
                st.subheader("📥 Download Reports")
                cols = st.columns(len(results['report_paths']))
                for i, (fmt, path) in enumerate(results['report_paths'].items()):
                    with cols[i]:
                        try:
                            with open(path, "rb") as f:
                                st.download_button(
                                    f"Download {fmt.upper()}",
                                    f,
                                    file_name=Path(path).name,
                                    mime='application/octet-stream',
                                    width="stretch"
                                )
                        except Exception as e:
                            st.error(f"Could not load {fmt} report.")
    
        with tab_graph:
            st.header("📈 Session Analysis")
            
            if not st.session_state.scan_history:
                st.info("No scan history available yet.")
            else:
                # Aggregate Data
                all_findings = []
                severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
                detector_counts = {}
                
                for entry in st.session_state.scan_history:
                    # Severity
                    counts = entry['results']['severity_counts']
                    for sev, count in counts.items():
                        severity_counts[sev] += count
                    
                    # Detectors
                    for finding in entry['results']['findings']:
                        det = finding['detector_name']
                        detector_counts[det] = detector_counts.get(det, 0) + 1
                        
                # 1. Severity Distribution
                sev_df = pd.DataFrame([
                    {"Severity": k, "Count": v} 
                    for k, v in severity_counts.items() 
                    if v > 0
                ])
                
                # 2. Detector Distribution
                det_df = pd.DataFrame([
                    {"Detector": k, "Count": v} 
                    for k, v in detector_counts.items()
                ])
                
                # Visualizations
                c1, c2 = st.columns(2)
                
                with c1:
                    st.subheader("Vulnerabilities by Severity")
                    if not sev_df.empty:
                        fig_sev = px.pie(
                            sev_df, 
                            values='Count', 
                            names='Severity',
                            hole=0.4,
                            color='Severity',
                            color_discrete_map={
                                'CRITICAL': '#dc2626',
                                'HIGH': '#ea580c',
                                'MEDIUM': '#ca8a04',
                                'LOW': '#2563eb'
                            }
                        )
                        fig_sev.update_traces(textinfo='value+percent')
                        fig_sev.update_layout(showlegend=True)
                        st.plotly_chart(fig_sev, width="stretch")
                    else:
                        st.info("No vulnerabilities found.")
    
                with c2:
                    st.subheader("Vulnerabilities by Detector")
                    if not det_df.empty:
                        fig_det = px.pie(
                            det_df, 
                            values='Count', 
                            names='Detector',
                            hole=0.4
                        )
                        fig_det.update_traces(textinfo='value+percent')
                        fig_det.update_layout(showlegend=True)
                        st.plotly_chart(fig_det, width="stretch")
                    else:
                        st.info("No vulnerabilities found.")
    
                st.markdown("---")
                st.subheader("Session History")
                
                # History Table
                history_data = []
                for entry in st.session_state.scan_history:
                    counts = entry['results']['severity_counts']
                    history_data.append({
                        "Filename": entry['filename'],
                        "Time": entry['timestamp'],
                        "Total Issues": entry['results']['total_findings'],
                        "Critical": counts.get('CRITICAL', 0),
                        "High": counts.get('HIGH', 0),
                        "Medium": counts.get('MEDIUM', 0),
                        "Low": counts.get('LOW', 0)
                    })
                
                st.dataframe(pd.DataFrame(history_data), width="stretch")



if __name__ == "__main__":
    main()
