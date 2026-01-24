"""
LLMCheck - AI Code Security Scanner
Demo Page: Interactive Security Scanner
"""

import streamlit as st
import sys
import os
from pathlib import Path
import tempfile

# Add parent directory to path to import src modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import AICodeScanner
from src.ingestion import CodeIngestion

# Page configuration
st.set_page_config(
    page_title="Demo - LLMCheck",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    .severity-critical {
        background-color: #dc3545;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-weight: bold;
        display: inline-block;
    }
    .severity-high {
        background-color: #fd7e14;
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-weight: bold;
        display: inline-block;
    }
    .severity-medium {
        background-color: #ffc107;
        color: black;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-weight: bold;
        display: inline-block;
    }
    .severity-low {
        background-color: #0dcaf0;
        color: black;
        padding: 0.25rem 0.75rem;
        border-radius: 15px;
        font-weight: bold;
        display: inline-block;
    }
    .finding-card {
        border-left: 5px solid #667eea;
        padding: 1rem;
        margin: 1rem 0;
        background-color: #f8f9fa;
        border-radius: 5px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'scanner' not in st.session_state:
    st.session_state.scanner = None


def format_severity_badge(severity: str) -> str:
    """Format severity as colored badge."""
    severity_lower = severity.lower()
    return f'<span class="severity-{severity_lower}">{severity}</span>'


def main():
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔍 Live Demo</h1>
        <h3>Try the LLMCheck Security Scanner</h3>
        <p>Upload your code and discover vulnerabilities in real-time</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Sidebar configuration
    st.sidebar.header("⚙️ Scanner Configuration")
    
    # Scanner settings
    use_snowflake = st.sidebar.checkbox(
        "Store results in Snowflake",
        value=False,
        help="Enable to persist scan results in Snowflake database"
    )
    
    use_llm_analysis = st.sidebar.checkbox(
        "Enable LLM Analysis",
        value=True,
        help="Use LLM to generate risk explanations and fix suggestions"
    )
    
    if use_llm_analysis:
        llm_provider = st.sidebar.selectbox(
            "LLM Provider",
            ["snowflake_cortex", "openai", "anthropic"],
            help="Select which LLM provider to use"
        )
    else:
        llm_provider = "snowflake_cortex"
    
    max_file_size = st.sidebar.slider(
        "Max File Size (MB)",
        min_value=1,
        max_value=50,
        value=10,
        help="Maximum file size to process"
    )
    
    # Report format selection
    st.sidebar.header("📄 Report Formats")
    report_json = st.sidebar.checkbox("JSON", value=True)
    report_html = st.sidebar.checkbox("HTML", value=True)
    report_markdown = st.sidebar.checkbox("Markdown", value=False)
    
    report_formats = []
    if report_json:
        report_formats.append('json')
    if report_html:
        report_formats.append('html')
    if report_markdown:
        report_formats.append('markdown')
    
    st.sidebar.markdown("---")
    st.sidebar.info(
        "💡 **Tip:** This tool detects:\n"
        "- Prompt Injection vulnerabilities\n"
        "- Hardcoded secrets\n"
        "- Over-privileged AI tools"
    )
    
    # Example files section
    st.sidebar.markdown("---")
    st.sidebar.header("📂 Example Files")
    st.sidebar.markdown("""
    Try scanning these example vulnerable files:
    - `example1_prompt_injection.py`
    - `example2_hardcoded_secrets.py`
    - `example3_overprivileged_tools.py`
    
    Located in: `examples/vulnerable_code/`
    """)
    
    # Main content area
    tab1, tab2 = st.tabs(["📤 Upload & Scan", "📊 Results"])
    
    with tab1:
        st.header("Upload Code File")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Choose a code file",
                type=['py', 'js', 'jsx', 'ts', 'tsx', 'java', 'go', 'rs', 'rb', 'php'],
                help="Upload Python, JavaScript, TypeScript, or other supported code files"
            )
            
            if uploaded_file is not None:
                st.success(f"✅ File uploaded: {uploaded_file.name}")
                
                # Show file preview
                with st.expander("📄 File Preview"):
                    try:
                        content = uploaded_file.read().decode('utf-8')
                        uploaded_file.seek(0)  # Reset file pointer
                        st.code(content[:1000] + ("..." if len(content) > 1000 else ""), language='python')
                    except Exception as e:
                        st.error(f"Could not preview file: {e}")
                
                # Scan button
                if st.button("🔍 Start Security Scan", type="primary", use_container_width=True):
                    with st.spinner("🔄 Scanning for vulnerabilities..."):
                        try:
                            # Save uploaded file to temp location
                            with tempfile.NamedTemporaryFile(
                                delete=False,
                                suffix=Path(uploaded_file.name).suffix,
                            scanner = None
                            tmp_path = None
                            try:
                                # Save uploaded file to temp location
                                with tempfile.NamedTemporaryFile(
                                    delete=False,
                                    suffix=Path(uploaded_file.name).suffix,
                                    mode='wb'
                                ) as tmp_file:
                                    tmp_file.write(uploaded_file.read())
                                    tmp_path = tmp_file.name

                                # Initialize scanner
                                scanner = AICodeScanner(
                                    use_snowflake=use_snowflake,
                                    use_llm_analysis=use_llm_analysis,
                                    llm_provider=llm_provider,
                                    max_file_size_mb=max_file_size
                                )

                                # Perform scan
                                results = scanner.scan_file(
                                    file_path=tmp_path,
                                    scanned_by="streamlit_user",
                                    generate_reports=True,
                                    report_formats=report_formats
                                )

                                # Store results in session state
                                st.session_state.scan_results = results

                                if results['success']:
                                    st.success("✅ Scan completed successfully!")
                                    st.balloons()
                                else:
                                    st.error(f"❌ Scan failed: {results.get('error', 'Unknown error')}")
                            finally:
                                # Ensure temporary file and scanner are always cleaned up
                                try:
                                    if tmp_path is not None and os.path.exists(tmp_path):
                                        os.unlink(tmp_path)
                                except Exception:
                                    # Ignore temp file cleanup errors to avoid masking original issues
                                    pass

                                if scanner is not None:
                                    try:
                                        scanner.close()
                                    except Exception:
                                        # Ignore scanner close errors to avoid masking original issues
                                        pass
                        except Exception as e:
                            st.error(f"❌ Error during scan: {str(e)}")
                            import traceback
                            st.code(traceback.format_exc())
        
        with col2:
            st.markdown("### Supported Languages")
            st.markdown("""
            - 🐍 Python (.py)
            - 📜 JavaScript (.js, .jsx)
            - 📘 TypeScript (.ts, .tsx)
            - ☕ Java (.java)
            - 🔷 Go (.go)
            - 🦀 Rust (.rs)
            - 💎 Ruby (.rb)
            - 🐘 PHP (.php)
            """)
    
    with tab2:
        st.header("Scan Results")
        
        if st.session_state.scan_results is None:
            st.info("👆 Upload and scan a file to see results here")
        else:
            results = st.session_state.scan_results
            
            if not results['success']:
                st.error(f"Scan failed: {results.get('error', 'Unknown error')}")
            else:
                # Summary metrics
                st.subheader("📊 Summary")
                
                col1, col2, col3, col4, col5 = st.columns(5)
                
                with col1:
                    st.metric("Total Findings", results['total_findings'])
                
                with col2:
                    st.metric("🔴 Critical", results['severity_counts'].get('CRITICAL', 0))
                
                with col3:
                    st.metric("🟠 High", results['severity_counts'].get('HIGH', 0))
                
                with col4:
                    st.metric("🟡 Medium", results['severity_counts'].get('MEDIUM', 0))
                
                with col5:
                    st.metric("🔵 Low", results['severity_counts'].get('LOW', 0))
                
                st.markdown("---")
                
                # Detailed findings
                if results['total_findings'] > 0:
                    st.subheader(f"🔍 Detailed Findings ({results['total_findings']})")
                    
                    # Filter by severity
                    severity_filter = st.multiselect(
                        "Filter by severity",
                        ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                        default=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
                    )
                    
                    findings = results['findings']
                    filtered_findings = [f for f in findings if f['severity'] in severity_filter]
                    
                    if not filtered_findings:
                        st.info("No findings match the selected filters")
                    else:
                        for i, finding in enumerate(filtered_findings, 1):
                            with st.expander(
                                f"{i}. {finding['vulnerability_type']} - "
                                f"Line {finding.get('line_number', 'N/A')}",
                                expanded=(finding['severity'] == 'CRITICAL')
                            ):
                                # Severity badge
                                st.markdown(
                                    format_severity_badge(finding['severity']),
                                    unsafe_allow_html=True
                                )
                                
                                # Finding details
                                st.markdown(f"**Detector:** {finding['detector_name']}")
                                st.markdown(f"**Confidence:** {finding['confidence'] * 100:.0f}%")
                                st.markdown(f"**Line:** {finding.get('line_number', 'N/A')}")
                                
                                if finding.get('cwe_id'):
                                    st.markdown(f"**CWE:** {finding['cwe_id']}")
                                
                                if finding.get('owasp_category'):
                                    st.markdown(f"**OWASP:** {finding['owasp_category']}")
                                
                                st.markdown("---")
                                
                                # Description
                                st.markdown("**📝 Description:**")
                                st.write(finding['description'])
                                
                                # Code snippet
                                st.markdown("**💻 Code Snippet:**")
                                st.code(finding.get('code_snippet', 'No code snippet available'))
                                
                                # LLM Analysis (if available)
                                if finding.get('risk_explanation'):
                                    st.markdown("**🎯 Risk Explanation:**")
                                    st.info(finding['risk_explanation'])
                                
                                if finding.get('suggested_fix'):
                                    st.markdown("**✅ Suggested Fix:**")
                                    st.success(finding['suggested_fix'])
                else:
                    st.success("🎉 No vulnerabilities found! Your code looks secure.")
                
                # Download reports
                if results.get('report_paths'):
                    st.markdown("---")
                    st.subheader("📥 Download Reports")
                    
                    cols = st.columns(len(results['report_paths']))
                    for i, (format_type, path) in enumerate(results['report_paths'].items()):
                        with cols[i]:
                            try:
                                with open(path, 'rb') as f:
                                    file_data = f.read()
                                    st.download_button(
                                        label=f"Download {format_type.upper()}",
                                        data=file_data,
                                        file_name=Path(path).name,
                                        mime='application/octet-stream',
                                        use_container_width=True
                                    )
                            except Exception as e:
                                st.error(f"Could not load {format_type} report: {e}")


if __name__ == "__main__":
    main()
