"""
LLMCheck - AI Code Security Scanner
Home Page: Project Overview and Key Features
"""

import streamlit as st

# Page configuration
st.set_page_config(
    page_title="LLMCheck - AI Code Security Scanner",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': None,
        'Report a bug': None,
        'About': None
    }
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 3rem 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }
    
    .main-header h1 {
        font-size: 3.5rem;
        margin-bottom: 0.5rem;
        font-weight: 700;
    }
    
    .main-header h3 {
        font-size: 1.5rem;
        margin-bottom: 0.5rem;
        opacity: 0.95;
    }
    
    .main-header p {
        font-size: 1.1rem;
        opacity: 0.9;
    }
    
    .feature-card {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 5px solid #667eea;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        transition: transform 0.2s;
    }
    
    .feature-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(102, 126, 234, 0.3);
    }
    
    .feature-card h3 {
        color: #a5b4fc;
        margin-bottom: 0.5rem;
    }
    
    .feature-card p {
        color: #e0e0e0;
    }
    
    .stats-box {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        text-align: center;
        border: 2px solid #667eea;
        box-shadow: 0 2px 4px rgba(102, 126, 234, 0.2);
    }
    
    .stats-box h2 {
        color: #a5b4fc;
        font-size: 2.5rem;
        margin-bottom: 0.5rem;
    }
    
    .stats-box p {
        color: #d0d0d0;
        font-size: 1rem;
    }
    
    .tech-badge {
        background-color: #667eea;
        color: white;
        padding: 0.5rem 1rem;
        border-radius: 20px;
        display: inline-block;
        margin: 0.25rem;
        font-weight: 500;
    }
    
    .cta-button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem 2rem;
        border-radius: 30px;
        text-decoration: none;
        font-weight: 600;
        display: inline-block;
        margin: 0.5rem;
        transition: transform 0.2s;
    }
    
    .cta-button:hover {
        transform: scale(1.05);
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>🔒 LLMCheck</h1>
    <h3>AI Code Security Scanner</h3>
    <p>Find and fix security vulnerabilities in AI systems before attackers do</p>
</div>
""", unsafe_allow_html=True)

# Introduction
st.markdown("## 🎯 What is LLMCheck?")
st.markdown("""
**LLMCheck** (formerly AI Code Breaker) is a comprehensive security scanning tool designed to detect 
vulnerabilities in AI-powered systems. Built for developers, security teams, and organizations deploying 
AI applications, LLMCheck helps you identify critical security issues before they become exploits.
""")

# Key Features
st.markdown("## ✨ Key Features")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    <div class="feature-card">
        <h3>🎭 Prompt Injection Detection</h3>
        <p>Detects unsafe concatenation of user input into AI prompts that could allow attackers 
        to manipulate AI behavior through malicious instructions.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="feature-card">
        <h3>🔑 Hardcoded Secrets Scanner</h3>
        <p>Finds API keys, tokens, passwords, and credentials hardcoded in source code. Supports 
        OpenAI, AWS, GitHub, Anthropic, and many more providers.</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="feature-card">
        <h3>⚠️ Over-Privileged AI Tools</h3>
        <p>Identifies AI agents with dangerous permissions like delete, exec, eval, and drop 
        operations that violate the principle of least privilege.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="feature-card">
        <h3>🤖 AI-Powered Analysis</h3>
        <p>Uses Snowflake Cortex LLM to generate plain-language risk explanations and actionable 
        fix suggestions for every vulnerability discovered.</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Statistics
st.markdown("## 📊 Scanner Capabilities")
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.markdown("""
    <div class="stats-box">
        <h2>3</h2>
        <p>Vulnerability<br>Detectors</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="stats-box">
        <h2>8+</h2>
        <p>Supported<br>Languages</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="stats-box">
        <h2>1-5s</h2>
        <p>Average<br>Scan Time</p>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown("""
    <div class="stats-box">
        <h2>95%+</h2>
        <p>Detection<br>Accuracy</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Technology Stack
st.markdown("## 🛠️ Technology Stack")

st.markdown("""
<div class="feature-card">
    <span class="tech-badge">🐍 Python 3.8+</span>
    <span class="tech-badge">❄️ Snowflake Data Cloud</span>
    <span class="tech-badge">🤖 Snowflake Cortex (Mistral-Large)</span>
    <span class="tech-badge">🎨 Streamlit UI</span>
    <span class="tech-badge">📊 Pattern Matching + AST Analysis</span>
    <span class="tech-badge">📝 JSON/HTML/Markdown Reports</span>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# Quick Start
st.markdown("## 🚀 Quick Start")

tab1, tab2, tab3 = st.tabs(["💻 Web UI", "⌨️ Command Line", "🐍 Python API"])

with tab1:
    st.code("""
# Launch the web interface
streamlit run app.py

# Or use the CLI helper
python cli.py ui
    """, language="bash")
    st.info("👆 Navigate to the **Demo** page to try scanning a file right now!")

with tab2:
    st.code("""
# Scan a single file
python cli.py scan examples/vulnerable_code/example1_prompt_injection.py --snowflake

# Scan with LLM analysis
python cli.py scan myfile.py --snowflake --llm-provider snowflake_cortex

# Scan a directory recursively
python cli.py scan-dir ./myproject --recursive --snowflake

# Fast scan (no LLM, no Snowflake)
python cli.py scan myfile.py --no-llm
    """, language="bash")

with tab3:
    st.code("""
from src.scanner import AICodeScanner

# Initialize scanner with Snowflake
scanner = AICodeScanner(
    use_snowflake=True,
    use_llm_analysis=True,
    llm_provider="snowflake_cortex"
)

# Scan a file
results = scanner.scan_file("path/to/code.py")

# Print results
print(f"Found {results['total_findings']} vulnerabilities")
for finding in results['findings']:
    print(f"- {finding['vulnerability_type']}: {finding['description']}")

# Close scanner
scanner.close()
    """, language="python")

st.markdown("---")

# Use Cases
st.markdown("## 💼 Use Cases")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    **For Developers:**
    - 🔍 Scan code before committing to version control
    - 📚 Learn secure AI development practices
    - ⚡ Fix vulnerabilities during code reviews
    
    **For Security Teams:**
    - 🛡️ Automated vulnerability detection
    - 📈 Track remediation progress in Snowflake
    - 📋 Generate compliance reports
    """)

with col2:
    st.markdown("""
    **For Organizations:**
    - 🚫 Prevent data breaches and security incidents
    - 💰 Reduce security audit costs
    - ✅ Build secure AI systems from the start
    
    **For DevOps:**
    - 🔄 Integrate into CI/CD pipelines
    - 🤖 Automated pre-deployment scanning
    - 📊 Continuous security monitoring
    """)

st.markdown("---")

# Call to Action
st.markdown("## 🎯 Ready to Secure Your AI Code?")

col1, col2, col3 = st.columns([1, 1, 1])

with col1:
    st.markdown("""
    <a href="/Demo" target="_self" class="cta-button" style="text-align: center; display: block;">
        🚀 Try Demo Now
    </a>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <a href="/About" target="_self" class="cta-button" style="text-align: center; display: block;">
        📚 Learn More
    </a>
    """, unsafe_allow_html=True)

with col3:
    if st.button("📖 View Documentation", use_container_width=True):
        st.info("Check out README.md, QUICKSTART.md, and ARCHITECTURE.md in the project root!")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem 0;">
    <p>Built with ❤️ for HoyaHacks 2026 | Powered by Snowflake Data Cloud & Cortex</p>
    <p style="font-size: 0.9rem;">🔒 <strong>Security First:</strong> This tool is designed for defensive security only. 
    Always obtain proper authorization before scanning code.</p>
</div>
""", unsafe_allow_html=True)
