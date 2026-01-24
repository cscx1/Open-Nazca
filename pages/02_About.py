"""
LLMCheck - AI Code Security Scanner
About Page: Project Details, Team, and Resources
"""

import streamlit as st
from pathlib import Path

# Page configuration
st.set_page_config(
    page_title="About - LLMCheck",
    page_icon="ℹ️",
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
    
    .info-card {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        border-left: 5px solid #667eea;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
    }
    
    .info-card h3 {
        color: #a5b4fc;
        margin-bottom: 0.5rem;
    }
    
    .info-card p, .info-card ul, .info-card li {
        color: #e0e0e0;
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
    
    .vulnerability-box {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        border: 2px solid #667eea;
        margin: 1rem 0;
        box-shadow: 0 2px 4px rgba(102, 126, 234, 0.2);
    }
    
    .vulnerability-box h3 {
        color: #a5b4fc !important;
    }
    
    .vulnerability-box p {
        color: #e0e0e0;
    }
    
    .vulnerability-box strong {
        color: #a5b4fc;
        font-weight: 600;
    }
    
    /* Target Streamlit's generated markdown elements */
    div[data-testid="stMarkdown"] h3 {
        color: #a5b4fc !important;
    }
    
    div[data-testid="stMarkdown"] p {
        color: #e0e0e0 !important;
    }
    
    div[data-testid="stMarkdown"] strong {
        color: #a5b4fc !important;
    }
    
    .feature-list {
        background: rgba(30, 30, 46, 0.5);
        padding: 1rem;
        border-radius: 8px;
        margin: 0.5rem 0;
        color: #e0e0e0;
    }
    
    .feature-list strong {
        color: #a5b4fc;
        font-weight: 600;
    }
    
    .info-card strong {
        color: #a5b4fc;
        font-weight: 600;
    }
    
    .team-card {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        padding: 1.5rem;
        border-radius: 10px;
        margin: 1rem 0;
        border: 2px solid #667eea;
        box-shadow: 0 2px 4px rgba(102, 126, 234, 0.2);
        text-align: center;
    }
    
    .team-card h4 {
        color: #a5b4fc;
        margin-bottom: 0.5rem;
        font-size: 1.3rem;
    }
    
    .team-card p {
        color: #e0e0e0;
        margin: 0.5rem 0;
    }
    
    .social-links {
        margin-top: 1rem;
    }
    
    .social-links a {
        color: #667eea;
        text-decoration: none;
        margin: 0 0.5rem;
        font-weight: 500;
        transition: color 0.2s;
    }
    
    .social-links a:hover {
        color: #a5b4fc;
    }
</style>
""", unsafe_allow_html=True)

# Header
st.markdown("""
<div class="main-header">
    <h1>ℹ️ About LLMCheck</h1>
    <h3>Comprehensive AI Security Scanning</h3>
    <p>Learn more about our mission, technology, and team</p>
</div>
""", unsafe_allow_html=True)

# Mission Section
st.markdown("## 🎯 Our Mission")
st.markdown("""
**LLMCheck** (formerly AI Code Breaker) was created to address the growing security challenges in 
AI-powered applications. As artificial intelligence becomes increasingly integrated into critical 
systems, the potential for security vulnerabilities grows. Our mission is to:

- 🛡️ **Protect** AI systems from emerging security threats
- 📚 **Educate** developers about secure AI development practices
- ⚡ **Accelerate** the detection and remediation of vulnerabilities
- 🌐 **Enable** organizations to build trustworthy AI applications
""")

st.markdown("---")

# What We Detect Section
st.markdown("## 🔍 What We Detect")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("""
    <div class="vulnerability-box">
        <h3>🎭 Prompt Injection</h3>
        <p><strong>What it is:</strong> Attackers manipulate AI behavior by injecting malicious instructions into prompts through unsafe string concatenation.</p>
        <p><strong>Why it matters:</strong> Can lead to data exfiltration, unauthorized actions, or complete AI system compromise.</p>
        <p><strong>How we detect it:</strong> Pattern matching and AST analysis to identify unsafe user input concatenation in AI prompts.</p>
        <p><strong>CWE:</strong> CWE-74 (Improper Neutralization)</p>
        <p><strong>OWASP:</strong> LLM01:2023</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="vulnerability-box">
        <h3>🔑 Hardcoded Secrets</h3>
        <p><strong>What it is:</strong> API keys, passwords, tokens, and credentials stored directly in source code instead of secure vaults.</p>
        <p><strong>Why it matters:</strong> Exposed secrets can lead to unauthorized access, data breaches, and significant financial damage.</p>
        <p><strong>How we detect it:</strong> Advanced regex patterns for OpenAI, AWS, GitHub, Anthropic, and 20+ other providers.</p>
        <p><strong>CWE:</strong> CWE-798 (Hard-coded Credentials)</p>
        <p><strong>OWASP:</strong> A02:2021</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown("""
    <div class="vulnerability-box">
        <h3>⚠️ Over-Privileged Tools</h3>
        <p><strong>What it is:</strong> AI agents granted excessive permissions like delete, exec, eval, or drop operations.</p>
        <p><strong>Why it matters:</strong> Violates the principle of least privilege and can result in catastrophic system damage.</p>
        <p><strong>How we detect it:</strong> Contextual analysis of AI tool definitions to identify dangerous operation grants.</p>
        <p><strong>CWE:</strong> CWE-269 (Improper Privilege Management)</p>
        <p><strong>OWASP:</strong> LLM08:2023</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Technology Architecture
st.markdown("## 🏗️ Technology Architecture")

st.markdown("""
LLMCheck uses a modular, production-ready architecture designed for extensibility and performance.
""")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    <div class="info-card">
        <h3>🔧 Core Components</h3>
        <p><strong>Code Ingestion Module:</strong> Safely reads and parses code files with multi-language support and encoding fallback.</p>
        <p><strong>Detection Engine:</strong> Pattern-based and AST analysis for accurate vulnerability detection with minimal false positives.</p>
        <p><strong>LLM Analyzer:</strong> Snowflake Cortex (Mistral-Large) generates plain-language explanations and actionable fix suggestions.</p>
        <p><strong>Report Generator:</strong> Creates JSON, HTML, and Markdown reports with syntax highlighting and severity color-coding.</p>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="info-card">
        <h3>❄️ Snowflake Integration</h3>
        <p><strong>Data Storage:</strong> All scan results and findings persisted in Snowflake for long-term tracking and analytics.</p>
        <p><strong>Cortex LLM:</strong> Uses Snowflake Cortex for AI-powered analysis, eliminating the need for separate OpenAI/Anthropic accounts.</p>
        <p><strong>Analytics Ready:</strong> Pre-built SQL views for vulnerability trends, remediation tracking, and compliance reporting.</p>
        <p><strong>Single Platform:</strong> One credential, one system for complete security workflow management.</p>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Technology Stack
st.markdown("## 🛠️ Complete Technology Stack")

st.markdown("""
<div class="info-card">
    <h3>Core Technologies</h3>
    <span class="tech-badge">🐍 Python 3.8+</span>
    <span class="tech-badge">❄️ Snowflake Data Cloud</span>
    <span class="tech-badge">🤖 Snowflake Cortex (Mistral-Large)</span>
    <span class="tech-badge">🎨 Streamlit</span>
</div>

<div class="info-card">
    <h3>Detection & Analysis</h3>
    <span class="tech-badge">📊 Pattern Matching</span>
    <span class="tech-badge">🌲 AST (Abstract Syntax Tree) Analysis</span>
    <span class="tech-badge">🔍 Regex-based Secret Detection</span>
    <span class="tech-badge">🧠 Context-Aware Analysis</span>
</div>

<div class="info-card">
    <h3>Reporting & Output</h3>
    <span class="tech-badge">📝 JSON Reports</span>
    <span class="tech-badge">🌐 HTML Reports</span>
    <span class="tech-badge">📄 Markdown Reports</span>
    <span class="tech-badge">💻 Console Output</span>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# Use Cases
st.markdown("## 💼 Real-World Use Cases")

tab1, tab2, tab3, tab4 = st.tabs(["Developers", "Security Teams", "Organizations", "DevOps"])

with tab1:
    st.markdown("""
    ### 👨‍💻 For Developers
    
    **Pre-Commit Scanning:**
    - Scan code before committing to version control
    - Catch vulnerabilities during development
    - Learn secure coding practices through AI explanations
    
    **Code Reviews:**
    - Automated security checks during peer reviews
    - Reduce manual security review burden
    - Standardize security assessment criteria
    
    **Learning & Education:**
    - Understand AI security vulnerabilities
    - See real examples of insecure code
    - Get actionable fix suggestions
    """)

with tab2:
    st.markdown("""
    ### 🛡️ For Security Teams
    
    **Automated Auditing:**
    - Scan entire codebases quickly
    - Identify security hotspots
    - Prioritize remediation efforts by severity
    
    **Vulnerability Tracking:**
    - Store all findings in Snowflake
    - Track remediation progress over time
    - Generate compliance reports
    
    **Threat Intelligence:**
    - Identify patterns in vulnerabilities
    - Measure security posture improvements
    - Benchmark against industry standards
    """)

with tab3:
    st.markdown("""
    ### 🏢 For Organizations
    
    **Risk Mitigation:**
    - Prevent data breaches before they occur
    - Reduce potential financial and reputational damage
    - Demonstrate due diligence to stakeholders
    
    **Cost Reduction:**
    - Lower security audit costs
    - Reduce incident response expenses
    - Minimize developer remediation time
    
    **Compliance:**
    - Meet security compliance requirements
    - Document security scanning processes
    - Maintain audit trails in Snowflake
    """)

with tab4:
    st.markdown("""
    ### 🔄 For DevOps
    
    **CI/CD Integration:**
    - Automated scanning in deployment pipelines
    - Fail builds on critical vulnerabilities
    - Generate security reports per deployment
    
    **Continuous Monitoring:**
    - Regular scheduled scans
    - Alert on new vulnerability introductions
    - Track security metrics over time
    
    **Infrastructure as Code:**
    - Scan configuration files
    - Detect secrets in deployment scripts
    - Validate security policies
    """)

st.markdown("---")

# Security & Ethics
st.markdown("## 🔐 Security & Responsible Use")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    <div class="info-card">
        <h3>✅ Acceptable Use</h3>
        <ul>
            <li>Scanning your own code and projects</li>
            <li>Security audits with proper authorization</li>
            <li>Educational and research purposes</li>
            <li>CI/CD pipeline integration</li>
            <li>Security training and awareness</li>
            <li>Compliance and regulatory audits</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="info-card">
        <h3>❌ Prohibited Use</h3>
        <ul>
            <li>Generating exploit code or attacks</li>
            <li>Scanning code without authorization</li>
            <li>Attacking or compromising systems</li>
            <li>Violating terms of service</li>
            <li>Malicious security research</li>
            <li>Unauthorized penetration testing</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

st.warning("""
⚠️ **Important:** This tool is designed for **defensive security only**. Always obtain proper 
authorization before scanning code you don't own. Use responsibly and ethically.
""")

st.markdown("---")

# Resources
st.markdown("## 📚 Resources & Documentation")

col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    ### 📖 Project Documentation
    - **README.md** - Quick start guide
    - **QUICKSTART.md** - Detailed setup instructions
    - **ARCHITECTURE.md** - System design and architecture
    - **SNOWFLAKE_SETUP.md** - Snowflake configuration guide
    
    ### 🔗 External Resources
    - [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
    - [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)
    - [Snowflake Security Best Practices](https://docs.snowflake.com/en/user-guide/security)
    """)

with col2:
    st.markdown("""
    ### 🧪 Testing Resources
    - Example vulnerable files in `examples/vulnerable_code/`
    - Unit tests (coming soon)
    - Integration test suite (coming soon)
    
    ### 🛠️ Development
    - Python package structure
    - Modular detector architecture
    - Extensible LLM provider support
    - Custom report generators
    """)

st.markdown("---")

# Future Roadmap
st.markdown("## 🚀 Future Roadmap")

roadmap_col1, roadmap_col2 = st.columns(2)

with roadmap_col1:
    st.markdown("""
    <div class="info-card">
        <h3>🎯 Short-Term Goals</h3>
        <ul>
            <li>Additional vulnerability detectors (SQL injection, XSS)</li>
            <li>Support for more programming languages</li>
            <li>Enhanced AST-based detection</li>
            <li>Improved false positive filtering</li>
            <li>Performance optimizations</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

with roadmap_col2:
    st.markdown("""
    <div class="info-card">
        <h3>🌟 Long-Term Vision</h3>
        <ul>
            <li>CI/CD plugins (GitHub Actions, GitLab CI)</li>
            <li>IDE extensions (VS Code, PyCharm)</li>
            <li>ML-based detection using Snowflake ML</li>
            <li>Automated fix generation and PR creation</li>
            <li>Real-time scanning and monitoring</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

# Team & Credits
st.markdown("## 👥 Meet the Team")

st.markdown("""
### Built with ❤️ for HoyaHacks 2026

**LLMCheck** was developed by a passionate team dedicated to making AI systems more secure.
""")

# Team members in a 2x2 grid
col1, col2 = st.columns(2)

with col1:
    st.markdown("""
    <div class="team-card">
        <h4>Diego Zane</h4>
        <div class="social-links">
            <a href="https://github.com/cscx1" target="_blank">🔗 GitHub</a>
            <a href="https://www.linkedin.com/in/diegozane/" target="_blank">💼 LinkedIn</a>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="team-card">
        <h4>Michael Brown</h4>
        <div class="social-links">
            <a href="https://github.com/Mikebrown4768" target="_blank">🔗 GitHub</a>
            <a href="https://www.linkedin.com/in/michael-brown-jr-914069190/" target="_blank">💼 LinkedIn</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown("""
    <div class="team-card">
        <h4>Shaun Hoffmann</h4>
        <div class="social-links">
            <a href="https://github.com/ShaunHoffmann" target="_blank">🔗 GitHub</a>
            <a href="https://www.linkedin.com/in/shaunhoffmann/" target="_blank">💼 LinkedIn</a>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    <div class="team-card">
        <h4>Jungho An</h4>
        <div class="social-links">
            <a href="https://github.com/JungAn2" target="_blank">🔗 GitHub</a>
            <a href="https://www.linkedin.com/in/jungho-an-8958001b9/" target="_blank">💼 LinkedIn</a>
        </div>
    </div>
    """, unsafe_allow_html=True)

st.markdown("---")

st.markdown("""
### 🙏 Special Thanks

- **Snowflake** for providing the Data Cloud platform and Cortex LLM capabilities
- The **open-source security community** for vulnerability research and best practices
- **OWASP** for comprehensive security guidelines and frameworks
""")

st.markdown("---")

# Contact & Support
st.markdown("## 📧 Contact & Support")

col1, col2, col3 = st.columns(3)

with col1:
    st.info("""
    **📖 Documentation**
    
    Check the project's README.md 
    and other documentation files 
    in the repository root.
    """)

with col2:
    st.info("""
    **🐛 Bug Reports**
    
    Found an issue? Report it 
    on the project's issue 
    tracker on GitHub.
    """)

with col3:
    st.info("""
    **💡 Feature Requests**
    
    Have an idea? We welcome 
    contributions and suggestions 
    from the community!
    """)

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem 0;">
    <p><strong>LLMCheck - AI Code Security Scanner</strong></p>
    <p>Powered by Snowflake Data Cloud & Cortex | Built for HoyaHacks 2026</p>
    <p style="font-size: 0.9rem; margin-top: 1rem;">
        🔒 Remember: Security is not a one-time check. Regular scanning and staying updated 
        on security best practices are essential for maintaining secure AI systems.
    </p>
</div>
""", unsafe_allow_html=True)
