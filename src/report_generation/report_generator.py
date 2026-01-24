"""
Report Generation Module for AI Code Breaker
Creates formatted reports of security scan results.
"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates security scan reports in multiple formats (JSON, HTML, Markdown).
    """
    
    def __init__(self):
        """Initialize report generator."""
        self.severity_colors = {
            'CRITICAL': '#dc3545',  # Red
            'HIGH': '#fd7e14',      # Orange
            'MEDIUM': '#ffc107',    # Yellow
            'LOW': '#0dcaf0'        # Blue
        }
        
        self.severity_emojis = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵'
        }
    
    def generate_json_report(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_path: str
    ) -> str:
        """
        Generate JSON format report.
        
        Args:
            scan_data: Scan metadata
            findings: List of vulnerability findings
            output_path: Path to save the report
        
        Returns:
            Path to generated report
        """
        report = {
            'scan_info': {
                'scan_id': scan_data.get('scan_id'),
                'file_name': scan_data.get('file_name'),
                'language': scan_data.get('language'),
                'scan_timestamp': scan_data.get('scan_timestamp'),
                'total_findings': len(findings)
            },
            'summary': self._generate_summary(findings),
            'findings': findings
        }
        
        # Write JSON file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        logger.info(f"✓ Generated JSON report: {output_file}")
        return str(output_file)
    
    def generate_markdown_report(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_path: str
    ) -> str:
        """
        Generate Markdown format report.
        
        Args:
            scan_data: Scan metadata
            findings: List of vulnerability findings
            output_path: Path to save the report
        
        Returns:
            Path to generated report
        """
        summary = self._generate_summary(findings)
        
        # Build markdown content
        md_content = f"""# 🔒 AI Code Security Scan Report

## Scan Information

- **File:** {scan_data.get('file_name')}
- **Language:** {scan_data.get('language')}
- **Scan Time:** {scan_data.get('scan_timestamp')}
- **Scan ID:** {scan_data.get('scan_id')}

## Summary

| Severity | Count |
|----------|-------|
| 🔴 Critical | {summary['by_severity'].get('CRITICAL', 0)} |
| 🟠 High | {summary['by_severity'].get('HIGH', 0)} |
| 🟡 Medium | {summary['by_severity'].get('MEDIUM', 0)} |
| 🔵 Low | {summary['by_severity'].get('LOW', 0)} |
| **Total** | **{summary['total']}** |

### Vulnerabilities by Type

"""
        for vuln_type, count in summary['by_type'].items():
            md_content += f"- **{vuln_type}:** {count}\n"
        
        md_content += "\n---\n\n## Detailed Findings\n\n"
        
        # Group findings by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_findings = [f for f in findings if f.get('severity') == severity]
            
            if severity_findings:
                emoji = self.severity_emojis.get(severity, '')
                md_content += f"### {emoji} {severity} Severity\n\n"
                
                for i, finding in enumerate(severity_findings, 1):
                    md_content += self._format_finding_markdown(finding, i)
        
        # Write markdown file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        logger.info(f"✓ Generated Markdown report: {output_file}")
        return str(output_file)
    
    def generate_html_report(
        self,
        scan_data: Dict[str, Any],
        findings: List[Dict[str, Any]],
        output_path: str
    ) -> str:
        """
        Generate HTML format report.
        
        Args:
            scan_data: Scan metadata
            findings: List of vulnerability findings
            output_path: Path to save the report
        
        Returns:
            Path to generated report
        """
        summary = self._generate_summary(findings)
        
        # Build HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Code Security Scan Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .scan-info {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
        }}
        .summary-card .count {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .critical {{ color: #dc3545; }}
        .high {{ color: #fd7e14; }}
        .medium {{ color: #ffc107; }}
        .low {{ color: #0dcaf0; }}
        .finding {{
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 8px;
            border-left: 5px solid #ddd;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #0dcaf0; }}
        .finding h3 {{
            margin: 0 0 10px 0;
            color: #333;
        }}
        .finding .severity-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            color: white;
            margin-bottom: 15px;
        }}
        .finding .code-snippet {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            padding: 15px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            margin: 15px 0;
        }}
        .finding .section {{
            margin: 15px 0;
        }}
        .finding .section-title {{
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #666;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 AI Code Security Scan Report</h1>
        <p>Automated vulnerability detection for AI systems</p>
    </div>

    <div class="scan-info">
        <h2>Scan Information</h2>
        <p><strong>File:</strong> {scan_data.get('file_name')}</p>
        <p><strong>Language:</strong> {scan_data.get('language')}</p>
        <p><strong>Scan Time:</strong> {scan_data.get('scan_timestamp')}</p>
        <p><strong>Scan ID:</strong> {scan_data.get('scan_id')}</p>
    </div>

    <h2>Summary</h2>
    <div class="summary">
        <div class="summary-card">
            <h3>Critical</h3>
            <div class="count critical">{summary['by_severity'].get('CRITICAL', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>High</h3>
            <div class="count high">{summary['by_severity'].get('HIGH', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Medium</h3>
            <div class="count medium">{summary['by_severity'].get('MEDIUM', 0)}</div>
        </div>
        <div class="summary-card">
            <h3>Low</h3>
            <div class="count low">{summary['by_severity'].get('LOW', 0)}</div>
        </div>
    </div>

    <h2>Detailed Findings</h2>
"""
        
        # Add findings
        for finding in findings:
            html_content += self._format_finding_html(finding)
        
        html_content += """
    <div class="footer">
        <p>Generated by AI Code Breaker: LLM Security Scanner</p>
        <p>Review all findings and implement suggested fixes to improve security</p>
    </div>
</body>
</html>
"""
        
        # Write HTML file
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"✓ Generated HTML report: {output_file}")
        return str(output_file)
    
    def _generate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics from findings."""
        summary = {
            'total': len(findings),
            'by_severity': {},
            'by_type': {}
        }
        
        for finding in findings:
            # Count by severity
            severity = finding.get('severity', 'UNKNOWN')
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
            
            # Count by type
            vuln_type = finding.get('vulnerability_type', 'Unknown')
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
        
        return summary
    
    def _format_finding_markdown(self, finding: Dict[str, Any], index: int) -> str:
        """Format a single finding as Markdown."""
        md = f"""#### {index}. {finding.get('vulnerability_type', 'Unknown')}

**Location:** Line {finding.get('line_number', 'N/A')}  
**Detector:** {finding.get('detector_name', 'Unknown')}  
**Confidence:** {finding.get('confidence', 1.0) * 100:.0f}%

**Description:**  
{finding.get('description', 'No description available')}

**Code Snippet:**
```
{finding.get('code_snippet', 'No code snippet available')}
```

"""
        
        # Add LLM analysis if available
        if finding.get('risk_explanation'):
            md += f"""**Risk Explanation:**  
{finding.get('risk_explanation')}

"""
        
        if finding.get('suggested_fix'):
            md += f"""**Suggested Fix:**  
{finding.get('suggested_fix')}

"""
        
        md += "---\n\n"
        return md
    
    def _format_finding_html(self, finding: Dict[str, Any]) -> str:
        """Format a single finding as HTML."""
        severity = finding.get('severity', 'LOW').lower()
        severity_upper = severity.upper()
        color = self.severity_colors.get(severity_upper, '#6c757d')
        
        # Extract function name from code snippet if available
        code_snippet = finding.get('code_snippet', 'No code snippet available')
        function_name = self._extract_function_name(code_snippet)
        
        html = f"""
    <div class="finding {severity}">
        <h3>{finding.get('vulnerability_type', 'Unknown Vulnerability')}</h3>
        <span class="severity-badge" style="background-color: {color};">
            {severity_upper}
        </span>
        
        <div class="section">
            <div class="section-title">📍 Location:</div>
            <strong>Line {finding.get('line_number', 'N/A')}</strong>"""
        
        if function_name:
            html += f" in function <code>{function_name}</code>"
        
        html += f"""<br>
            Detector: {finding.get('detector_name', 'Unknown')} | 
            Confidence: {finding.get('confidence', 1.0) * 100:.0f}%
        </div>
        
        <div class="section">
            <div class="section-title">⚠️ Issue:</div>
            {finding.get('description', 'No description available')}
        </div>
        
        <div class="section">
            <div class="section-title">📄 Vulnerable Code:</div>
            <div class="code-snippet"><pre>{code_snippet}</pre></div>
        </div>
"""
        
        # Add LLM analysis if available
        if finding.get('risk_explanation'):
            # Clean up risk explanation - remove any code artifacts
            risk_text = finding.get('risk_explanation', '')
            risk_text = self._clean_explanation_text(risk_text)
            html += f"""
        <div class="section">
            <div class="section-title">🎯 Risk Explanation:</div>
            <p>{risk_text}</p>
        </div>
"""
        
        if finding.get('suggested_fix'):
            # Format the fix properly - preserve code blocks
            fix_text = finding.get('suggested_fix', '')
            formatted_fix = self._format_fix_with_code(fix_text)
            html += f"""
        <div class="section">
            <div class="section-title">✅ Suggested Fix:</div>
            {formatted_fix}
        </div>
"""
        
        html += "    </div>\n"
        return html
    
    def _extract_function_name(self, code_snippet: str) -> str:
        """Extract function name from code snippet."""
        import re
        # Look for Python function definition
        match = re.search(r'def\s+(\w+)\s*\(', code_snippet)
        if match:
            return match.group(1)
        # Look for JavaScript function
        match = re.search(r'function\s+(\w+)\s*\(', code_snippet)
        if match:
            return match.group(1)
        # Look for arrow function assignment
        match = re.search(r'(const|let|var)\s+(\w+)\s*=.*=>', code_snippet)
        if match:
            return match.group(2)
        return ""
    
    def _clean_explanation_text(self, text: str) -> str:
        """Clean up explanation text - remove code artifacts and formatting issues."""
        import re
        # Remove any code blocks that snuck in
        text = re.sub(r'```[\s\S]*?```', '', text)
        # Remove lines that look like code
        lines = text.split('\n')
        clean_lines = []
        for line in lines:
            # Skip lines that look like code
            if line.strip().startswith(('def ', 'return ', 'import ', '{', '}', 'model=', '#')):
                continue
            if '=' in line and '(' in line and ')' in line:  # Likely code
                continue
            clean_lines.append(line)
        text = ' '.join(clean_lines)
        # Clean up whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def _format_fix_with_code(self, fix_text: str) -> str:
        """Format fix text to properly display code examples."""
        import re
        import html
        
        # Clean up markdown code block markers
        fix_text = re.sub(r'```python\s*', '\n', fix_text)
        fix_text = re.sub(r'```\s*', '\n', fix_text)
        fix_text = re.sub(r'\bpython\n', '\n', fix_text)  # Standalone "python" language tags
        
        # Check if fix contains code examples (our structured format or LLM format)
        if '# VULNERABLE' in fix_text or '# SAFE' in fix_text or 'Vulnerable' in fix_text or 'Safe' in fix_text:
            # Split into explanation and code sections
            parts = []
            current_text = []
            in_code = False
            
            for line in fix_text.split('\n'):
                stripped = line.strip()
                # Detect start of code section
                is_code_header = (
                    (stripped.startswith('#') and ('VULNERABLE' in stripped or 'SAFE' in stripped)) or
                    stripped.startswith('Vulnerable code:') or
                    stripped.startswith('Safe code:') or
                    stripped.startswith('Vulnerable pattern:') or
                    stripped.startswith('Safe alternative:')
                )
                
                if is_code_header:
                    if current_text:
                        parts.append(('text', '\n'.join(current_text)))
                        current_text = []
                    in_code = True
                    current_text.append(line)
                elif in_code:
                    # Check if we're back to explanatory text (long sentence, no code patterns)
                    is_code_line = (
                        stripped.startswith(('#', 'def ', 'import ', 'return', 'if ', 'for ', 'while ')) or
                        stripped.startswith(('{', '}', '[', ']', "'", '"')) or
                        any(kw in stripped for kw in ['api_key', 'messages', 'tools', 'prompt', 'response', 
                                                       'secret', 'confirm', 'log_', 'os.', 'openai.', 
                                                       'print(', 'load_dotenv', '= [', '= {', '("']) or
                        (stripped.count('=') > 0 and stripped.count('"') >= 2) or
                        stripped.endswith((',', ']', '}', ')'))
                    )
                    
                    if stripped and not is_code_line and len(stripped) > 60 and stripped[0].isupper():
                        # Looks like explanatory text
                        if current_text:
                            parts.append(('code', '\n'.join(current_text)))
                            current_text = []
                        in_code = False
                        current_text.append(line)
                    else:
                        current_text.append(line)
                else:
                    current_text.append(line)
            
            # Add remaining content
            if current_text:
                parts.append(('code' if in_code else 'text', '\n'.join(current_text)))
            
            # Build HTML
            result = ""
            for part_type, content in parts:
                if part_type == 'code':
                    result += f'<div class="code-snippet"><pre>{html.escape(content)}</pre></div>'
                else:
                    clean_text = content.strip()
                    if clean_text:
                        result += f'<p>{html.escape(clean_text)}</p>'
            
            return result if result else f'<p>{html.escape(fix_text)}</p>'
        
        # Fallback: just wrap in paragraph
        return f'<p>{html.escape(fix_text)}</p>'
    
    def generate_console_summary(self, scan_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> str:
        """
        Generate a console-friendly summary for terminal output.
        
        Args:
            scan_data: Scan metadata
            findings: List of findings
        
        Returns:
            Formatted console output string
        """
        summary = self._generate_summary(findings)
        
        output = "\n" + "="*70 + "\n"
        output += "🔒 AI CODE SECURITY SCAN RESULTS\n"
        output += "="*70 + "\n\n"
        
        output += f"File: {scan_data.get('file_name')}\n"
        output += f"Language: {scan_data.get('language')}\n"
        output += f"Scan ID: {scan_data.get('scan_id')}\n\n"
        
        output += "SUMMARY:\n"
        output += f"  🔴 Critical: {summary['by_severity'].get('CRITICAL', 0)}\n"
        output += f"  🟠 High:     {summary['by_severity'].get('HIGH', 0)}\n"
        output += f"  🟡 Medium:   {summary['by_severity'].get('MEDIUM', 0)}\n"
        output += f"  🔵 Low:      {summary['by_severity'].get('LOW', 0)}\n"
        output += f"  ─────────────────────\n"
        output += f"  Total:      {summary['total']}\n\n"
        
        if summary['by_type']:
            output += "BY TYPE:\n"
            for vuln_type, count in sorted(summary['by_type'].items()):
                output += f"  • {vuln_type}: {count}\n"
        
        output += "\n" + "="*70 + "\n"
        
        return output


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    generator = ReportGenerator()
    print("Report generator ready!")

