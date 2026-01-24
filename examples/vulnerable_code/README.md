# Example Vulnerable Code

This directory contains intentionally vulnerable code examples for testing the AI Code Breaker scanner.

## ⚠️ WARNING

**These files contain intentional security vulnerabilities for demonstration purposes only.**

**DO NOT:**
- Use this code in production
- Commit real API keys or secrets
- Execute the vulnerable code without understanding the risks

## Examples

### 1. Prompt Injection (`example1_prompt_injection.py`)
Demonstrates unsafe concatenation of user input into AI prompts.

**Vulnerabilities:**
- Direct string concatenation with user input
- Using `.format()` with user queries
- Mixing system prompts with user content

**Test Command:**
```bash
python -m src.scanner examples/vulnerable_code/example1_prompt_injection.py
```

### 2. Hardcoded Secrets (`example2_hardcoded_secrets.py`)
Shows various ways API keys and credentials can be exposed in code.

**Vulnerabilities:**
- OpenAI and Anthropic API keys in code
- AWS credentials hardcoded
- Database passwords in connection strings
- GitHub and Slack tokens exposed

**Test Command:**
```bash
python -m src.scanner examples/vulnerable_code/example2_hardcoded_secrets.py
```

### 3. Over-Privileged Tools (`example3_overprivileged_tools.py`)
Illustrates AI agents with excessive permissions.

**Vulnerabilities:**
- File deletion capabilities
- Command execution access
- Database DROP operations
- Using `eval()` with AI-generated code

**Test Command:**
```bash
python -m src.scanner examples/vulnerable_code/example3_overprivileged_tools.py
```

## Safe Alternatives

Each example file also includes safe alternatives demonstrating proper security practices:
- Structured message formats for prompts
- Environment variable usage for secrets
- Read-only operations for AI agents
- Human-in-the-loop approval for dangerous operations

## Expected Results

When scanning these files, you should see:
- **Critical** findings for prompt injection and hardcoded secrets
- **High** findings for over-privileged tools
- Detailed risk explanations (if LLM analysis is enabled)
- Safe code fix suggestions

## Learning Objectives

These examples help you understand:
1. Common security pitfalls in AI systems
2. How attackers could exploit these vulnerabilities
3. Best practices for secure AI development
4. The importance of defense in depth

