# Verdict Rule Order and Precedence

## Why order matters

1. **SQL Sanitizer before Taint Reachability**  
   Parameterized queries should be marked Out-of-scope. If Taint ran first, it would mark them Confirmed (reachable). So SQL Sanitizer (and Input Validation) must run before Taint.

2. **Unverified does not terminate**  
   The engine only stops when a rule returns **Confirmed** or **Out-of-scope**. If a rule returns **Unverified** (e.g. "file in /tests/"), evaluation continues. A later rule can still return Confirmed or Out-of-scope, avoiding false negatives.

3. **Environment first**  
   Non-production paths (/tests/, /examples/) are tagged Unverified early, but a later rule (e.g. Taint) can override with Confirmed if the finding is still in scope.

## Canonical order

| Order | Rule | Purpose |
|-------|------|---------|
| 1 | Environment Neutralizer | Unverified for /tests/, /examples/ (does not stop) |
| 2 | XSS Context | XSS: Confirmed only with output context; Out-of-scope if no web/routing |
| 3 | SQL Sanitizer | SQL Injection + parameterized line → Out-of-scope |
| 4 | Input Validation | Same-line allowlist/sanitization → Out-of-scope |
| 5 | Taint Reachability | Confirmed Reachable → Confirmed |
| 6 | Pattern-Only Fallback | No attack path / Unverifiable → Unverified |

## Adding new rules

- **Mitigation rules** (e.g. “already fixed”): add **before** Taint Reachability so they can override reachability.
- **Positive rules** (e.g. “definitely exploitable”): add **before** Pattern-Only Fallback so they can override Unverified.
- **Optional rules**: pass `extra_rules=[YourRule()]` to `VerdictEngine(project_root, extra_rules=...)`. They run after the built-in list; same precedence (Unverified does not stop).

## When multiple rules match

The engine does not “first match wins” for Unverified. It runs all rules in order and:

- Stops on first **Confirmed** or **Out-of-scope** and uses that verdict.
- If only **Unverified** (and/or None) was returned, uses the last Unverified, or default Unverified if none.

So: Confirmed/Out-of-scope take precedence over Unverified regardless of order; among Confirmed/Out-of-scope, the first one in rule order wins.
