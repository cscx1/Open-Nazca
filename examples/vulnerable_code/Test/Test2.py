from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

# Mock dashboard template
DASH_HTML = """
<html>
    <body>
        <h1>Corporate Dashboard</h1>
        <div id="search-section">
            <p>You searched for: {{ search_term | safe }}</p>
        </div>
        <form action="/search" method="GET">
            <input type="text" name="query" placeholder="Search reports...">
            <input type="submit" value="Go">
        </form>
        <hr>
        <a href="/logout?next=/login">Logout</a>
    </body>
</html>
"""

@app.route("/dashboard")
def dashboard():
    # VULNERABLE: search_term is marked 'safe' in Jinja, bypassing auto-escaping
    query = request.args.get("query", "")
    return render_template_string(DASH_HTML, search_term=query)

@app.route("/logout")
def logout():
    """Vulnerable to Open Redirect."""
    target = request.args.get("next", "/login")
    
    # VULNERABLE: Redirecting to a user-controlled URL without validation
    # Attacker can use: /logout?next=http://malicious-site.com
    return redirect(target)

if __name__ == "__main__":
    app.run(port=5001)