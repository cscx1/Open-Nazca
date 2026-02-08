import sqlite3
from flask import Flask, request, g

app = Flask(__name__)
DATABASE = 'cms_database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.route("/api/v1/login", methods=["POST"])
def login_handler():
    """Vulnerable login using string concatenation."""
    username = request.form.get("user")
    password = request.form.get("pass")
    
    cursor = get_db().cursor()
    # VULNERABLE: Direct f-string injection
    sql = f"SELECT id, role FROM users WHERE username = '{username}' AND password = '{password}'"
    
    cursor.execute(sql)
    user = cursor.fetchone()
    if user:
        return {"status": "success", "role": user[1]}
    return {"status": "fail"}, 401

@app.route("/api/v1/user/search")
def search_users():
    """Search users by name - another injection point."""
    name_query = request.args.get("q", "")
    cursor = get_db().cursor()
    
    # VULNERABLE: Multiple parameters concatenated
    # Attacker can use UNION SELECT to dump other tables
    query = "SELECT username, bio FROM users WHERE username LIKE '%" + name_query + "%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    return {"results": results}

if __name__ == "__main__":
    app.run(debug=True)