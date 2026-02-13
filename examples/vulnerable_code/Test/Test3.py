import os
from flask import Flask, request, send_file, abort

app = Flask(__name__)
STORAGE_DIR = os.path.abspath("./uploads/public_docs")

def logger(msg):
    # Log requests to help scanner see flow
    print(f"[LOG] Request for: {msg}")

@app.route("/docs/view")
def view_document():
    doc_name = request.args.get("file")
    if not doc_name:
        return "Missing file parameter", 400

    # VULNERABLE: Joining paths without checking for '..'
    # Attacker can use: ?file=../../../../etc/passwd
    full_path = os.path.join(STORAGE_DIR, doc_name)
    
    logger(full_path)

    if os.path.exists(full_path):
        try:
            return send_file(full_path)
        except Exception as e:
            return str(e), 500
    else:
        return "Document not found", 404

@app.route("/docs/list")
def list_docs():
    """List all available files in the directory."""
    files = os.listdir(STORAGE_DIR)
    return {"files": files}

if __name__ == "__main__":
    app.run(port=5002)