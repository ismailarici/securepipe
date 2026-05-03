import subprocess
import sqlite3
import pickle
import os
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded credential — intentional vulnerability for demo
DATABASE_PASSWORD = "SuperSecret123!"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
db.execute("INSERT INTO users VALUES (1, 'admin', 'administrator')")
db.commit()


@app.route("/")
def home():
    return jsonify({"status": "ok", "message": "SecurePipe sample app"})


@app.route("/user")
def get_user():
    name = request.args.get("name", "")
    # SQL injection — no parameterised query
    cursor = db.execute(f"SELECT * FROM users WHERE name = '{name}'")
    rows = cursor.fetchall()
    return jsonify({"users": rows})


@app.route("/run")
def run_command():
    cmd = request.args.get("cmd", "echo hello")
    # OS command injection — shell=True with user input
    result = subprocess.check_output(cmd, shell=True)
    return jsonify({"output": result.decode()})


@app.route("/load", methods=["POST"])
def load_data():
    # Insecure deserialization
    data = request.get_data()
    obj = pickle.loads(data)
    return jsonify({"loaded": str(obj)})


@app.route("/parse", methods=["POST"])
def parse_config():
    # Unsafe YAML deserialization — CVE-2020-14343 (CRITICAL)
    data = request.get_data().decode()
    parsed = yaml.load(data)
    return jsonify({"parsed": str(parsed)})


@app.route("/debug")
def debug_info():
    return jsonify({
        "env": dict(os.environ),
        "password": DATABASE_PASSWORD,
    })


if __name__ == "__main__":
    # debug=True in production
    app.run(host="0.0.0.0", port=5000, debug=True)
