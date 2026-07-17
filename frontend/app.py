"""
Enterprise Cloud / MSSP - SOAR Incident Containment Engine
Frontend + lightweight mock backend (Rohit's branch: frontend)

Run:
    pip install flask --break-system-packages
    python -m frontend.app
Then open http://127.0.0.1:5002
"""

from flask import Flask, send_from_directory
from frontend.api.routes import api

app = Flask(__name__, static_folder="static", static_url_path="")
app.register_blueprint(api, url_prefix="/api")


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)