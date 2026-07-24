import os
from flask import Flask, send_from_directory
from frontend.api.routes import api
from ingestion.simulator import start_simulator

app = Flask(__name__, static_folder="static", static_url_path="")
app.register_blueprint(api, url_prefix="/api")

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    # If debug mode is enabled, Flask's Werkzeug reloader runs the entrypoint twice.
    # Start the simulator only in the active worker process (WERKZEUG_RUN_MAIN=true).
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        start_simulator()
    elif not os.environ.get("WERKZEUG_RUN_MAIN") and not app.debug:
        start_simulator()

    app.run(debug=True, port=5002)