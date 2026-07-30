import os
from flask import Flask, send_from_directory
from frontend.api.routes import api
from ingestion.simulator import start_simulator

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = os.getenv("SECRET_KEY", "soarvault_production_secret_key_2026")
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.register_blueprint(api, url_prefix="/api")

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    is_prod = os.getenv("ENVIRONMENT") == "production"
    port = int(os.getenv("PORT", 5000 if is_prod else 5002))
    host = "0.0.0.0" if is_prod else "127.0.0.1"

    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or is_prod:
        start_simulator()
    elif not os.environ.get("WERKZEUG_RUN_MAIN") and not is_prod:
        start_simulator()

    app.run(debug=not is_prod, host=host, port=port)
