import os
from flask import Flask, jsonify
from scraper import run_scrape_job

app = Flask(__name__)

@app.get("/run_scraper")
def run_scraper():
    result = run_scrape_job()
    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)