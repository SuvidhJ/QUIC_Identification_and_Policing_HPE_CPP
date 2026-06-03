from flask import Flask, render_template, jsonify

from live_flow_windows import (
    recent_packets,
    flows,
    completed_windows
)

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/dashboard")
def dashboard():

    return jsonify({

        "packet_count": len(recent_packets),

        "flow_count": len(flows),

        "window_count": len(completed_windows),

        "packets": list(recent_packets)[::-1],

        "flows": [
            {
                "flow_id": f["flow_id"],
                "window_id": f["window_id"],
                "packet_count": len(f["packets"]),
                "duration": round(
                    f["window_start"] - f["flow_start"],
                    2
                )
            }
            for f in flows.values()
        ],

        "windows": list(completed_windows)[::-1][:5]
    })


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
