from flask import Flask, render_template
from flask_socketio import SocketIO
import threading

from extraction import (
    start_capture,
    recent_packets,
    completed_windows,
    flows
)

app = Flask(__name__)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)


@app.route("/")
def home():
    return render_template("index.html")


def capture_thread():
    start_capture(socketio)


if __name__ == "__main__":

    threading.Thread(
        target=capture_thread,
        daemon=True
    ).start()

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False
    )
