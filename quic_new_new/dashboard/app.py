from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO
import threading
import logging

from extraction import (
    start_capture,
    recent_packets,
    completed_windows,
    prediction_history,
    flows,
    OVS_AVAILABLE,
)

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

@socketio.on('connect')
def handle_connect():
    import extraction
    # Emit a single state payload to initialize the frontend correctly
    socketio.emit("init_state", {
        "packet_counter": extraction.packet_counter,
        "flow_counter": extraction.flow_counter,
        # Get the total window count from the latest window ID across all flows
        "window_counter": sum(f.get("window_id", 0) for f in flows.values()),
        "recent_packets": list(recent_packets),
        "flows": [{
            "flow_id": f["flow_id"],
            "flow_key": k,
            "current_class": f.get("current_class", "DEFAULT"),
            "sni": f.get("sni", "")
        } for k, f in flows.items()],
        "completed_windows": list(completed_windows),
        "predictions": list(prediction_history)
    }, to=request.sid)


# ── OVS QoS initialisation ────────────────────────────────────────────────────
if OVS_AVAILABLE:
    import ovs_qos

    def _init_ovs():
        try:
            ovs_qos.setup_htb_qos()
            # Emit initial allocation state so the QoS page shows correct
            # starting config (Default=100%, others=0) immediately on connect
            socketio.emit("qos_bw_alloc", {
                "queues": {
                    str(q): {
                        "queue":   q,
                        "name":    ovs_qos.QUEUE_META[q]["name"],
                        "color":   ovs_qos.QUEUE_META[q]["color"],
                        "min_bps": ovs_qos._queue_min_bps[q],
                        "max_bps": ovs_qos._queue_max_bps[q],
                        "active":  q in ovs_qos._active_queues,
                        "weight":  ovs_qos.QUEUE_WEIGHT[q],
                    } for q in range(4)
                },
                "total_bps": ovs_qos.TOTAL_BPS,
                "active":    list(ovs_qos._active_queues),
            })
        except Exception as exc:
            logging.warning("[app] OVS QoS setup failed: %s", exc)

    threading.Thread(target=_init_ovs, daemon=True).start()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/qos")
def qos_page():
    return render_template("qos.html")

@app.route("/firewall")
def firewall_page():
    return render_template("firewall.html")


# ── ACL REST API ──────────────────────────────────────────────────────────────

@app.route("/api/acl/rules", methods=["GET"])
def acl_get_rules():
    import ovs_acl
    return jsonify(ovs_acl.get_rules())


@app.route("/api/acl/rules", methods=["POST"])
def acl_add_rule():
    """
    Body: { "dst_ip": "10.0.0.2", "category": "ALL" | 0 | 1 | 2, "dst_port": 443 | null }
    """
    import ovs_acl
    try:
        data     = request.get_json(force=True)
        dst_ip   = data.get("dst_ip", "").strip()
        category = data.get("category", "ALL")
        dst_port = data.get("dst_port")

        if not dst_ip:
            return jsonify({"ok": False, "error": "dst_ip required"}), 400

        if category != "ALL":
            try:
                category = int(category)
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "category must be ALL|0|1|2"}), 400

        if dst_port is not None and dst_port != "":
            try:
                dst_port = int(dst_port)
                if not (1 <= dst_port <= 65535):
                    return jsonify({"ok": False, "error": "port must be 1-65535"}), 400
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "port must be a number 1-65535"}), 400
        else:
            dst_port = None

        rule = ovs_acl.add_rule(dst_ip, category, socketio, dst_port=dst_port)
        socketio.emit("acl_rules_updated", ovs_acl.get_rules())
        return jsonify({"ok": True, "rule": ovs_acl._rule_to_dict(rule)})
    except Exception as exc:
        logging.error("[ACL] add_rule error: %s", exc, exc_info=True)
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/acl/rules/<rule_id>", methods=["DELETE"])
def acl_remove_rule(rule_id: str):
    import ovs_acl
    try:
        ok = ovs_acl.remove_rule(rule_id, socketio)
        socketio.emit("acl_rules_updated", ovs_acl.get_rules())
        return jsonify({"ok": ok})
    except Exception as exc:
        logging.error("[ACL] remove_rule error: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/acl/clear", methods=["POST"])
def acl_clear():
    import ovs_acl
    try:
        ovs_acl.clear_all(socketio)
        socketio.emit("acl_rules_updated", [])
        return jsonify({"ok": True})
    except Exception as exc:
        logging.error("[ACL] clear error: %s", exc)
        return jsonify({"ok": False, "error": str(exc)}), 500


# ── QoS REST API ──────────────────────────────────────────────────────────────

@app.route("/api/qos/status")
def qos_status():
    if not OVS_AVAILABLE:
        return jsonify({"error": "OVS not available"}), 503
    return jsonify(ovs_qos.get_status())

@app.route("/api/qos/flows")
def qos_flows():
    if not OVS_AVAILABLE:
        return jsonify({"error": "OVS not available"}), 503
    return jsonify({"flows": ovs_qos.dump_flows()})


@app.route("/api/qos/queue/<int:queue_num>", methods=["POST"])
def update_queue(queue_num: int):
    """
    Update bandwidth limits for a queue at runtime.
    Body: { "min_bps": 2000000, "max_bps": 5000000 }
    """
    if not OVS_AVAILABLE:
        return jsonify({"error": "OVS not available"}), 503

    data = request.get_json(force=True)
    mn = int(data.get("min_bps", ovs_qos._queue_min_bps.get(queue_num, 0)))
    mx = int(data.get("max_bps", ovs_qos._queue_max_bps.get(queue_num, ovs_qos.TOTAL_BPS)))

    ok = ovs_qos.update_queue_bandwidth(queue_num, mn, mx)
    if ok:
        socketio.emit("qos_config_updated", ovs_qos.get_status())
        return jsonify({"ok": True, "queue": queue_num, "min_bps": mn, "max_bps": mx})
    return jsonify({"ok": False, "error": "Failed to update queue"}), 500


@app.route("/api/qos/teardown", methods=["POST"])
def teardown():
    if not OVS_AVAILABLE:
        return jsonify({"error": "OVS not available"}), 503
    ovs_qos.teardown_qos()
    socketio.emit("qos_config_updated", {"qos_ready": False})
    return jsonify({"ok": True})


# ── Capture thread ────────────────────────────────────────────────────────────

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
