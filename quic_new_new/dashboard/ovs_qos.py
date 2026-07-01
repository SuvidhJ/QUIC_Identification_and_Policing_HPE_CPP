"""
ovs_qos.py  –  Real OVS HTB QoS with dynamic bandwidth allocation.

Queue layout on s1-eth2 (egress toward h2):
  Queue 0  Default   unclassified QUIC flows
  Queue 1  Video     ML class 1   ← highest priority
  Queue 2  Data      ML class 2
  Queue 3  Web       ML class 0

Bandwidth allocation is fully dynamic:
  - At start, only Default queue exists → gets 100% of the link (max-rate)
    with min-rate = 0 (HTB borrows freely up to root ceiling).
  - When the first flow of a class is classified, that queue becomes active.
    We recompute every active queue's min-rate using a weighted fair-share
    based on priority weights, and push the update to OVS via ovs-vsctl.
  - Priority weights: Video=4, Data=2, Web=1, Default=1
    e.g. Video + Data active → Video gets 4/6 * total, Data gets 2/6 * total.
  - Default queue always gets whatever is left unclaimed.
  - max-rate for each queue = total link rate (HTB allows bursting up to root).
  - Stats are read from real kernel `tc -s class show dev s1-eth2` counters
    and from `ovs-ofctl dump-flows`.  Nothing is computed, estimated, or faked.

Stats are pushed over SocketIO immediately after each tc read (triggered by
the capture thread via notify_packet, not by a polling timer).
"""

import subprocess
import logging
import threading
import re
import time
from collections import deque
from typing import Dict, Tuple, Optional

log = logging.getLogger("ovs_qos")

# ── Topology ──────────────────────────────────────────────────────────────────
SWITCH      = "s1"
EGRESS_PORT = "s1-eth2"
OF_PORT     = 2            # OpenFlow port number for s1-eth2

TOTAL_BPS   = 10_000_000   # 10 Mbps link

# ML class → OVS queue number
CLASS_TO_QUEUE: Dict[int, int] = {
    1: 1,   # Video → queue 1
    2: 2,   # Data  → queue 2
    0: 3,   # Web   → queue 3
}
DEFAULT_QUEUE = 0

# Priority weights for dynamic bandwidth allocation (higher = more share)
QUEUE_WEIGHT = {
    1: 4,   # Video   – highest
    2: 2,   # Data
    3: 1,   # Web
    0: 1,   # Default – gets remainder
}

QUEUE_META = {
    0: {"name": "Default", "color": "#607d8b"},
    1: {"name": "Video",   "color": "#f44336"},
    2: {"name": "Data",    "color": "#ff9800"},
    3: {"name": "Web",     "color": "#2196f3"},
}

# ── State ─────────────────────────────────────────────────────────────────────
_lock   = threading.Lock()
_qos_ready        = False
_installed_flows: Dict[str, int] = {}    # flow_key → queue_num

# Dynamic bandwidth: only queues that have ≥1 classified flow
_active_queues: set = {0}                # starts with only Default

# Current allocated min_bps per queue (computed dynamically)
_queue_min_bps: Dict[int, int] = {0: 0, 1: 0, 2: 0, 3: 0}
_queue_max_bps: Dict[int, int] = {0: TOTAL_BPS, 1: TOTAL_BPS, 2: TOTAL_BPS, 3: TOTAL_BPS}

# Stats state
_stats_lock  = threading.Lock()
_prev_tc     : Dict[int, dict] = {}
_prev_tc_ts  : float = 0.0
_live_stats  : Dict[int, dict] = {
    q: {"bps": 0.0, "pps": 0.0, "tx_bytes": 0, "tx_pkts": 0,
        "tx_errors": 0, "history_bps": deque(maxlen=60), "history_pps": deque(maxlen=60)}
    for q in range(4)
}
_of_flow_cache: list = []

# Socketio reference (set once in start_stats_loop)
_socketio = None

# Stats push throttle: push at most once per second
_last_push: float = 0.0

# ── Subprocess helper ─────────────────────────────────────────────────────────

def _run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("CMD: %s", cmd)
    r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"[{r.returncode}] {cmd}\n{r.stderr.strip()}")
    return r


# ── HTB setup ─────────────────────────────────────────────────────────────────

def setup_htb_qos() -> None:
    """
    Create linux-htb QoS on EGRESS_PORT.
    All 4 queues are created with min-rate=0 / max-rate=TOTAL_BPS.
    Dynamic allocation will update them as traffic classes appear.
    """
    global _qos_ready

    log.info("[OVS-QoS] Setting up HTB on %s", EGRESS_PORT)

    # Clear any existing QoS
    _run(f"ovs-vsctl clear port {EGRESS_PORT} qos", check=False)
    _run("ovs-vsctl --all destroy qos",   check=False)
    _run("ovs-vsctl --all destroy queue", check=False)
    time.sleep(0.3)

    total = str(TOTAL_BPS)

    # All queues start with min=0, max=TOTAL_BPS
    # Default (Q0) effectively gets everything at startup since it's the only
    # queue receiving traffic and HTB lets it burst to max-rate.
    cmd = (
        f"ovs-vsctl set port {EGRESS_PORT} qos=@newqos -- "
        f"--id=@newqos create qos type=linux-htb "
        f"other-config:max-rate={total} "
        f"queues:0=@q0 queues:1=@q1 queues:2=@q2 queues:3=@q3 -- "
        f"--id=@q0 create queue other-config:min-rate=0 other-config:max-rate={total} -- "
        f"--id=@q1 create queue other-config:min-rate=0 other-config:max-rate={total} -- "
        f"--id=@q2 create queue other-config:min-rate=0 other-config:max-rate={total} -- "
        f"--id=@q3 create queue other-config:min-rate=0 other-config:max-rate={total}"
    )
    _run(cmd)

    # Install catch-all default rule (priority 1 → queue 0)
    _run(f"ovs-ofctl del-flows {SWITCH}", check=False)
    _run(
        f"ovs-ofctl add-flow {SWITCH} "
        f"priority=1,in_port=1,actions=enqueue:{OF_PORT}:{DEFAULT_QUEUE}",
        check=False
    )

    with _lock:
        _queue_min_bps[0] = 0
        _queue_max_bps[0] = TOTAL_BPS

    _qos_ready = True
    log.info("[OVS-QoS] Ready. Default queue has full link (min=0 max=%d)", TOTAL_BPS)


def teardown_qos() -> None:
    global _qos_ready
    _run(f"ovs-ofctl del-flows {SWITCH}", check=False)
    _run(f"ovs-vsctl clear port {EGRESS_PORT} qos", check=False)
    _run("ovs-vsctl --all destroy qos",   check=False)
    _run("ovs-vsctl --all destroy queue", check=False)
    with _lock:
        _installed_flows.clear()
        _active_queues.clear()
        _active_queues.add(0)
    _qos_ready = False
    log.info("[OVS-QoS] Teardown complete.")


# ── Dynamic bandwidth allocation ──────────────────────────────────────────────

def _recompute_and_apply_bw(socketio=None) -> None:
    """
    Called whenever _active_queues changes.
    Computes weighted fair-share min-rates for all active queues
    and pushes them to OVS via ovs-vsctl set queue.
    Default queue gets whatever the weighted queues don't claim.
    Must be called with _lock held.
    """
    active_non_default = _active_queues - {0}

    if not active_non_default:
        # Only Default active: give it 0 min (can burst to max=TOTAL_BPS)
        _queue_min_bps[0] = 0
        _apply_queue_bw(0, 0, TOTAL_BPS)
        _emit_bw_update(socketio)
        return

    # Weighted share for non-default queues
    total_weight = sum(QUEUE_WEIGHT[q] for q in active_non_default)
    committed    = 0

    for q in active_non_default:
        share   = int((QUEUE_WEIGHT[q] / total_weight) * TOTAL_BPS)
        # Leave at least 10% for Default so unclassified traffic isn't starved
        share   = min(share, int(TOTAL_BPS * 0.9 / len(active_non_default)))
        _queue_min_bps[q] = share
        _queue_max_bps[q] = TOTAL_BPS   # can burst to full link
        committed += share
        _apply_queue_bw(q, share, TOTAL_BPS)
        log.info("[OVS-QoS] Queue %d (%s) min=%d bps",
                 q, QUEUE_META[q]["name"], share)

    # Default gets remainder as min, still bursts to full
    default_min = max(0, TOTAL_BPS - committed)
    _queue_min_bps[0] = default_min
    _queue_max_bps[0] = TOTAL_BPS
    _apply_queue_bw(0, default_min, TOTAL_BPS)
    log.info("[OVS-QoS] Queue 0 (Default) min=%d bps (remainder)", default_min)

    _emit_bw_update(socketio)


def _apply_queue_bw(queue_num: int, min_bps: int, max_bps: int) -> None:
    """Push min/max-rate update for one queue to OVS kernel."""
    try:
        r = _run(f"ovs-vsctl get port {EGRESS_PORT} qos")
        qos_uuid = r.stdout.strip()
        if not qos_uuid or qos_uuid == "[]":
            return
        r = _run(f"ovs-vsctl get qos {qos_uuid} queues:{queue_num}")
        q_uuid = r.stdout.strip()
        if not q_uuid:
            return
        _run(
            f"ovs-vsctl set queue {q_uuid} "
            f"other-config:min-rate={min_bps} "
            f"other-config:max-rate={max_bps}"
        )
    except RuntimeError as e:
        log.warning("[OVS-QoS] _apply_queue_bw q%d failed: %s", queue_num, e)


def _emit_bw_update(socketio) -> None:
    """Emit a bandwidth allocation change event so the UI updates immediately."""
    if socketio is None:
        return
    alloc = {}
    for q in range(4):
        alloc[str(q)] = {
            "queue":   q,
            "name":    QUEUE_META[q]["name"],
            "color":   QUEUE_META[q]["color"],
            "min_bps": _queue_min_bps[q],
            "max_bps": _queue_max_bps[q],
            "active":  q in _active_queues,
            "weight":  QUEUE_WEIGHT[q],
        }
    socketio.emit("qos_bw_alloc", {
        "queues":     alloc,
        "total_bps":  TOTAL_BPS,
        "active":     list(_active_queues),
    })


# ── Flow classification → OF rule install ─────────────────────────────────────

def apply_flow_classification(
    flow_key: str,
    src_ip: str, dst_ip: str,
    src_port: str, dst_port: str,
    traffic_class: int,
    socketio=None
) -> bool:
    """
    Install OpenFlow enqueue rule for a classified QUIC flow.
    Also activates the queue and rebalances bandwidth if this is the
    first flow of that class.
    Returns True if OF rule was installed.
    """
    if not _qos_ready:
        return False

    queue_num = CLASS_TO_QUEUE.get(traffic_class, DEFAULT_QUEUE)

    with _lock:
        already = _installed_flows.get(flow_key)
        if already == queue_num:
            return True   # no change needed

        is_new_class = queue_num not in _active_queues

        _installed_flows[flow_key] = queue_num

        if is_new_class:
            _active_queues.add(queue_num)
            log.info("[OVS-QoS] New class activated: queue %d (%s)",
                     queue_num, QUEUE_META[queue_num]["name"])
            _recompute_and_apply_bw(socketio)

    # Install bidirectional OF rules
    matches = _build_matches(src_ip, dst_ip, src_port, dst_port)
    installed = False
    for match in matches:
        try:
            _run(
                f"ovs-ofctl add-flow {SWITCH} "
                f"priority=100,{match},"
                f"actions=enqueue:{OF_PORT}:{queue_num}"
            )
            installed = True
        except RuntimeError as e:
            log.warning("[OVS-QoS] add-flow failed: %s", e)

    if installed and socketio:
        socketio.emit("qos_rule_installed", {
            "flow_key":   flow_key,
            "queue":      queue_num,
            "queue_name": QUEUE_META[queue_num]["name"],
            "class":      traffic_class,
            "match":      matches[0] if matches else "",
            "new_class":  is_new_class,
        })

    return installed


def _build_matches(src_ip, dst_ip, src_port, dst_port):
    matches = []
    try:
        matches.append(
            f"udp,nw_src={src_ip.strip()},nw_dst={dst_ip.strip()},"
            f"tp_src={src_port.strip()},tp_dst={dst_port.strip()}"
        )
        matches.append(
            f"udp,nw_src={dst_ip.strip()},nw_dst={src_ip.strip()},"
            f"tp_src={dst_port.strip()},tp_dst={src_port.strip()}"
        )
    except Exception:
        pass
    return matches


# ── Real stats from kernel ─────────────────────────────────────────────────────

def _read_tc_stats() -> dict:
    """
    Read `tc -s class show dev <port>` and return per-queue cumulative counters.
    Returns {queue_num: {tx_bytes, tx_pkts, tx_errors}} or {} on failure.
    HTB creates classes 1:1, 1:2, 1:3, 1:4 for queues 0, 1, 2, 3.
    """
    r = subprocess.run(
        f"tc -s class show dev {EGRESS_PORT}",
        shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    if r.returncode != 0:
        return {}

    stats = {}
    cur_q = None
    for line in r.stdout.splitlines():
        m = re.search(r'class htb 1:(\d+)', line)
        if m:
            cur_q = int(m.group(1)) - 1   # 1:1→0, 1:2→1, 1:3→2, 1:4→3
            stats[cur_q] = {"tx_bytes": 0, "tx_pkts": 0, "tx_errors": 0}
            continue
        if cur_q is None:
            continue
        m = re.search(r'Sent (\d+) bytes (\d+) pkt.*dropped (\d+)', line)
        if m:
            stats[cur_q] = {
                "tx_bytes":  int(m.group(1)),
                "tx_pkts":   int(m.group(2)),
                "tx_errors": int(m.group(3)),
            }
    return stats


def _read_of_flows() -> list:
    """
    Read `ovs-ofctl dump-flows` and return only priority-100 classified rules
    with their real packet/byte counters.
    """
    r = _run(f"ovs-ofctl dump-flows {SWITCH}", check=False)
    flows_out = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("NXST", "OFPST")):
            continue
        m_pri = re.search(r'priority=(\d+)', line)
        pri   = int(m_pri.group(1)) if m_pri else 0
        if pri != 100:
            continue   # skip default catch-all rules

        entry = {
            "priority":  pri,
            "n_packets": int(re.search(r'n_packets=(\d+)', line).group(1)) if re.search(r'n_packets=(\d+)', line) else 0,
            "n_bytes":   int(re.search(r'n_bytes=(\d+)',   line).group(1)) if re.search(r'n_bytes=(\d+)',   line) else 0,
            "nw_src":    (re.search(r'nw_src=([\d.]+)',    line) or type('', (), {'group': lambda s,n: ''})()).group(1),
            "nw_dst":    (re.search(r'nw_dst=([\d.]+)',    line) or type('', (), {'group': lambda s,n: ''})()).group(1),
            "tp_src":    (re.search(r'tp_src=(\d+)',       line) or type('', (), {'group': lambda s,n: ''})()).group(1),
            "tp_dst":    (re.search(r'tp_dst=(\d+)',       line) or type('', (), {'group': lambda s,n: ''})()).group(1),
        }
        m_q = re.search(r'enqueue:\d+:(\d+)', line)
        entry["queue"]      = int(m_q.group(1)) if m_q else -1
        entry["queue_name"] = QUEUE_META.get(entry["queue"], {}).get("name", "—")
        entry["color"]      = QUEUE_META.get(entry["queue"], {}).get("color", "#888")
        flows_out.append(entry)
    return flows_out


def push_stats(socketio) -> None:
    """
    Read real tc + OF stats and push them to all connected clients.
    Called from the packet capture thread (event-driven, not polled).
    Throttled to at most once per second.
    """
    global _last_push, _of_flow_cache

    if not _qos_ready:
        return

    now = time.monotonic()
    if now - _last_push < 1.0:
        return
    _last_push = now

    # ── tc counters ──────────────────────────────────────────────────────────
    tc = _read_tc_stats()

    with _stats_lock:
        prev_ts   = _prev_tc_ts if _prev_tc_ts else now
        elapsed   = max(0.01, now - prev_ts)

        for q in range(4):
            cur  = tc.get(q, {"tx_bytes": 0, "tx_pkts": 0, "tx_errors": 0})
            prev = _prev_tc.get(q, {"tx_bytes": 0, "tx_pkts": 0})

            dbytes = max(0, cur["tx_bytes"] - prev["tx_bytes"])
            dpkts  = max(0, cur["tx_pkts"]  - prev["tx_pkts"])
            bps    = dbytes / elapsed
            pps    = dpkts  / elapsed

            _live_stats[q].update({
                "bps":       round(bps, 1),
                "pps":       round(pps, 2),
                "tx_bytes":  cur["tx_bytes"],
                "tx_pkts":   cur["tx_pkts"],
                "tx_errors": cur["tx_errors"],
            })
            _live_stats[q]["history_bps"].append(round(bps / 1000, 2))
            _live_stats[q]["history_pps"].append(round(pps, 2))

            _prev_tc[q] = cur

        # Use a local variable to avoid modifying global inside lock
        _prev_tc_ts_new = now

    # Update global timestamp outside inner lock scope
    with _stats_lock:
        pass
    # Set timestamp (fine outside lock since it's a single float write)
    globals()['_prev_tc_ts'] = now

    # ── OF flows ─────────────────────────────────────────────────────────────
    _of_flow_cache = _read_of_flows()

    # ── ACL stats refresh ─────────────────────────────────────────────────────
    try:
        import ovs_acl
        ovs_acl.refresh_stats()
        if socketio:
            socketio.emit("acl_stats", ovs_acl.get_rules())
    except Exception as e:
        log.debug("ACL stats refresh error: %s", e)

    # ── Emit ─────────────────────────────────────────────────────────────────
    if socketio:
        socketio.emit("qos_stats", _build_payload())


def _build_payload() -> dict:
    with _stats_lock:
        queues = {}
        for q in range(4):
            s  = _live_stats[q]
            mn = _queue_min_bps[q]
            mx = _queue_max_bps[q]
            queues[str(q)] = {
                "name":        QUEUE_META[q]["name"],
                "color":       QUEUE_META[q]["color"],
                "bps":         s["bps"],
                "kbps":        round(s["bps"] / 1000, 2),
                "pps":         s["pps"],
                "tx_bytes":    s["tx_bytes"],
                "tx_pkts":     s["tx_pkts"],
                "tx_errors":   s["tx_errors"],
                "min_bps":     mn,
                "max_bps":     mx,
                "utilization": round(min(100.0, s["bps"] / max(1, mx) * 100), 1),
                "active":      q in _active_queues,
                "weight":      QUEUE_WEIGHT[q],
                "history_bps": list(s["history_bps"]),
                "history_pps": list(s["history_pps"]),
            }

    with _lock:
        installed_snap = dict(_installed_flows)

    return {
        "qos_ready":    _qos_ready,
        "egress_port":  EGRESS_PORT,
        "total_bps":    TOTAL_BPS,
        "queues":       queues,
        "of_flows":     list(_of_flow_cache),
        "active_queues": list(_active_queues),
        "installed_flows": {
            k: {"queue": v, "queue_name": QUEUE_META[v]["name"]}
            for k, v in installed_snap.items()
        },
    }


# ── Public API ────────────────────────────────────────────────────────────────

def get_status() -> dict:
    with _lock:
        installed = dict(_installed_flows)
    queues = {}
    for q in range(4):
        queues[str(q)] = {
            **QUEUE_META[q],
            "min_bps": _queue_min_bps[q],
            "max_bps": _queue_max_bps[q],
            "active":  q in _active_queues,
            "weight":  QUEUE_WEIGHT[q],
        }
    return {
        "qos_ready":       _qos_ready,
        "egress_port":     EGRESS_PORT,
        "total_bps":       TOTAL_BPS,
        "queues":          queues,
        "active_queues":   list(_active_queues),
        "installed_flows": installed,
        "stats":           _build_payload(),
    }


def dump_flows() -> str:
    r = _run(f"ovs-ofctl dump-flows {SWITCH}", check=False)
    return r.stdout
