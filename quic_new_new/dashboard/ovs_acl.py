"""
ovs_acl.py  –  Real OVS packet-blocking rules via OpenFlow drop actions.

How it works:
  - Rules are stored in _rules dict (rule_id → rule)
  - Each rule specifies: dst_ip, category (ALL / 0=Web / 1=Video / 2=Data)
  - "Block ALL traffic to dst_ip":
      Immediately installs priority-200 drop rule in OVS:
        ovs-ofctl add-flow s1 priority=200,udp,nw_dst=<ip>,actions=drop
  - "Block category X traffic to dst_ip":
      Rule is stored. When extraction.py classifies a flow going to dst_ip
      as category X, check_and_enforce() installs a drop rule for that
      specific 5-tuple at priority 200.
  - Blocked packet counts come from real OVS n_packets counters on drop rules.
    Nothing is estimated or made up.

Priority hierarchy in OVS:
  200  – drop rules (ACL)        ← always wins
  100  – enqueue rules (QoS)
    1  – default catch-all
"""

import subprocess
import threading
import logging
import re
import time
from typing import Dict, Optional

log = logging.getLogger("ovs_acl")

SWITCH  = "s1"
OF_PORT = 2    # egress port toward h2

# Category constants (match extraction.py)
CAT_ALL   = "ALL"
CAT_VIDEO = 1
CAT_DATA  = 2
CAT_WEB   = 0

CAT_NAMES = {CAT_VIDEO: "Video", CAT_DATA: "Data", CAT_WEB: "Web", CAT_ALL: "All"}

# ── State ─────────────────────────────────────────────────────────────────────
_lock    = threading.Lock()
_rules:  Dict[str, dict] = {}   # rule_id → rule dict
_rule_counter = 0

# rule dict schema:
# {
#   "rule_id":   str,
#   "dst_ip":    str,
#   "category":  "ALL" | 0 | 1 | 2,
#   "active":    bool,
#   "created_at": float,
#   # Counters updated from OVS dump-flows
#   "blocked_packets": int,
#   "blocked_bytes":   int,
#   # OF cookie assigned to this rule (hex str) for easy lookup
#   "cookie": str,
#   # List of installed OF matches (may be multiple for category rules)
#   "of_matches": [str],
# }

_cookie_counter = 0xACE00001   # start from a recognisable base


# ── OVS helpers ───────────────────────────────────────────────────────────────

def _run(cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    log.debug("ACL CMD: %s", cmd)
    r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(f"[{r.returncode}] {cmd}\n{r.stderr.strip()}")
    return r


def _next_cookie() -> str:
    global _cookie_counter
    _cookie_counter += 1
    return hex(_cookie_counter)


# ── Rule management ───────────────────────────────────────────────────────────

def add_rule(dst_ip: str, category, socketio=None, dst_port=None) -> dict:
    """
    Add a blocking rule.
    category: "ALL" | 0 (Web) | 1 (Video) | 2 (Data)
    dst_port: int or None (None = match any port)

    For ALL: installs an immediate broad drop rule in OVS.
    For category: stores the rule; OF rules are installed per-flow
    when classification happens via check_and_enforce().

    Returns the rule dict.
    """
    global _rule_counter

    dst_ip   = dst_ip.strip()
    # Normalise category — keep "ALL" as string, integers as int
    if category != CAT_ALL:
        category = int(category)

    # Normalise port
    if dst_port is not None:
        dst_port = int(dst_port)
        if not (1 <= dst_port <= 65535):
            dst_port = None

    # Deduplicate: don't add the same dst_ip+category+port twice
    with _lock:
        for r in _rules.values():
            if (r["dst_ip"] == dst_ip and r["category"] == category
                    and r.get("dst_port") == dst_port and r["active"]):
                log.info("[ACL] Duplicate rule ignored: %s %s port=%s", dst_ip, category, dst_port)
                return r

        _rule_counter += 1
        rule_id = f"rule-{_rule_counter}"
        cookie  = _next_cookie()

        rule = {
            "rule_id":         rule_id,
            "dst_ip":          dst_ip,
            "dst_port":        dst_port,
            "category":        category,
            "category_name":   CAT_NAMES.get(category, str(category)),
            "active":          True,
            "created_at":      time.time(),
            "blocked_packets": 0,
            "blocked_bytes":   0,
            "cookie":          cookie,
            "of_matches":      [],
        }
        _rules[rule_id] = rule

    # Install OF rule outside lock
    if category == CAT_ALL:
        match = f"udp,nw_dst={dst_ip}"
        if dst_port is not None:
            match += f",tp_dst={dst_port}"
        _install_drop(rule_id, match, cookie)

    if socketio:
        try:
            socketio.emit("acl_rule_added", _rule_to_dict(rule))
        except Exception as e:
            log.warning("[ACL] socketio emit failed: %s", e)

    log.info("[ACL] Rule added: %s  dst=%s  cat=%s", rule_id, dst_ip, category)
    return rule


def remove_rule(rule_id: str, socketio=None) -> bool:
    """Remove a blocking rule and delete its OF drop flows from OVS."""
    with _lock:
        rule = _rules.get(rule_id)
        if not rule:
            return False
        rule["active"] = False
        matches  = list(rule["of_matches"])
        cookie   = rule["cookie"]

    # Delete by cookie — removes all OF entries for this rule
    _run(
        f"ovs-ofctl del-flows {SWITCH} cookie={cookie}/-1",
        check=False
    )
    log.info("[ACL] Rule removed: %s  (deleted %d OF entries)", rule_id, len(matches))

    if socketio:
        socketio.emit("acl_rule_removed", {"rule_id": rule_id})

    return True


def check_and_enforce(
    flow_key:       str,
    dst_ip:         str,
    src_ip:         str,
    src_port:       str,
    dst_port:       str,
    traffic_class:  int,
    socketio=None
) -> bool:
    """
    Called from extraction.py after a flow is classified.
    Checks if any active category rule targets dst_ip with this traffic_class.
    If so, installs a specific 5-tuple drop rule in OVS.
    Returns True if a new drop rule was installed.
    """
    dst_port_int = None
    try:
        dst_port_int = int(dst_port)
    except (ValueError, TypeError):
        pass

    with _lock:
      matching_rules = [
        r for r in _rules.values()
        if r["active"]
        and r["dst_ip"] == dst_ip
        and r["category"] == traffic_class
        and (r.get("dst_port") is None or r.get("dst_port") == dst_port_int)
    ]

    if not matching_rules:
        return False

    installed = False
    for rule in matching_rules:
        # Build specific 5-tuple drop match
        fwd_match = f"udp,nw_src={src_ip},nw_dst={dst_ip},tp_src={src_port},tp_dst={dst_port}"
        rev_match = f"udp,nw_src={dst_ip},nw_dst={src_ip},tp_src={dst_port},tp_dst={src_port}"

        # Collect matches that need installing (under lock),
        # then install them OUTSIDE the lock to avoid deadlock
        # (_install_drop also acquires _lock internally).
        to_install = []
        with _lock:
            for match in (fwd_match, rev_match):
                if match not in rule["of_matches"]:
                    to_install.append(match)

        for match in to_install:
            result = _install_drop(rule["rule_id"], match, rule["cookie"])
            if result:
                installed = True

        if installed and socketio:
            socketio.emit("acl_flow_blocked", {
                "rule_id":       rule["rule_id"],
                "flow_key":      flow_key,
                "dst_ip":        dst_ip,
                "category":      traffic_class,
                "category_name": CAT_NAMES.get(traffic_class, str(traffic_class)),
            })
            log.info("[ACL] Flow blocked: %s → %s  cat=%s  rule=%s",
                     flow_key, dst_ip, traffic_class, rule["rule_id"])

    return installed


def _install_drop(rule_id: str, match: str, cookie: str) -> bool:
    """
    Install a priority-200 drop rule in OVS for the given match.
    Returns True on success, False on failure (non-fatal — rule stays stored).
    """
    cmd = (
        f"ovs-ofctl add-flow {SWITCH} "
        f"cookie={cookie},priority=200,{match},actions=drop"
    )
    try:
        _run(cmd)
        with _lock:
            rule = _rules.get(rule_id)
            if rule and match not in rule["of_matches"]:
                rule["of_matches"].append(match)
        log.info("[ACL] Drop rule installed: %s  match=%s", rule_id, match)
        return True
    except RuntimeError as e:
        log.warning("[ACL] Failed to install drop rule for %s: %s", rule_id, e)
        return False


# ── Stats refresh from OVS ────────────────────────────────────────────────────

def refresh_stats() -> None:
    """
    Read n_packets/n_bytes for every drop rule from ovs-ofctl dump-flows.
    Groups by cookie to accumulate per-rule totals.
    Called from push_stats in ovs_qos.py (already throttled to 1/s).
    """
    r = _run(f"ovs-ofctl dump-flows {SWITCH}", check=False)

    # Map cookie → (packets, bytes)
    cookie_stats: Dict[str, tuple] = {}

    for line in r.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith(("NXST", "OFPST")):
            continue

        # Only care about drop rules (priority 200)
        m_pri = re.search(r'priority=(\d+)', line)
        if not m_pri or int(m_pri.group(1)) != 200:
            continue

        m_ck = re.search(r'cookie=(0x[0-9a-f]+)', line)
        if not m_ck:
            continue
        ck = m_ck.group(1)

        m_pkts  = re.search(r'n_packets=(\d+)', line)
        m_bytes = re.search(r'n_bytes=(\d+)',   line)
        pkts  = int(m_pkts.group(1))  if m_pkts  else 0
        bts   = int(m_bytes.group(1)) if m_bytes else 0

        if ck not in cookie_stats:
            cookie_stats[ck] = (0, 0)
        p, b = cookie_stats[ck]
        cookie_stats[ck] = (p + pkts, b + bts)

    # Update rule counters
    with _lock:
        for rule in _rules.values():
            if not rule["active"]:
                continue
            ck = rule["cookie"]
            if ck in cookie_stats:
                rule["blocked_packets"] = cookie_stats[ck][0]
                rule["blocked_bytes"]   = cookie_stats[ck][1]


# ── Serialisation ─────────────────────────────────────────────────────────────

def _rule_to_dict(rule: dict) -> dict:
    return {
        "rule_id":         rule["rule_id"],
        "dst_ip":          rule["dst_ip"],
        "dst_port":        rule.get("dst_port"),
        "category":        rule["category"],
        "category_name":   rule["category_name"],
        "active":          rule["active"],
        "blocked_packets": rule["blocked_packets"],
        "blocked_bytes":   rule["blocked_bytes"],
        "of_matches":      rule["of_matches"],
        "created_at":      rule["created_at"],
    }


def get_rules() -> list:
    with _lock:
        return [_rule_to_dict(r) for r in _rules.values() if r["active"]]


def get_all_rules() -> list:
    with _lock:
        return [_rule_to_dict(r) for r in _rules.values()]


def clear_all(socketio=None) -> None:
    """Remove all active rules."""
    with _lock:
        ids = list(_rules.keys())
    for rid in ids:
        remove_rule(rid, socketio)
