/**
 * firewall.js
 *
 * Real-time blocked traffic visualization.
 * Every counter comes from real OVS n_packets/n_bytes on priority-200
 * drop rules read via ovs-ofctl dump-flows.
 *
 * SocketIO events used:
 *   acl_rules_updated  – full rule list, fires on add/remove/clear
 *   acl_stats          – per-rule counters, fires every second with traffic
 *   acl_flow_blocked   – fires the moment a new drop rule is installed for a flow
 *   acl_rule_added     – fires when a rule is created
 *   acl_rule_removed   – fires when a rule is deleted
 */

const socket = io();

const CAT_META = {
  "ALL": { label: "All",   cls: "cat-all",   color: "#f44336" },
  "1":   { label: "Video", cls: "cat-video", color: "#f44336" },
  "2":   { label: "Data",  cls: "cat-data",  color: "#ff9800" },
  "0":   { label: "Web",   cls: "cat-web",   color: "#2196f3" },
};

let rules = [];   // current rule list (from server)

// ── Add rule ──────────────────────────────────────────────────────────────────
function addRule() {
  const ip      = document.getElementById("inputIp").value.trim();
  const portStr = document.getElementById("inputPort").value.trim();
  const cat     = document.getElementById("inputCat").value;
  const msg     = document.getElementById("addRuleMsg");

  if (!ip) {
    msg.style.color = "#f44336";
    msg.textContent = "Enter a destination IP address.";
    return;
  }
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    msg.style.color = "#f44336";
    msg.textContent = "Invalid IP address format.";
    return;
  }

  let dst_port = null;
  if (portStr !== "") {
    dst_port = parseInt(portStr, 10);
    if (isNaN(dst_port) || dst_port < 1 || dst_port > 65535) {
      msg.style.color = "#f44336";
      msg.textContent = "Port must be a number between 1 and 65535.";
      return;
    }
  }

  fetch("/api/acl/rules", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ dst_ip: ip, category: cat, dst_port: dst_port }),
  })
  .then(r => r.json())
  .then(d => {
    if (d.ok) {
      const portLabel = dst_port ? `:${dst_port}` : "";
      msg.style.color = "#00ff88";
      msg.textContent  = `Rule added: ${ip}${portLabel}  category=${cat}`;
      document.getElementById("inputIp").value = "";
      document.getElementById("inputPort").value = "";
      logBlock(`Rule added → block ${CAT_META[String(cat)]?.label ?? cat} to ${ip}${portLabel}`, "bl-add");
    } else {
      msg.style.color = "#f44336";
      msg.textContent  = d.error || "Failed to add rule";
      logBlock(`Error: ${d.error || "unknown"}`, "bl-remove");
    }
    setTimeout(() => { msg.textContent = ""; }, 5000);
  })
  .catch(err => {
    msg.style.color = "#f44336";
    msg.textContent = "Request failed: " + err;
    setTimeout(() => { msg.textContent = ""; }, 5000);
  });
}

function deleteRule(ruleId) {
  fetch(`/api/acl/rules/${ruleId}`, { method: "DELETE" })
    .then(r => r.json())
    .then(d => {
      if (d.ok) logBlock(`Rule ${ruleId} removed`, "bl-remove");
    });
}

function clearAll() {
  if (!confirm("Remove all blocking rules?")) return;
  fetch("/api/acl/clear", { method: "POST" })
    .then(() => logBlock("All rules cleared", "bl-remove"));
}

// ── Render rules table ────────────────────────────────────────────────────────
function renderRules(ruleList) {
  rules = ruleList;
  const tbody = document.getElementById("rulesTable");
  tbody.innerHTML = "";

  let totalPkts  = 0;
  let totalBytes = 0;

  const active = ruleList.filter(r => r.active !== false);

  document.getElementById("totalRules").textContent = active.length;

  if (active.length === 0) {
    tbody.innerHTML = `<tr><td colspan="9" class="empty-row">No active block rules</td></tr>`;
    document.getElementById("totalBlocked").textContent      = "0";
    document.getElementById("totalBlockedBytes").textContent = "0 B";
    renderBreakdown([]);
    return;
  }

  active.forEach(r => {
    totalPkts  += r.blocked_packets || 0;
    totalBytes += r.blocked_bytes   || 0;

    const catKey  = String(r.category);
    const catMeta = CAT_META[catKey] || { label: catKey, cls: "cat-all", color: "#888" };
    const created = new Date(r.created_at * 1000).toLocaleTimeString();
    const matches = r.of_matches?.length || 0;
    const pkts    = (r.blocked_packets || 0).toLocaleString();
    const bytes   = fmtBytes(r.blocked_bytes || 0);
    const hiPkts  = (r.blocked_packets || 0) > 0 ? "count-hi" : "";
    const portStr = r.dst_port != null ? r.dst_port : "Any";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="font-family:monospace;font-size:11px;color:#9ba3c7">${r.rule_id}</td>
      <td><b>${r.dst_ip}</b></td>
      <td>${portStr}</td>
      <td><span class="cat-badge ${catMeta.cls}">${catMeta.label}</span></td>
      <td>${matches} OF rule${matches !== 1 ? "s" : ""}
        ${r.category === "ALL"
          ? '<span style="font-size:10px;color:#9ba3c7"> (broad match)</span>'
          : '<span style="font-size:10px;color:#9ba3c7"> (per-flow)</span>'}
      </td>
      <td class="${hiPkts}">${pkts}</td>
      <td>${bytes}</td>
      <td style="font-size:11px;color:#9ba3c7">${created}</td>
      <td><button class="btn-del" onclick="deleteRule('${r.rule_id}')">Remove</button></td>`;
    tbody.appendChild(tr);
  });

  document.getElementById("totalBlocked").textContent      = totalPkts.toLocaleString();
  document.getElementById("totalBlockedBytes").textContent = fmtBytes(totalBytes);

  renderBreakdown(active);
}

// ── Breakdown chart ───────────────────────────────────────────────────────────
function renderBreakdown(active) {
  const el = document.getElementById("breakdown");
  if (active.length === 0) {
    el.innerHTML = `<p style="color:#9ba3c7;font-size:13px">No rules yet</p>`;
    return;
  }

  const maxPkts = Math.max(1, ...active.map(r => r.blocked_packets || 0));
  let html = "";

  active.forEach(r => {
    const catKey  = String(r.category);
    const catMeta = CAT_META[catKey] || { label: catKey, color: "#f44336" };
    const pct     = Math.round(((r.blocked_packets || 0) / maxPkts) * 100);
    html += `
<div class="bkd-row">
  <div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">
    <span style="color:${catMeta.color}">${catMeta.label}</span>
    <span style="color:#9ba3c7;font-size:11px"> → ${r.dst_ip}</span>
  </div>
  <div class="bkd-bar-wrap">
    <div class="bkd-bar" style="width:${pct}%;background:${catMeta.color}"></div>
  </div>
  <div class="bkd-val">${(r.blocked_packets || 0).toLocaleString()} pkts</div>
</div>`;
  });

  el.innerHTML = html;
}

// ── SocketIO ──────────────────────────────────────────────────────────────────

// Full rule list — fires on add/remove/clear
socket.on("acl_rules_updated", ruleList => {
  renderRules(ruleList);
});

// Per-rule counters — fires every second while traffic is flowing
socket.on("acl_stats", ruleList => {
  renderRules(ruleList);
});

// A flow was matched and a drop rule installed in OVS
socket.on("acl_flow_blocked", ev => {
  document.getElementById("lastBlockedAt").textContent = new Date().toLocaleTimeString();
  const catLabel = CAT_META[String(ev.category)]?.label ?? ev.category;
  logBlock(
    `BLOCKED  ${catLabel} flow → ${ev.dst_ip}  [${ev.rule_id}]`,
    "bl-block"
  );
});

// ── Log helper ────────────────────────────────────────────────────────────────
function logBlock(msg, cls = "") {
  const el  = document.getElementById("blockLog");
  const div = document.createElement("div");
  div.className   = cls;
  div.textContent = `[${new Date().toLocaleTimeString()}]  ${msg}`;
  el.prepend(div);
  while (el.children.length > 200) el.removeChild(el.lastChild);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (b >= 1_048_576) return (b / 1_048_576).toFixed(1) + " MB";
  if (b >= 1_024)     return (b / 1_024).toFixed(1) + " KB";
  return b + " B";
}

// ── Init: load existing rules ─────────────────────────────────────────────────
fetch("/api/acl/rules")
  .then(r => r.json())
  .then(renderRules)
  .catch(() => logBlock("Could not reach /api/acl/rules", "bl-remove"));

logBlock("Firewall monitor connected", "");
