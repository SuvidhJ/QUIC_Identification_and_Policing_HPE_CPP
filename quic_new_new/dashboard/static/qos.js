/**
 * qos.js  –  QoS Monitor
 *
 * Two separate real-time data streams from the server:
 *
 *  qos_stats      – fired every second (event-driven by QUIC packets)
 *                   contains real tc HTB counters + OF flow counters
 *                   → updates bandwidth bars, chart, OF table
 *
 *  qos_bw_alloc   – fired immediately when a new traffic class is
 *                   detected and bandwidth is rebalanced in OVS
 *                   → updates allocation display, config sliders
 *
 *  qos_rule_installed – fired the moment an OF enqueue rule is pushed
 *                   → updates flow→queue table, event log
 *
 * Zero dummy/fake data. If traffic = 0, bars = 0.
 */

const socket = io();

const QUEUES = {
  "0": { name: "Default", color: "#607d8b", weight: 1 },
  "1": { name: "Video",   color: "#f44336", weight: 4 },
  "2": { name: "Data",    color: "#ff9800", weight: 2 },
  "3": { name: "Web",     color: "#2196f3", weight: 1 },
};
// Display order — Video first (highest priority)
const Q_ORDER = ["1", "2", "3", "0"];

// ── State ─────────────────────────────────────────────────────────────────────
let currentAlloc = null;   // latest qos_bw_alloc payload
let currentStats = null;   // latest qos_stats payload
let flowLog      = [];     // qos_rule_installed events

// ── Chart ─────────────────────────────────────────────────────────────────────
const bwChart = new Chart(
  document.getElementById("bwChart").getContext("2d"),
  {
    type: "line",
    data: {
      labels:   [],
      datasets: Q_ORDER.map(q => ({
        label:           QUEUES[q].name,
        data:            [],
        borderColor:     QUEUES[q].color,
        backgroundColor: QUEUES[q].color + "18",
        fill:            true,
        tension:         0.3,
        pointRadius:     0,
        borderWidth:     2,
      })),
    },
    options: {
      animation:   false,
      responsive:  true,
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { color: "#c8d0e8", boxWidth: 14 } },
        tooltip: {
          callbacks: {
            label: c => ` ${c.dataset.label}: ${c.parsed.y.toFixed(1)} kbps`,
          },
        },
      },
      scales: {
        x: { ticks: { color: "#9ba3c7", maxTicksLimit: 10 }, grid: { color: "#1f2745" } },
        y: {
          min: 0,
          ticks: { color: "#9ba3c7", callback: v => v + " k" },
          grid:  { color: "#1f2745" },
          title: { display: true, text: "kbps", color: "#9ba3c7" },
        },
      },
    },
  }
);

// ── Build queue lanes (once) ──────────────────────────────────────────────────
function buildLanes() {
  const el = document.getElementById("queueLanes");
  el.innerHTML = "";
  Q_ORDER.forEach(q => {
    const m = QUEUES[q];
    el.innerHTML += `
<div class="queue-lane" id="lane-${q}">
  <div class="q-label">
    <span class="q-dot" style="background:${m.color}"></span>
    <div>
      <div>${m.name}</div>
      <div class="q-priority-label" id="q-alloc-${q}" style="color:${m.color}">—</div>
    </div>
  </div>
  <div class="q-bar-col">
    <div class="q-bar-wrap">
      <div class="q-bar-min"  id="bar-min-${q}"  style="background:${m.color}40; width:0%"></div>
      <div class="q-bar-live" id="bar-live-${q}" style="background:${m.color};   width:0%"></div>
    </div>
    <div class="q-bar-legend">
      <span id="bar-legend-${q}" style="color:#9ba3c7;font-size:11px">No traffic</span>
    </div>
  </div>
  <div class="q-stat"><div class="val" id="q-kbps-${q}">0.0</div><div class="lbl">kbps</div></div>
  <div class="q-stat"><div class="val" id="q-pps-${q}">0.0</div><div class="lbl">pkt/s</div></div>
  <div class="q-stat"><div class="val" id="q-util-${q}">0%</div><div class="lbl">util</div></div>
  <div class="q-stat"><div class="val" id="q-pkts-${q}">0</div><div class="lbl">total pkts</div></div>
</div>`;
  });
}

// ── Update allocation display (from qos_bw_alloc) ────────────────────────────
function applyAlloc(alloc) {
  currentAlloc = alloc;
  const total  = alloc.total_bps;
  const active = alloc.active || [];

  Q_ORDER.forEach(q => {
    const qd  = alloc.queues[q];
    const lane = document.getElementById(`lane-${q}`);

    if (active.includes(parseInt(q))) {
      lane.classList.remove("q-inactive");
    } else {
      lane.classList.add("q-inactive");
    }

    // Allocation label under queue name
    const minLabel = qd.min_bps > 0 ? `min ${fmt(qd.min_bps)}` : "no reservation";
    document.getElementById(`q-alloc-${q}`).textContent =
      qd.active ? `${minLabel} · max ${fmt(qd.max_bps)}` : "inactive";

    // Min-rate bar width (what we reserved in OVS)
    const minPct = total > 0 ? Math.min(100, (qd.min_bps / total) * 100) : 0;
    document.getElementById(`bar-min-${q}`).style.width = minPct + "%";
  });

  // Update config sliders if already built
  Q_ORDER.forEach(q => {
    const minEl = document.getElementById(`cfg-min-${q}`);
    const maxEl = document.getElementById(`cfg-max-${q}`);
    if (!minEl) return;
    const qd = alloc.queues[q];
    minEl.value = qd.min_bps;
    maxEl.value = qd.max_bps;
    updateCfgLabel(q);
  });

  // Rebuild allocation pie legend
  renderAllocPie(alloc);
}

// ── Update live traffic bars (from qos_stats) ─────────────────────────────────
function applyStats(stats) {
  currentStats = stats;
  const total  = stats.total_bps;

  // Status badge
  const badge = document.getElementById("qosStatus");
  badge.className   = stats.qos_ready ? "badge badge-ok"  : "badge badge-off";
  badge.textContent = stats.qos_ready ? "● QoS Active"    : "● QoS Inactive";

  // Top-bar stats
  let totalKbps = 0;
  Q_ORDER.forEach(q => { totalKbps += (stats.queues[q]?.kbps || 0); });
  document.getElementById("totalKbps").textContent = totalKbps.toFixed(1);

  const defKbps = stats.queues["0"]?.kbps || 0;
  const defPct  = totalKbps > 0
    ? ((defKbps / totalKbps) * 100).toFixed(0) + "%"
    : (stats.active_queues?.length <= 1 ? "100%" : "0%");
  document.getElementById("defaultPct").textContent = defPct;
  document.getElementById("lastUpdate").textContent = new Date().toLocaleTimeString();

  // Per-queue lane updates
  Q_ORDER.forEach(q => {
    const qd   = stats.queues[q];
    const live  = qd.bps;
    const livePct = total > 0 ? Math.min(100, (live / total) * 100) : 0;

    document.getElementById(`bar-live-${q}`).style.width = livePct + "%";

    const mn  = qd.min_bps;
    const mx  = qd.max_bps;
    const leg = live > 0
      ? `${qd.kbps} kbps  ·  min ${fmt(mn)} / max ${fmt(mx)}`
      : mn > 0
        ? `idle  ·  reserved ${fmt(mn)}`
        : "no traffic · no reservation";
    document.getElementById(`bar-legend-${q}`).textContent = leg;

    document.getElementById(`q-kbps-${q}`).textContent = qd.kbps.toFixed(1);
    document.getElementById(`q-pps-${q}`).textContent  = qd.pps.toFixed(1);
    document.getElementById(`q-util-${q}`).textContent = qd.utilization + "%";
    document.getElementById(`q-pkts-${q}`).textContent = qd.tx_pkts.toLocaleString();
  });

  // Chart
  const now = new Date().toLocaleTimeString();
  bwChart.data.labels.push(now);
  if (bwChart.data.labels.length > 60) bwChart.data.labels.shift();
  Q_ORDER.forEach((q, i) => {
    bwChart.data.datasets[i].data.push(stats.queues[q]?.kbps || 0);
    if (bwChart.data.datasets[i].data.length > 60)
      bwChart.data.datasets[i].data.shift();
  });
  bwChart.update("none");

  // OF flow table
  updateOFTable(stats.of_flows || []);
}

// ── Allocation pie ─────────────────────────────────────────────────────────────
function renderAllocPie(alloc) {
  const el = document.getElementById("allocPie");
  if (!el) return;

  const total  = alloc.total_bps;
  const active = alloc.active || [];
  let html     = "";
  let usedPct  = 0;

  Q_ORDER.filter(q => active.includes(parseInt(q))).forEach(q => {
    const qd  = alloc.queues[q];
    const pct = total > 0 ? Math.round((qd.min_bps / total) * 100) : 0;
    usedPct  += pct;
    html     += `
<div class="pie-row">
  <span class="q-dot" style="background:${QUEUES[q].color}"></span>
  <span>${QUEUES[q].name}</span>
  <div class="pie-bar-wrap">
    <div class="pie-bar" style="width:${pct}%;background:${QUEUES[q].color}"></div>
  </div>
  <span class="pie-pct">${fmt(qd.min_bps)}</span>
</div>`;
  });

  // Default (remainder)
  const defPct = Math.max(0, 100 - usedPct);
  const defMin = alloc.queues["0"]?.min_bps || 0;
  html += `
<div class="pie-row">
  <span class="q-dot" style="background:#607d8b"></span>
  <span>Default</span>
  <div class="pie-bar-wrap">
    <div class="pie-bar" style="width:${defPct}%;background:#607d8b"></div>
  </div>
  <span class="pie-pct">${defMin > 0 ? fmt(defMin) : "remainder"}</span>
</div>`;

  el.innerHTML = html;
}

// ── OF flow table ─────────────────────────────────────────────────────────────
function updateOFTable(ofFlows) {
  const tbody = document.getElementById("ofTable");
  if (!tbody) return;
  tbody.innerHTML = "";

  const classified = ofFlows.filter(f => f.priority === 100);
  document.getElementById("ofRules").textContent = classified.length;

  if (classified.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="color:#9ba3c7;text-align:center;padding:20px">
      No classified QUIC flows yet — waiting for first ML window prediction
    </td></tr>`;
    return;
  }

  classified.sort((a, b) => b.n_packets - a.n_packets);
  classified.forEach(f => {
    const color = f.color || "#888";
    const tr    = document.createElement("tr");
    tr.innerHTML = `
      <td>${f.nw_src || "—"}</td><td>${f.nw_dst || "—"}</td>
      <td>${f.tp_src || "—"}</td><td>${f.tp_dst || "—"}</td>
      <td><span class="q-badge" style="background:${color}22;color:${color}">
        Q${f.queue} ${f.queue_name}</span></td>
      <td>${f.n_packets.toLocaleString()}</td>
      <td>${fmtBytes(f.n_bytes)}</td>`;
    tbody.appendChild(tr);
  });
}

// ── Flow→queue table ──────────────────────────────────────────────────────────
function updateFlowTable() {
  const tbody = document.getElementById("flowQueueTable");
  if (!tbody) return;
  tbody.innerHTML = "";

  document.getElementById("classifiedFlows").textContent = flowLog.length;

  if (flowLog.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" style="color:#9ba3c7;text-align:center;padding:16px">
      Waiting for QUIC flow classifications…
    </td></tr>`;
    return;
  }

  const CLS = { 1: "Video", 2: "Data", 0: "Web" };
  flowLog.slice(0, 30).forEach(f => {
    const color = QUEUES[String(f.queue)]?.color || "#888";
    const tr    = document.createElement("tr");
    tr.innerHTML = `
      <td style="font-family:monospace;font-size:11px">${f.flow_key.substring(0, 30)}</td>
      <td>${CLS[f.traffic_class] ?? f.traffic_class}</td>
      <td><span class="q-badge" style="background:${color}22;color:${color}">
        Q${f.queue} ${f.queue_name}</span></td>
      <td style="font-size:11px;color:#9ba3c7">${f.ts}</td>`;
    tbody.appendChild(tr);
  });
}

// ── Config panel ──────────────────────────────────────────────────────────────
function buildConfigPanels(alloc) {
  const el = document.getElementById("configPanels");
  if (el.dataset.built) return;
  el.dataset.built = "1";

  Q_ORDER.forEach(q => {
    const m   = QUEUES[q];
    const qd  = alloc.queues[q];
    const tot = alloc.total_bps;
    el.innerHTML += `
<div class="config-card" style="border-top-color:${m.color}">
  <h3><span class="q-dot" style="background:${m.color}"></span> Q${q} · ${m.name}
    <span style="font-weight:normal;font-size:11px;color:#9ba3c7;margin-left:6px">
      weight ${m.weight}
    </span>
  </h3>
  <label>Min guaranteed rate</label>
  <input type="range" id="cfg-min-${q}" min="0" max="${tot}" step="100000"
    value="${qd.min_bps}" oninput="updateCfgLabel('${q}')">
  <div class="range-val" id="cfg-min-lbl-${q}">${fmt(qd.min_bps)}</div>
  <label>Max ceiling</label>
  <input type="range" id="cfg-max-${q}" min="100000" max="${tot}" step="100000"
    value="${qd.max_bps}" oninput="updateCfgLabel('${q}')">
  <div class="range-val" id="cfg-max-lbl-${q}">${fmt(qd.max_bps)}</div>
  <button onclick="applyQueueConfig('${q}')">Apply to OVS</button>
  <div class="applied-note" id="cfg-note-${q}"></div>
</div>`;
  });
}

function updateCfgLabel(q) {
  const minV = document.getElementById(`cfg-min-${q}`)?.value;
  const maxV = document.getElementById(`cfg-max-${q}`)?.value;
  if (minV !== undefined) document.getElementById(`cfg-min-lbl-${q}`).textContent = fmt(+minV);
  if (maxV !== undefined) document.getElementById(`cfg-max-lbl-${q}`).textContent = fmt(+maxV);
}

function applyQueueConfig(q) {
  const min_bps = +document.getElementById(`cfg-min-${q}`).value;
  const max_bps = +document.getElementById(`cfg-max-${q}`).value;
  fetch(`/api/qos/queue/${q}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ min_bps, max_bps }),
  })
  .then(r => r.json())
  .then(d => {
    const note = document.getElementById(`cfg-note-${q}`);
    note.textContent = d.ok ? "✓ Applied to OVS" : "✗ Failed";
    note.style.color = d.ok ? "#00ff88" : "#f44336";
    setTimeout(() => { note.textContent = ""; }, 3000);
    logEvent(d.ok
      ? `Q${q} (${QUEUES[q].name}) updated: min=${fmt(min_bps)} max=${fmt(max_bps)}`
      : `Q${q} update failed`, d.ok ? "ev-config" : "ev-error");
  });
}

// ── SocketIO ──────────────────────────────────────────────────────────────────

// Bandwidth allocation changed — new class became active, OVS was updated
socket.on("qos_bw_alloc", alloc => {
  applyAlloc(alloc);
  if (!document.getElementById("configPanels").dataset.built) {
    buildConfigPanels(alloc);
  }
  const activeNames = (alloc.active || [])
    .filter(q => q !== 0)
    .map(q => QUEUES[String(q)]?.name)
    .join(", ");
  if (activeNames) {
    logEvent(`Bandwidth reallocated — active classes: ${activeNames}`, "ev-config");
  }
});

// Real tc+OF stats — fires every second while QUIC traffic is flowing
socket.on("qos_stats", stats => {
  applyStats(stats);
  // If we haven't received an alloc event yet, seed from stats
  if (!currentAlloc && stats.queues) {
    applyAlloc({
      queues: Object.fromEntries(
        Object.entries(stats.queues).map(([q, qd]) => [q, {
          ...qd, active: qd.active ?? true, weight: QUEUES[q]?.weight ?? 1
        }])
      ),
      total_bps: stats.total_bps,
      active:    stats.active_queues || [0],
    });
    if (!document.getElementById("configPanels").dataset.built) {
      buildConfigPanels({
        queues: stats.queues,
        total_bps: stats.total_bps,
      });
    }
  }
});

// A new OF enqueue rule was pushed to OVS
socket.on("qos_rule_installed", ev => {
  flowLog.unshift({
    flow_key:      ev.flow_key,
    traffic_class: ev.class,
    queue:         ev.queue,
    queue_name:    ev.queue_name,
    ts:            new Date().toLocaleTimeString(),
  });
  updateFlowTable();
  logEvent(
    `${ev.new_class ? "★ NEW CLASS " : ""}Flow → Q${ev.queue} (${ev.queue_name})  ${ev.match}`,
    ev.new_class ? "ev-classify" : "ev-rule"
  );
});

// Config updated from another client
socket.on("qos_config_updated", status => {
  logEvent("Queue config updated", "ev-config");
  if (status?.stats) applyStats(status.stats);
});

// ── Event log ─────────────────────────────────────────────────────────────────
function logEvent(msg, cls = "ev-info") {
  const el  = document.getElementById("eventLog");
  const div = document.createElement("div");
  div.className   = cls;
  div.textContent = `[${new Date().toLocaleTimeString()}]  ${msg}`;
  el.prepend(div);
  while (el.children.length > 300) el.removeChild(el.lastChild);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmt(bps) {
  bps = +bps;
  if (bps >= 1_000_000) return (bps / 1_000_000).toFixed(1) + " Mbps";
  if (bps >= 1_000)     return (bps / 1_000).toFixed(0) + " kbps";
  return bps + " bps";
}
function fmtBytes(b) {
  if (b >= 1_048_576) return (b / 1_048_576).toFixed(1) + " MB";
  if (b >= 1_024)     return (b / 1_024).toFixed(1) + " KB";
  return b + " B";
}

// ── Init ──────────────────────────────────────────────────────────────────────
buildLanes();
logEvent("QoS monitor connected — waiting for QUIC traffic", "ev-info");

// Seed from REST API on page load
fetch("/api/qos/status")
  .then(r => r.json())
  .then(d => {
    if (d.error) { logEvent("OVS not available", "ev-error"); return; }
    if (d.stats) {
      applyStats(d.stats);
      applyAlloc({
        queues: Object.fromEntries(
          Object.entries(d.queues || {}).map(([q, qd]) => [q, {
            ...qd, weight: QUEUES[q]?.weight ?? 1,
          }])
        ),
        total_bps: d.total_bps,
        active:    d.active_queues || [0],
      });
      buildConfigPanels({
        queues: d.queues,
        total_bps: d.total_bps,
      });
    }
    // Restore flow log from already-installed flows
    Object.entries(d.installed_flows || {}).forEach(([fk, qn]) => {
      if (!flowLog.find(f => f.flow_key === fk)) {
        flowLog.push({
          flow_key:      fk,
          traffic_class: Object.entries({1:1,2:2,3:0}).find(([,v])=>v===qn)?.[0] ?? "?",
          queue:         qn,
          queue_name:    QUEUES[String(qn)]?.name ?? "?",
          ts:            "—",
        });
      }
    });
    updateFlowTable();
  })
  .catch(() => logEvent("Could not reach /api/qos/status", "ev-error"));
