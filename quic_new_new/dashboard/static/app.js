const socket = io();

const predictionTable = document.getElementById("predictionTable");
const packetTable = document.getElementById("packetTable");
const flowCards = document.getElementById("flowCards");
const windowTable = document.getElementById("windowTable");
const selectedWindow = document.getElementById("selectedWindow");
const featureContainer = document.getElementById("featureContainer");

let predictions = [];
let packetCount = 0;
let flowCount = 0;
let windowCount = 0;
let activeFlows = [];
let windows = [];
let selectedWindowId = null;

// Filter state
let windowClassFilter = "all";
let predClassFilter = "all";

const CLASS_LABELS = {
    0: { label: "Web",     css: "web" },
    1: { label: "Video",   css: "video" },
    2: { label: "Data",    css: "data" },
    "DEFAULT": { label: "Default", css: "default" },
};

function classInfo(cls) {
    return CLASS_LABELS[cls] || CLASS_LABELS["DEFAULT"];
}

function classBadge(cls) {
    const info = classInfo(cls);
    return `<span class="class-badge ${info.css}">${info.label}</span>`;
}

function confidenceHtml(conf) {
    if (conf == null || conf === 0) return '<span style="color:var(--muted);">—</span>';
    const pct = Math.round(conf * 100);
    return `<span class="confidence-bar">
        <span class="bar"><span class="bar-fill" style="width:${pct}%"></span></span>
        ${pct}%
    </span>`;
}

const FEATURE_LABELS = {
    packet_count: "Packet Count",
    total_bytes: "Total Bytes",
    duration_s: "Duration (s)",
    bytes_per_sec: "Throughput (B/s)",
    mean_payload_len: "Mean Payload",
    std_payload_len: "Std Payload",
    min_payload_len: "Min Payload",
    max_payload_len: "Max Payload",
    mean_iat: "Mean IAT (s)",
    std_iat: "Std IAT (s)",
    min_iat: "Min IAT (s)",
    max_iat: "Max IAT (s)",
    burst_count: "Burst Count",
    upload_ratio: "Upload Ratio",
};

// ── Init state (restore after refresh) ──────────────────────

socket.on("init_state", (state) => {
    packetCount = state.packet_counter || 0;
    flowCount = state.flow_counter || 0;
    windowCount = state.window_counter || 0;

    updateCounters();

    packetTable.innerHTML = "";
    (state.recent_packets || []).forEach(pkt => addPacketRow(pkt));

    activeFlows = (state.flows || []).reverse();
    renderFlows();

    windows = (state.completed_windows || []).reverse();
    renderWindows();

    predictions = (state.predictions || []).reverse();
    renderPredictions();

    if (windows.length > 0) {
        selectWindow(windows[0]);
    }
});

// ── Live events ─────────────────────────────────────────────

socket.on("packet", (pkt) => {
    packetCount++;
    updateCounters();
    addPacketRow(pkt);
    filterPackets();
    while (packetTable.rows.length > 50) {
        packetTable.deleteRow(packetTable.rows.length - 1);
    }
});

socket.on("flow", (flow) => {
    flowCount++;
    activeFlows.unshift(flow);
    updateCounters();
    renderFlows();
});

socket.on("window", (windowData) => {
    windowCount++;
    windows.unshift(windowData);
    updateCounters();
    renderWindows();
    selectWindow(windowData);
});

socket.on("flow_update", (update) => {
    const idx = activeFlows.findIndex(f => f.flow_id === update.flow_id);
    if (idx >= 0) {
        activeFlows[idx].current_class = update.current_class;
        activeFlows[idx].confidence = update.confidence;
        if (update.sni) activeFlows[idx].sni = update.sni;
        renderFlows();
        updateCategoryCounts();
    }
});

socket.on("prediction", (pred) => {
    predictions.unshift(pred);
    renderPredictions();
});

// ── Helpers ─────────────────────────────────────────────────

function updateCounters() {
    document.getElementById("packetCount").innerText = packetCount.toLocaleString();
    document.getElementById("flowCount").innerText = flowCount.toLocaleString();
    document.getElementById("windowCount").innerText = windowCount.toLocaleString();
    document.getElementById("flowBadge").innerText = `${activeFlows.length} flows`;
    document.getElementById("predBadge").innerText = `${predictions.length} predictions`;
    updateCategoryCounts();
}

function addPacketRow(pkt) {
    const row = packetTable.insertRow(0);
    row.insertCell().innerText = new Date(pkt.ts * 1000).toLocaleTimeString();
    row.insertCell().innerText = pkt.src;
    row.insertCell().innerText = pkt.dst;
    row.insertCell().innerText = pkt.len;

    const keyCell = row.insertCell();
    keyCell.style.fontFamily = "'SF Mono','Fira Code',monospace";
    keyCell.style.fontSize = "12px";
    keyCell.innerText = pkt.flow_key.substring(0, 24);
}

// ── Filter: Live Packets ────────────────────────────────────

function filterPackets() {
    const q = (document.getElementById("filterPacketIp").value || "").toLowerCase().trim();
    const rows = packetTable.rows;
    let shown = 0;
    for (let i = 0; i < rows.length; i++) {
        const src = rows[i].cells[1]?.innerText?.toLowerCase() || "";
        const dst = rows[i].cells[2]?.innerText?.toLowerCase() || "";
        const match = !q || src.includes(q) || dst.includes(q);
        rows[i].style.display = match ? "" : "none";
        if (match) shown++;
    }
    document.getElementById("packetBadge").innerText = q ? `${shown} matching` : `last ${rows.length}`;
}

// ── Render flows (with search filter) ───────────────────────

function renderFlows() {
    const q = (document.getElementById("filterFlowSearch").value || "").toLowerCase().trim();

    if (activeFlows.length === 0) {
        flowCards.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">&#8674;</div>
                <div class="empty-text">Waiting for QUIC flows...</div>
            </div>`;
        document.getElementById("flowBadge").innerText = "0 flows";
        return;
    }

    const filtered = activeFlows.filter(flow => {
        if (!q) return true;
        const sni = (flow.sni || "").toLowerCase();
        const key = (flow.flow_key || "").toLowerCase();
        const fid = String(flow.flow_id);
        return sni.includes(q) || key.includes(q) || fid.includes(q);
    });

    document.getElementById("flowBadge").innerText = q
        ? `${filtered.length} / ${activeFlows.length} flows`
        : `${activeFlows.length} flows`;

    if (filtered.length === 0) {
        flowCards.innerHTML = `
            <div class="empty-state">
                <div class="empty-text">No flows match "${q}"</div>
            </div>`;
        return;
    }

    flowCards.innerHTML = "";
    filtered.forEach(flow => {
        const sniHtml = flow.sni
            ? `<span class="flow-sni">${flow.sni}</span>`
            : `<span class="flow-sni unknown">hostname unknown</span>`;

        flowCards.innerHTML += `
            <div class="flow-card">
                <div class="flow-card-header">
                    <span class="flow-id">Flow #${flow.flow_id}</span>
                    ${classBadge(flow.current_class)}
                </div>
                <div class="flow-card-meta">
                    ${sniHtml}
                    <span class="flow-key">${flow.flow_key}</span>
                </div>
            </div>`;
    });
}

// ── Filter: Windows class pills ─────────────────────────────

function setWindowClassFilter(cls, btn) {
    windowClassFilter = cls;
    document.querySelectorAll("#windowClassFilter .fpill").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    renderWindows();
}

// ── Render windows table (with class + search filter) ───────

function renderWindows() {
    windowTable.innerHTML = "";
    if (windows.length === 0) return;

    const q = (document.getElementById("filterWindowSearch").value || "").toLowerCase().trim();

    const filtered = windows.filter(w => {
        if (windowClassFilter !== "all") {
            const wCls = w.predicted_class != null ? w.predicted_class : "DEFAULT";
            if (wCls !== windowClassFilter) return false;
        }
        if (q) {
            const sni = (w.sni || "").toLowerCase();
            const fid = String(w.flow_id);
            if (!sni.includes(q) && !fid.includes(q)) return false;
        }
        return true;
    });

    if (filtered.length === 0) {
        const row = windowTable.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 6;
        cell.style.textAlign = "center";
        cell.style.padding = "24px";
        cell.style.color = "var(--muted)";
        cell.innerText = "No windows match current filters";
        return;
    }

    filtered.forEach(w => {
        const row = windowTable.insertRow();
        row.className = "clickable-row" + (selectedWindowId === `${w.flow_id}-${w.window_id}` ? " active" : "");
        row.dataset.wid = `${w.flow_id}-${w.window_id}`;

        row.insertCell().innerText = w.window_id;
        row.insertCell().innerText = `#${w.flow_id}`;

        const sniCell = row.insertCell();
        sniCell.innerText = w.sni || "—";
        if (!w.sni) sniCell.style.color = "var(--muted)";

        row.insertCell().innerText = w.packet_count || (w.features ? w.features.packet_count : "—");

        const classCell = row.insertCell();
        classCell.innerHTML = w.predicted_class != null ? classBadge(w.predicted_class) : classBadge("DEFAULT");

        const confCell = row.insertCell();
        confCell.innerHTML = confidenceHtml(w.confidence);

        row.onclick = () => selectWindow(w);
    });
}

// ── Select window ───────────────────────────────────────────

function selectWindow(w) {
    selectedWindowId = `${w.flow_id}-${w.window_id}`;

    document.querySelectorAll("#windowTable .clickable-row").forEach(r => {
        r.classList.toggle("active", r.dataset.wid === selectedWindowId);
    });

    selectedWindow.innerHTML = `
        <div class="window-detail">
            <div class="detail-item">
                <span class="detail-label">Window</span>
                <span class="detail-value">#${w.window_id}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Flow</span>
                <span class="detail-value">#${w.flow_id}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Predicted Class</span>
                <span class="detail-value">${classBadge(w.predicted_class != null ? w.predicted_class : "DEFAULT")}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Confidence</span>
                <span class="detail-value">${confidenceHtml(w.confidence)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Hostname (SNI)</span>
                <span class="detail-value">${w.sni || '<span style="color:var(--muted)">unknown</span>'}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Flow Key</span>
                <span class="detail-value mono">${w.flow_key || "—"}</span>
            </div>
        </div>`;

    if (w.features) {
        let cells = "";
        Object.entries(w.features).forEach(([k, v]) => {
            const label = FEATURE_LABELS[k] || k;
            const display = typeof v === "number" ? (Number.isInteger(v) ? v.toLocaleString() : v.toFixed(4)) : v;
            cells += `
                <div class="feature-cell">
                    <span class="feat-name">${label}</span>
                    <span class="feat-value">${display}</span>
                </div>`;
        });
        featureContainer.innerHTML = `<div class="feature-grid">${cells}</div>`;
    } else {
        featureContainer.innerHTML = `
            <div class="empty-state">
                <div class="empty-text">No features available for this window</div>
            </div>`;
    }
}

// ── Filter: Prediction class pills ──────────────────────────

function setPredClassFilter(cls, btn) {
    predClassFilter = cls;
    document.querySelectorAll("#predClassFilter .fpill").forEach(b => b.classList.remove("active"));
    btn.classList.add("active");
    renderPredictions();
}

// ── Render predictions (with class + search + confidence) ───

function renderPredictions() {
    predictionTable.innerHTML = "";

    const q = (document.getElementById("filterPredSearch").value || "").toLowerCase().trim();
    const slider = document.getElementById("filterPredConf");
    const minConf = parseInt(slider.value, 10) / 100;
    document.getElementById("filterPredConfVal").innerText = `${slider.value}%`;

    const filtered = predictions.filter(pred => {
        if (predClassFilter !== "all") {
            if (pred.predicted_class !== predClassFilter) return false;
        }
        if (minConf > 0 && (pred.confidence || 0) < minConf) return false;
        if (q) {
            const sni = (pred.sni || "").toLowerCase();
            const fid = String(pred.flow_id);
            if (!sni.includes(q) && !fid.includes(q)) return false;
        }
        return true;
    });

    document.getElementById("predBadge").innerText = (q || predClassFilter !== "all" || minConf > 0)
        ? `${filtered.length} / ${predictions.length} predictions`
        : `${predictions.length} predictions`;

    if (filtered.length === 0) {
        const row = predictionTable.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.style.textAlign = "center";
        cell.style.padding = "24px";
        cell.style.color = "var(--muted)";
        cell.innerText = "No predictions match current filters";
        return;
    }

    filtered.forEach(pred => {
        const row = predictionTable.insertRow();

        row.insertCell().innerText = pred.window_id;
        row.insertCell().innerText = `#${pred.flow_id}`;

        const classCell = row.insertCell();
        classCell.innerHTML = classBadge(pred.predicted_class);

        const confCell = row.insertCell();
        confCell.innerHTML = confidenceHtml(pred.confidence);

        const sniCell = row.insertCell();
        sniCell.innerText = pred.sni || "—";
        if (!pred.sni) sniCell.style.color = "var(--muted)";
    });
}

// ── Category counts ─────────────────────────────────────────

function updateCategoryCounts() {
    const counts = { 0: 0, 1: 0, 2: 0, "DEFAULT": 0 };
    activeFlows.forEach(f => {
        const cls = f.current_class;
        if (cls === 0 || cls === 1 || cls === 2) {
            counts[cls]++;
        } else {
            counts["DEFAULT"]++;
        }
    });

    const el0 = document.getElementById("catCount0");
    const el1 = document.getElementById("catCount1");
    const el2 = document.getElementById("catCount2");
    const elD = document.getElementById("catCountDEFAULT");
    const elA = document.getElementById("catCountAll");

    if (el0) el0.innerText = counts[0];
    if (el1) el1.innerText = counts[1];
    if (el2) el2.innerText = counts[2];
    if (elD) elD.innerText = counts["DEFAULT"];
    if (elA) elA.innerText = activeFlows.length;
}

// ── Category modal ──────────────────────────────────────────

function openCategoryModal(category) {
    const modal = document.getElementById("categoryModal");
    const title = document.getElementById("modalTitle");
    const tbody = document.getElementById("modalFlowTable");

    let filtered;
    if (category === "ALL") {
        filtered = activeFlows;
        title.innerHTML = `All Flows <span style="color:var(--muted-fg);font-size:13px;font-weight:400">(${filtered.length})</span>`;
    } else if (category === "DEFAULT") {
        filtered = activeFlows.filter(f =>
            f.current_class !== 0 && f.current_class !== 1 && f.current_class !== 2
        );
        title.innerHTML = `Default / Unclassified Flows <span style="color:var(--muted-fg);font-size:13px;font-weight:400">(${filtered.length})</span>`;
    } else {
        filtered = activeFlows.filter(f => f.current_class === category);
        title.innerHTML = `${classBadge(category)} Flows <span style="color:var(--muted-fg);font-size:13px;font-weight:400">(${filtered.length})</span>`;
    }

    tbody.innerHTML = "";

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" style="text-align:center;padding:32px;color:var(--muted)">
            No flows in this category
        </td></tr>`;
    } else {
        filtered.forEach(f => {
            const row = tbody.insertRow();

            row.insertCell().innerText = `#${f.flow_id}`;

            const classCell = row.insertCell();
            classCell.innerHTML = classBadge(f.current_class);

            const sniCell = row.insertCell();
            sniCell.innerText = f.sni || "—";
            if (f.sni) {
                sniCell.style.color = "var(--green)";
            } else {
                sniCell.style.color = "var(--muted)";
            }

            const keyCell = row.insertCell();
            keyCell.className = "flow-key-cell";
            keyCell.innerText = f.flow_key;
        });
    }

    modal.classList.add("open");
}

function closeCategoryModal(event) {
    const modal = document.getElementById("categoryModal");
    if (!event || event.target === modal) {
        modal.classList.remove("open");
    }
}
