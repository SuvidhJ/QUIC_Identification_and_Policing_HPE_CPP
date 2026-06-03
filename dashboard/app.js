const socket = io();


console.log("packetTable", document.getElementById("packetTable"));
console.log("flowCards", document.getElementById("flowCards"));
console.log("windowTable", document.getElementById("windowTable"));
console.log("selectedWindow", document.getElementById("selectedWindow"));
console.log("featureTable", document.getElementById("featureTable"));

const packetTable =
    document.getElementById("packetTable");

const flowCards =
    document.getElementById("flowCards");

const windowTable =
    document.getElementById("windowTable");

const selectedWindow =
    document.getElementById("selectedWindow");

const featureTable =
    document.getElementById("featureTable");

let packetCount = 0;
let flowCount = 0;
let windowCount = 0;

let activeFlows = [];
let windows = [];

socket.on("packet", (pkt) => {

    packetCount++;

    document.getElementById(
        "packetCount"
    ).innerText = packetCount;

    const row =
        packetTable.insertRow(0);

    row.insertCell().innerText =
        new Date(
            pkt.ts * 1000
        ).toLocaleTimeString();

    row.insertCell().innerText =
        pkt.src;

    row.insertCell().innerText =
        pkt.dst;

    row.insertCell().innerText =
        pkt.len;

    row.insertCell().innerText =
        pkt.flow_key.substring(0,20);

    while(packetTable.rows.length > 10){
        packetTable.deleteRow(10);
    }
});


socket.on("flow", (flow) => {

    flowCount++;

    document.getElementById(
        "flowCount"
    ).innerText = flowCount;

    activeFlows.unshift(flow);

    if(activeFlows.length > 20){
        activeFlows.pop();
    }

    renderFlows();
});


socket.on("window", (windowData) => {

    windowCount++;

    document.getElementById(
        "windowCount"
    ).innerText = windowCount;

    windows.unshift(windowData);

    if(windows.length > 50){
        windows.pop();
    }

    renderWindows();

    selectWindow(windowData);
});


function renderFlows(){

    flowCards.innerHTML = "";

    activeFlows.forEach(flow => {

        flowCards.innerHTML += `
            <div class="flow-card">

                <h3>
                    Flow #${flow.flow_id}
                </h3>

                <p>
                    ${flow.flow_key}
                </p>

            </div>
        `;
    });
}


function renderWindows(){

    windowTable.innerHTML = "";

    windows.forEach(windowData => {

        const row =
            windowTable.insertRow();

        row.style.cursor =
            "pointer";

        row.insertCell().innerText =
            windowData.window_id;

        row.insertCell().innerText =
            windowData.flow_id;

        row.insertCell().innerText =
            windowData.packet_count;

        row.onclick = () => {
            selectWindow(windowData);
        };
    });
}


function selectWindow(windowData){

    selectedWindow.innerHTML = `

        <h3>
            Window #${windowData.window_id}
        </h3>

        <p>
            Flow #${windowData.flow_id}
        </p>

        <p>
            ${windowData.flow_key}
        </p>

    `;

    featureTable.innerHTML = "";

    Object.entries(
        windowData.features
    ).forEach(([k,v]) => {

        featureTable.innerHTML += `

            <tr>
                <td>${k}</td>
                <td>${v}</td>
            </tr>

        `;
    });
}
