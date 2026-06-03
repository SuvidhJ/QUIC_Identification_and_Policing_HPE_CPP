const socket = io();
const predictionTable =
    document.getElementById("predictionTable");

let predictions = [];
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

    activeFlows.push(flow);



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

socket.on("flow_update", (update) => {

    const idx = activeFlows.findIndex(
        f => f.flow_id === update.flow_id
    );

    if(idx >= 0){

        activeFlows[idx].current_class =
            update.current_class;

        activeFlows[idx].confidence =
            update.confidence;

        renderFlows();
    }

});

socket.on("prediction", (pred) => {

    predictions.unshift(pred);

    if(predictions.length > 100){
        predictions.pop();
    }

    renderPredictions();
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
            Class:
            <b>${flow.current_class}</b>
        </p>

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
function renderPredictions(){

    predictionTable.innerHTML = "";

    predictions.forEach(pred => {

        const row =
            predictionTable.insertRow();

        row.insertCell().innerText =
            pred.window_id;

        row.insertCell().innerText =
            pred.flow_id;

        row.insertCell().innerText =
            pred.predicted_class;

        row.insertCell().innerText =
            pred.confidence;
    });

}
