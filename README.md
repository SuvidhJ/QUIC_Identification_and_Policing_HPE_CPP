# QUIC Classification and Policing

An end-to-end network management system that performs **real-time QUIC packet classification** using Machine Learning, dynamically adjusts **Quality of Service (QoS)** bandwidth allocations using Open vSwitch (OVS) Hierarchy Token Bucket (HTB), and enforces **Access Control Lists (ACL)** via bidirectional OpenFlow drop rules.

---

## 🚀 Key Features

* **Real-time Packet Capture & Parsing**: Mirrors traffic to a dedicated classification host (`hc`) via OVS port mirroring, parsing UDP/QUIC streams in real-time.
* **ML-based Traffic Classification**: Evaluates statistical flow features across 5-second sliding windows using a Random Forest model (`model.pkl`) to identify categories: **Video**, **Data**, or **Web**.
* **OVS HTB QoS Control**: Automatically maps classified flows to dedicated kernel HTB queues with dynamic weight-based bandwidth shares on the egress switch port.
* **Bidirectional ACL Firewall**: Enforces OpenFlow drop rules (priority 200) based on Destination/Source IP, Port, or SNI (Server Name Indication) patterns, dropping blocked connections directly in the kernel datapath.
* **Interactive Dashboard**: Modern dark-themed dashboard presenting active flows, live packet logs, completed classification windows, QoS queue lane throughputs, and real-time blocked traffic stats.

---

## 📐 System Architecture

```text
       Replay Host (h1)                       Destination Host (h2)
          10.0.0.1                                  10.0.0.2
             │                                         ▲
             │ (10 Mbps QUIC stream)                   │ [Shaped Egress Queue]
             ▼                                         │
        ┌─────────┐      s1-eth2 (HTB Egress Port)    ┌┴────────┐
        │ s1-eth1 ├──────────────────────────────────►│ s1-eth2 │  (Switch s1)
        └─────────┘                                   └─────────┘
             │
             │ [OVS Port Mirroring]
             ▼
        ┌─────────┐
        │ s1-eth3 │  Classifier Host (hc - 10.0.0.99)
        └────┬────┘
             │ (Raw Socket capture on s1-eth3)
             ▼
      [ extraction.py ] ◄─────► [ Side-channel tshark SNI sniffer ]
             │ (Predicts: Web/Video/Data)
             ▼
     ┌───────┴───────┐
     ▼               ▼
 [ ovs_qos ]     [ ovs_acl ]
 (HTB shaping)   (OpenFlow dropping)
```

---

## 📂 Project Structure

```text
├── topology.py             # Mininet network configuration and virtual topology creator
├── requirements.txt        # Python library dependencies
├── README.md               # Getting started guide
└── dashboard/              # Web application backend and UI folder
    ├── app.py              # Flask server and SocketIO event broker
    ├── extraction.py       # Core packet processing loop, ML feature extractor, & SNI sniffer
    ├── packet_classifier.py# Custom network packet parser & QUIC/non-QUIC classifier
    ├── ovs_qos.py          # OVS HTB Queue manager & live traffic rate stats aggregator
    ├── ovs_acl.py          # OpenFlow dropping rules and ACL manager (bidirectional)
    ├── model.pkl           # Pre-trained Random Forest flow classifier model
    ├── templates/          # HTML pages
    │   ├── index.html      # Main flows dashboard
    │   ├── qos.html        # QoS monitor & live queue throughput chart
    │   └── firewall.html   # Firewall configuration and blocked stats view
    └── static/             # Frontend Javascript and CSS styles
        ├── app.js          # Main dashboard interactive logic
        ├── qos.js          # Live charts and QoS config logic
        ├── firewall.js     # Firewall dashboard event handling
        └── style.css       # Core layout stylesheet
```

---

## 🛠️ Installation & Dependencies

To set up the workspace on your machine or inside the Mininet VM, run:

1. **Clone & Enter Project Directory**:
   ```bash
   cd /home/hpe/quic_new_new
   ```

2. **Initialize Virtual Environment & Install Requirements**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Verify Dependencies**:
   * Python 3.8+
   * Open vSwitch (`ovs-vsctl`, `ovs-ofctl` utilities)
   * Linux TC (`tc` kernel utility)
   * Tshark (`tshark` command-line packet analyzer)

---

## ⚡ Running the Project

### Step 1: Start the Mininet Network
Launch the network emulator. This script constructs the switches, links, configures initial QoS ports, and mirrors packet captures:
```bash
sudo python3 topology.py
```
*Keep this window open.* You will use the `mininet>` command prompt to send traffic later.

### Step 2: Start the Dashboard Web App
In a new terminal window, activate the environment and start the Flask controller backend:
```bash
cd /home/hpe/quic_new_new/dashboard
source ../venv/bin/activate
sudo python3 app.py
```
Open your browser and navigate to `http://localhost:5000` (or `http://<VM-IP>:5000`).

### Step 3: Run Traffic Replay
Inside the Mininet CLI prompt (from **Step 1**), replay a PCAP capture at your chosen rate (e.g. 5 Mbps):
```bash
mininet> h1 tcpreplay -i h1-eth0 --pps=500 /home/hpe/quic_new_new/capture2.pcap
```

---

## 📶 QoS Lane Configurations

Classified flows are steered to distinct queues on port `s1-eth2` by priority-100 OpenFlow rules:

| Queue | Traffic Class | Description | Bandwidth Limit |
|:---:|---|---|---|
| **Queue 0** | **Default** | Unclassified / Handshake traffic | 20% – 100% |
| **Queue 1** | **Video** | Highest priority (ML Class 1) | 40% – 80% |
| **Queue 2** | **Data** | Medium priority (ML Class 2) | 20% – 50% |
| **Queue 3** | **Web** | Standard priority (ML Class 0) | 10% – 30% |

Bandwidth limits can be adjusted dynamically in the **QoS Monitor** tab, which automatically updates the switch's HTB parameters at runtime.

---

## 🛡️ Firewall & ACL Management

OpenFlow Drop Rules (priority 200) override the QoS rules to drop packets instantly in the kernel. The firewall supports three modes:

1. **Broad IP blocking**: Immediately drops any packet matching the specified IP (installed instantly as a wildcard match).
2. **Category-based blocking**: Blocks flows to/from the IP only when they are classified into a specific traffic category (e.g., block `10.0.0.2` Web traffic).
3. **SNI-based blocking (Dynamic)**: Drops flows targeting a specific domain name (e.g., `youtube.com`). The moment the SNI is extracted, a flow-specific 5-tuple drop rule is written to the switch.

### Bidirectional Matching
All ACL matches are **fully bidirectional**. Storing a block rule for a client host or server port will drop both outgoing requests and incoming replies, preventing the connection from initializing.
