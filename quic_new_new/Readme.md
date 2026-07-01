# QUIC Traffic Classification & QoS Engine

## How to Run

### 1. Create virtual environment and install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Start the Mininet topology

```bash
sudo python3 topology.py
```

This creates the virtual network with Open vSwitch. Keep this terminal open — you'll use the Mininet CLI in step 4.

### 3. Start the dashboard (new terminal)

```bash
source venv/bin/activate
cd dashboard
sudo python3 app.py
```

The dashboard will be available at `http://localhost:5000`.

### 4. Replay traffic (in the Mininet CLI from step 2)

```bash
h1 tcpreplay -i h1-eth0 /home/hpe/quic_new_new/capture2.pcap
```

This replays captured QUIC traffic through the network. The dashboard will start showing live packets, flow classification, and QoS enforcement in real time.
