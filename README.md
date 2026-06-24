# FusionIDS: Decentralized Blockchain-Based Intrusion Detection System

A production-ready, fully decentralized Intrusion Detection System (IDS) that combines high-throughput native packet capture, dual-layer machine learning, and Byzantine fault-tolerant blockchain consensus to eliminate single points of failure and prevent log tampering.

##  Aim

To design and implement a fully decentralized, real-time Intrusion Detection System that addresses the critical vulnerabilities of traditional centralized IDS architectures through:

- **Native packet capture** with zero packet loss via C++17 + libpcap
- **Dual-layer machine learning** (supervised ensemble + unsupervised anomaly detection) for complete threat coverage
- **Cryptographically secured distributed ledger** with PBFT consensus for tamper-proof audit trails
- **Production-ready Docker orchestration** with multi-node cluster support

---

## 📋 Table of Contents

1. [System Architecture](#system-architecture)
2. [Introduction](#introduction)
3. [Literature Survey & Technologies](#literature-survey--technologies)
4. [Methodology](#methodology)
5. [System Performance](#system-performance)
6. [Deployment](#deployment)
7. [Results](#results)
8. [Conclusions & Future Scope](#conclusions--future-scope)
9. [References](#references)

---

##  System Architecture

### Three-Tier Overview

FusionIDS addresses both weaknesses of centralized IDS through a three-tier architecture:

```mermaid
graph TB
    subgraph Tier1["Tier 1: Native C++17 Flow Capturer"]
        A["libpcap + BPF Filter"]
        B["PacketParser"]
        C["FlowTable<br/>5-Tuple Hashing"]
        D["StatisticalEngine<br/>68 Features"]
        E["FeatureSender<br/>HTTP POST"]
    end

    subgraph Tier2["Tier 2: Hybrid ML Inference"]
        F["Supervised Ensemble<br/>LightGBM | XGBoost | RF"]
        G["Unsupervised Anomaly<br/>Isolation Forest"]
        H["Fusion Engine<br/>Decision Matrix"]
    end

    subgraph Tier3["Tier 3: PBFT Blockchain Consensus"]
        I["Alert Transaction<br/>ECDSA Signing"]
        J["PRE-PREPARE<br/>Block Broadcast"]
        K["PREPARE<br/>Local Validation"]
        L["COMMIT<br/>Consensus Vote"]
        M["Block Commitment<br/>SQLite Persistence"]
    end

    A --> B --> C --> D --> E
    E --> F
    E --> G
    F --> H
    G --> H
    H --> I
    I --> J
    J --> K
    K --> L
    L --> M
```

### Data Flow Pipeline

```mermaid
sequenceDiagram
    participant NIC as Network<br/>Interface
    participant Cap as C++ Capturer<br/>Traffic Capture
    participant ML as FastAPI<br/>ML Inference
    participant Node as Blockchain<br/>Node PBFT
    participant Peer as Peer<br/>Nodes
    participant DB as SQLite<br/>Database

    NIC->>Cap: Raw Packets
    Cap->>Cap: Parse + Extract<br/>68 Features
    Cap->>ML: POST Flow Features<br/>JSON
    ML->>ML: Supervised +<br/>Unsupervised Detection
    ML->>Node: Alert with Metadata
    Node->>Peer: PRE-PREPARE<br/>Encrypted Block
    Peer->>Peer: /validate Endpoint<br/>Local Re-validation
    Peer->>Node: PREPARE Vote
    Peer->>Peer: Collect 2f+1 Votes
    Peer->>Node: COMMIT Message
    Node->>DB: add_block()<br/>Persist to Chain
    Node->>DB: save_block()<br/>SQLite WAL
```

### ML Fusion Engine Decision Matrix

```mermaid
graph LR
    A["Signature<br/>Prediction"] --> B{"Fusion<br/>Decision"}
    C["Anomaly<br/>Score"] --> B
    
    B -->|Case 1| D["🔴 CRITICAL<br/>Attack Detected<br/>+ Strong Anomaly"]
    B -->|Case 2| E["🟠 HIGH<br/>Attack Detected<br/>+ Normal"]
    B -->|Case 3| F["🟠 HIGH<br/>Benign Label<br/>+ Strong Anomaly<br/>→ Zero-Day?"]
    B -->|Case 4| G["🟡 LOW<br/>Benign/Low Conf<br/>+ Anomaly"]
    B -->|Case 5| H["🟡 MEDIUM<br/>Attack/Low Conf<br/>+ Anomaly"]
    B -->|Case 6| I["✅ NORMAL<br/>Benign + Normal"]
```

### PBFT Consensus Sequence

```mermaid
sequenceDiagram
    participant Prop as Proposing<br/>Node
    participant N1 as Node 1
    participant N2 as Node 2
    participant N3 as Node 3

    Prop->>Prop: submit_alert()<br/>Create Block<br/>ECDSA Sign
    Prop->>N1: Broadcast PRE-PREPARE<br/>AES-256-GCM Encrypted
    Prop->>N2: Broadcast PRE-PREPARE
    Prop->>N3: Broadcast PRE-PREPARE

    par Parallel Validation
        N1->>N1: Verify ECDSA Sig<br/>Decrypt Message<br/>Call /validate
        N2->>N2: Verify ECDSA Sig<br/>Decrypt Message<br/>Call /validate
        N3->>N3: Verify ECDSA Sig<br/>Decrypt Message<br/>Call /validate
    end

    N1->>Prop: PREPARE Vote
    N2->>Prop: PREPARE Vote
    N3->>Prop: PREPARE Vote
    
    Prop->>Prop: Collect 2f+1 PREPARE<br/>quorum = 3/5

    Prop->>N1: COMMIT Message
    Prop->>N2: COMMIT Message
    Prop->>N3: COMMIT Message

    par Commit Broadcast
        N1->>N1: Record COMMIT
        N2->>N2: Record COMMIT
        N3->>N3: Record COMMIT
    end

    N1->>N1: Collect 2f+1 COMITs<br/>ON_BLOCK_COMMITTED()
    N2->>N2: Collect 2f+1 COMITs<br/>ON_BLOCK_COMMITTED()
    N3->>N3: Collect 2f+1 COMITs<br/>ON_BLOCK_COMMITTED()

    Note over Prop,N3: Block immutably committed<br/>to all 5 nodes
```

### Docker Compose Deployment

```mermaid
graph TB
    subgraph docker["Docker Compose Cluster"]
        subgraph node0["Node 0<br/>Container"]
            c0["C++ Capturer"]
            m0["FastAPI<br/>ML Server"]
            b0["Flask<br/>Blockchain"]
            t0["Target<br/>Echo Server"]
            s0["supervisord"]
        end

        subgraph node1["Node 1<br/>Container"]
            c1["C++ Capturer"]
            m1["FastAPI<br/>ML Server"]
            b1["Flask<br/>Blockchain"]
            t1["Target<br/>Echo Server"]
            s1["supervisord"]
        end

        subgraph nodeN["Node N<br/>Container"]
            cN["C++ Capturer"]
            mN["FastAPI<br/>ML Server"]
            bN["Flask<br/>Blockchain"]
            tN["Target<br/>Echo Server"]
            sN["supervisord"]
        end

        db0[["SQLite DB<br/>node0"]]
        db1[["SQLite DB<br/>node1"]]
        dbN[["SQLite DB<br/>nodeN"]]

        bridge["ids-net<br/>Bridge Network"]
    end

    s0 -.->|manages| c0
    s0 -.->|manages| m0
    s0 -.->|manages| b0
    s0 -.->|manages| t0

    s1 -.->|manages| c1
    s1 -.->|manages| m1
    s1 -.->|manages| b1
    s1 -.->|manages| t1

    sN -.->|manages| cN
    sN -.->|manages| mN
    sN -.->|manages| bN
    sN -.->|manages| tN

    b0 --> db0
    b1 --> db1
    bN --> dbN

    b0 -.->|PBFT Consensus| bridge
    b1 -.->|PBFT Consensus| bridge
    bN -.->|PBFT Consensus| bridge
```

---

##  Introduction

### Problem Statement

Modern network infrastructures face increasingly sophisticated cyber threats. Traditional centralized IDS suffer from two fundamental weaknesses:

| Weakness | Impact | FusionIDS Solution |
|----------|--------|-------------------|
| **Single Point of Failure** | Compromised central server renders entire monitoring inoperable | Distributed N-node architecture with PBFT fault tolerance |
| **Log Tampering** | Attackers can delete/modify alerts retroactively | Immutable blockchain ledger with cryptographic consensus |

### Why Decentralization Matters

- **Resilience**: System remains operational even if f nodes are compromised (Byzantine fault tolerance)
- **Trust**: Alerts validated by 2f+1 independent nodes—no single entity controls the truth
- **Auditability**: ECDSA-signed blocks create verifiable, tamper-proof evidence

---

##  Literature Survey & Technologies

### Key Academic References

| Reference | Contribution | FusionIDS Application |
|-----------|--------------|----------------------|
| Sharafaldin et al. (2018) | CSE-CIC-IDS2018 dataset & CICFlowMeter | Training data + C++ capturer design |
| Castro & Liskov (1999) | PBFT consensus protocol | Blockchain consensus foundation |
| Liu, Ting & Zhou (2008) | Isolation Forest algorithm | Zero-day anomaly detection |
| Ferrag et al. (2020) | ML/DL survey for NIDS | Justified ensemble over deep learning |
| Alexopoulos et al. (2020) | Blockchain-based IDS | Tamper-proof alert ledger |

### Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Packet Capture** | C++17, libpcap, POSIX | Native high-speed network flow extraction |
| **Flow Tracking** | Custom hash map, murmurhash | Bidirectional flow assembly by 5-tuple |
| **Statistics Engine** | Welford's online algorithm | O(1) per-packet mean/variance updates |
| **Feature Extraction** | FeatureExtractor (68 features) | CIC-IDS2018-compatible vectors |
| **Build System** | CMake 3.10+, GCC/G++ | Cross-platform C++ compilation |
| **ML Inference** | Python 3.11, LightGBM, XGBoost, scikit-learn | Supervised ensemble classification |
| **Anomaly Detection** | scikit-learn Isolation Forest | Unsupervised zero-day threat detection |
| **API Server** | FastAPI, Uvicorn | ML microservice (`/predict`, `/validate`) |
| **Blockchain** | Core Python, ECDSA (secp256k1) | Alert signing and chain validation |
| **Consensus** | Custom PBFT implementation | Byzantine fault-tolerant agreement |
| **Cryptography** | ECDH, AES-256-GCM | Encrypted inter-node PBFT messages |
| **Persistence** | SQLite (WAL mode) | On-chain blocks + off-chain features |
| **Containerization** | Docker multi-stage, Docker Compose | Multi-node cluster orchestration |
| **Process Management** | supervisord | 4 processes per container lifecycle |
| **Dashboard** | React/Vite, TailwindCSS, FastAPI | Real-time attack visualization |

---

## 🔧 Methodology

### 1. Data Preprocessing Pipeline

The raw CSE-CIC-IDS2018 dataset undergoes rigorous preprocessing:

```mermaid
graph LR
    A["Raw CSV<br/>Multiple Sessions"] --> B["Merge &<br/>Deduplicate"]
    B --> C["Clean Data<br/>NaN/Inf Handling"]
    C --> D["Label Encode<br/>7 Classes"]
    D --> E["Stratified Split<br/>Train/Val/Test"]
    E --> F["Feature Selection<br/>RF + MI Union"]
    F --> G["Final: 63 Features<br/>Optimized"]
```

**Pipeline Steps:**

1. **Merging**: Consolidate multiple CSV sessions with deduplication
2. **Cleaning**: Remove NaN, replace inf, drop constant columns
3. **Label Encoding**: Map 7 attack types to integer classes (0-6)
4. **Stratified Sampling**: Preserve class distributions across splits
5. **Feature Selection**: Union of RF importance (>0.001) + Mutual Information (90th percentile)
   - **Dropped**: `Bwd PSH Flags`, `Fwd URG Flags`, `Bwd URG Flags`, `FIN Flag Cnt`, `RST Flag Cnt`, `ECE Flag Cnt`
   - **Result**: 63 high-signal features from original 68

### 2. Native C++17 Flow Capture Engine

The front-line packet processing component with **zero packet loss** performance.

**Architecture:**

```
traffic_capturer_updated/
├── Header Files (20)
│   ├── FlowKey.h          → 5-tuple hashing
│   ├── Flow.h             → Per-flow state machine
│   ├── RunningStats.h     → Welford's online algorithm
│   ├── FeatureExtractor.h → 68-feature computation
│   ├── FeatureSender.h    → HTTP POST to ML server
│   └── ...
└── Source Files (13)
    ├── main.cpp           → libpcap loop
    ├── PacketParser.cpp   → Frame dissection
    ├── ThreadSafeQueue.cpp → Producer-consumer queue
    └── ...
```

**Key Components:**

| Component | Function |
|-----------|----------|
| **pcap_loop()** | Kernel-level buffering, promiscuous mode, BPF filter (excludes ports 5000, 8000) |
| **ThreadSafeQueue** | Mutex + condition variable decouples capture from N worker threads (autoscaled to `hardware_concurrency/2`) |
| **PacketParser** | Dissects Ethernet → IPv4 → TCP/UDP; extracts 5-tuple, flags, window size |
| **FlowTable** | `unordered_map<FlowKey, Flow*>` with murmur-inspired hash function |
| **Flow::update()** | Delegates to 6 stat modules; each performs O(1) Welford update |
| **RunningStats** | Numerically stable online mean/variance without storing samples |
| **FeatureExtractor** | Produces 68-element vector in exact CIC-IDS2018 order |
| **FeatureSender** | Serializes JSON, POSTs via raw POSIX sockets to ML server |

**Statistical Modules (6):**

1. **LengthStats**: Payload-only packet lengths
2. **IATStats**: Inter-arrival time distributions
3. **ActivityStats**: Active/idle period tracking (1-second threshold)
4. **HeaderStats**: Forward/backward header bytes
5. **TCPStats**: 7 TCP flag counters, window sizes, active data packets
6. **VolumeStats**: Packet/byte rate metrics

**Flow Expiry:**
- Configurable timeout + dedicated `ExpiryThread` (5-second scan interval)
- Idle flow detection triggered by packet arrivals

### 3. Hybrid Machine Learning Architecture

#### 3a. Supervised Signature Ensemble

Three gradient boosting classifiers trained on 63 selected features:

**LightGBM:**
- Estimators: 500 (early stopped ~200)
- Max depth: 8, Leaves: 127
- Learning rate: 0.1
- Balanced class weights, L1/L2 regularization (α=0.1, λ=1.5)
- Validation accuracy: **99.8%+**

**XGBoost:**
- Similar configuration with Optuna hyperparameter tuning
- GPU acceleration support
- Validation accuracy: **99.6%+**

**Random Forest:**
- Sklearn implementation with balanced subsample weighting
- Bayesian Optimization hyperparameters
- Validation accuracy: **99.5%+**

**Feature Normalization:**
- `SignaturePredictor` handles transparent underscore ↔ space conversion
- All models preserve `feature_names_in_` for correct alignment

#### 3b. Unsupervised Anomaly Detection

**Isolation Forest** trained exclusively on benign traffic:

| Anomaly Score | Interpretation |
|---|---|
| > -0.45 | Normal |
| -0.55 to -0.45 | Anomaly |
| < -0.55 | Strong Anomaly |

- Missing values imputed with column medians
- Benign-only training ensures zero false negatives on known traffic

#### 3c. Fusion Engine

The **6-case decision matrix** combines signature and anomaly results:

```mermaid
graph TD
    A["Signature Result"] --> B["Fusion Decision"]
    C["Anomaly Score"] --> B
    
    B --> C1["Case 1: Attack + Strong Anomaly<br/>→ CRITICAL"]
    B --> C2["Case 2: Attack + Normal<br/>→ HIGH"]
    B --> C3["Case 3: Benign + Strong Anomaly<br/>→ UNKNOWN ATTACK = HIGH"]
    B --> C4["Case 4: Benign/Low Conf + Anomaly<br/>→ SUSPICIOUS = LOW"]
    B --> C5["Case 5: Attack/Low Conf + Anomaly<br/>→ SUSPICIOUS = MEDIUM"]
    B --> C6["Case 6: Benign + Normal<br/>→ NORMAL FLOW"]
```

**Coverage Strategy:**
- **Known attacks**: Cases 1-2 (supervised ensemble)
- **Zero-day threats**: Case 3 (anomaly detector)
- **Edge cases**: Cases 4-5 (graduated confidence)
- **Normal traffic**: Case 6 (no false positives)

#### 3d. Server Architecture

**Two FastAPI endpoints with distinct roles:**

```python
# /predict — Called by C++ capturer
# Runs both detectors → fuses results → forwards to blockchain (bg thread)
# Returns full inference results to capturer

# /validate — Called by peer nodes during PBFT PRE-PREPARE
# Runs identical inference but NEVER forwards to blockchain
# Prevents infinite recursive alert loops
```

### 4. PBFT Blockchain Consensus

When the ML engine produces an alert, it enters the blockchain pipeline:

**Step 1: Alert Creation & Signing**

```
NodeApi.py:/alert endpoint
├─ Receive alert from ml_server.py
├─ Create AlertTransaction
│  ├─ Alert type (7 categories)
│  ├─ Detector outputs (signature confidence + anomaly score)
│  ├─ Audit metadata (5-tuple, severity, fusion type)
│  └─ Raw flow features (_raw_features)
├─ Sign with ECDSA (secp256k1 private key)
└─ Derive unique tx_id = SHA256(signing_data + signature_hex)
```

**Step 2: Block Proposal**

- Signed alert queued in pending alerts list
- New Block created with linkage to previous block
- Raw flow features attached as `_raw_features` for peer validation
- Watchdog thread monitors blocks (drops if uncommitted after 5 seconds)

**Step 3: Leaderless PBFT Consensus**

```
PRE-PREPARE:
├─ Proposing node broadcasts block to peers
└─ Messages encrypted: AES-256-GCM with ECDH-derived session key

PREPARE:
├─ Each peer decrypts message
├─ Verifies sender's ECDSA signature
├─ Calls local ML's /validate endpoint on raw features
└─ Sends PREPARE vote if local model agrees (non-benign)

COMMIT:
├─ Once 2f+1 PREPARE votes collected
└─ Nodes send COMMIT messages

DECIDED:
├─ After 2f+1 COMMIT votes
└─ Block permanently committed
```

**Step 4: Block Commitment**

```python
Node.On_Block_Committed():
├─ blockchain.add_block()         # Validate linkage & hashes
├─ db.save_block()                # Persist to SQLite
├─ Store raw features in flow_features table (linked by tx_id)
└─ Advance pool to next candidate block
```

**Step 5: Immutable Storage**

**SQLite Schema (WAL mode enabled):**

```sql
-- On-chain data (blocks table)
CREATE TABLE blocks (
    block_hash TEXT PRIMARY KEY,
    previous_hash TEXT,
    block_number INTEGER,
    alert_type TEXT,
    alert_severity TEXT,
    detector_outputs JSON,
    pbft_signatures JSON,
    node_id TEXT,
    timestamp INTEGER
);
CREATE INDEX idx_block_hash ON blocks(block_hash);
CREATE INDEX idx_alert_type ON blocks(alert_type);
CREATE INDEX idx_node_id ON blocks(node_id);

-- Off-chain data (flow features table)
CREATE TABLE flow_features (
    tx_id TEXT PRIMARY KEY,
    flow_features JSON,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER
);
CREATE INDEX idx_tx_id ON flow_features(tx_id);
```

**Step 6: Chain Synchronization**

- **Trusted path**: Restore chain from local SQLite (no recompute)
- **Untrusted path**: Sync with peers via `replace_chain()` (full hash verification on every block)

### 5. Secure Inter-Node Communication

All PBFT messages encrypted end-to-end:

**Key Exchange (ECDH):**
- Each node generates ECDH keypair on startup
- `/dh handshake` exchanges DH + identity public keys in one round-trip
- Shared secret derived via elliptic curve scalar multiplication
- 256-bit AES session key derived via SHA-256

**Message Encryption (AES-256-GCM):**
- Before broadcast: encrypt PBFT message with recipient's unique session key
- 12-byte random nonce for authenticated encryption

**Message Authentication (ECDSA secp256k1):**
- Each encrypted payload signed with sender's private key
- Recipient verifies signature against registered public key before decryption
- Prevents forgery and replay attacks

### 6. Containerized Deployment

**Multi-Stage Docker Build:**

```dockerfile
# Stage 1: cpp-builder
FROM ubuntu:22.04 AS cpp-builder
RUN apt-get update && apt-get install -y \
    cmake build-essential libpcap-dev libboost-all-dev \
    nlohmann-json3-dev
COPY traffic_capturer_updated/ /src/
WORKDIR /src
RUN cmake . && make

# Stage 2: runtime
FROM python:3.11-slim
COPY --from=cpp-builder /src/capturer /usr/local/bin/
RUN pip install fastapi uvicorn lightgbm xgboost scikit-learn \
    ecdsa cryptography flask pandas numpy joblib
COPY updated_model/inference/ /app/
COPY blockchain/ /app/blockchain/
COPY supervisord.conf /etc/supervisor/conf.d/
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]
```

**Docker Compose (5-Node Cluster):**

```yaml
version: '3.8'
services:
  node-0:
    build: .
    container_name: fusion-ids-node-0
    environment:
      NODE_ID: 0
      BLOCKCHAIN_PORT: 5000
      ML_PORT: 8000
    ports:
      - "5000:5000"
      - "8000:8000"
      - "9000:9000"
    volumes:
      - ./data/node0:/app/data
    networks:
      - ids-net

  node-1:
    build: .
    container_name: fusion-ids-node-1
    # ... similar config with NODE_ID: 1, port mapping offsets
    volumes:
      - ./data/node1:/app/data

  # ... node-2, node-3, node-4

  dashboard:
    image: node:18-alpine
    build: ./dashboard
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data
    networks:
      - ids-net

networks:
  ids-net:
    driver: bridge
```

**Process Management (supervisord):**

Each container runs 4 processes with automatic restart:

```ini
[program:target_server]
command=/usr/bin/python3 /app/target_server.py
autorestart=true
priority=1

[program:blockchain_node]
command=/usr/bin/python3 /app/blockchain/node.py
autorestart=true
priority=2

[program:ml_server]
command=/usr/bin/uvicorn app.inference:app --host 0.0.0.0 --port 8000
autorestart=true
priority=3

[program:c_capturer]
command=/usr/local/bin/capturer
autorestart=true
priority=4
```

### 7. Real-Time Monitoring Dashboard

**Backend (FastAPI):**

```python
@app.get("/api/nodes")
async def get_nodes():
    """Node status + model info across all SQLite DBs"""
    return {
        "nodes": [
            {"node_id": 0, "model": "LightGBM", "status": "healthy"},
            {"node_id": 1, "model": "XGBoost", "status": "healthy"},
            # ...
        ]
    }

@app.get("/api/alerts")
async def get_recent_alerts(limit: int = 50):
    """Recent alerts deduplicated by alert_tx_id"""
    return fetch_and_deduplicate_alerts(limit)

@app.get("/api/blocks")
async def get_blockchain():
    """Full block list with timestamps"""
    return blockchain_data

@app.get("/api/stats")
async def get_stats():
    """Attack distribution, severity, fusion method breakdown"""
    return aggregated_statistics
```

**Frontend (React/Vite):**

- TailwindCSS-styled SPA
- Live node health monitoring
- Alert timeline with severity badges
- Attack type breakdown charts (recharts)
- Severity distribution visualization
- Auto-refresh every 5 seconds

---

##  System Performance

### Performance Metrics

| Metric | Value | Note |
|--------|-------|------|
| **C++ Feature Extraction Latency** | < 1ms | O(1) per packet, Welford's online |
| **ML Inference Latency** | < 2ms (single), < 5ms (3-model voting) | Per flow |
| **PBFT Consensus Time** | < 500ms | 5-node cluster, parallel broadcast |
| **End-to-End Alert Latency** | < 1 second | Capture → classify → commit |
| **Blockchain Block Size** | 1 alert/block | Granular audit trail |
| **Byzantine Fault Tolerance** | f=1 | Tolerates 1 compromised node in 5-node |
| **Feature Dimensionality** | 68 → 63 | 5 dropped by feature selection |
| **Flow Expiry Detection** | 5-second scan + packet-driven | ExpiryThread efficiency |
| **Encryption** | AES-256-GCM + ECDSA | Inter-node + signatures |
| **Database Mode** | SQLite WAL | Concurrent read/write support |

### Classification Accuracy

| Model | Validation Accuracy | Best Iteration |
|-------|-------------------|-----------------|
| LightGBM | 99.8%+ | ~200 (early stopped) |
| XGBoost | 99.6%+ | Similar early stopping |
| Random Forest | 99.5%+ | Full training |

### Traffic Classification Categories

The system successfully classifies into **7 attack types**:

1. **Benign (0)** — Normal network traffic
2. **BruteForce (1)** — Credential stuffing / password guessing (high PSH count, bidirectional)
3. **DoS (2)** — Denial-of-Service flooding (thousands of packets, high byte rate)
4. **PortScan (3)** — Network reconnaissance (many short single-packet flows)
5. **Bot (4)** — Botnet C&C beaconing (long idle periods, periodic bursts)
6. **WebAttack (5)** — SQL injection, XSS, web exploitation
7. **Infiltration (6)** — Slow data exfiltration (high TotLen Fwd, sustained transfer)

---

##  Deployment

### Quick Start

```bash
# Clone repository
git clone https://github.com/yourusername/FusionIDS.git
cd FusionIDS

# Build Docker images
docker-compose build

# Start 5-node cluster
docker-compose up -d

# View logs
docker-compose logs -f node-0

# Access dashboard
open http://localhost:3000

# Check blockchain consensus
curl http://localhost:5000/api/blocks

# Stop cluster
docker-compose down
```

### System Requirements

- **CPU**: 4+ cores (for worker thread autoscaling)
- **RAM**: 8GB+ (for model inference + blockchain state)
- **Network**: 1Gbps+ for packet capture (libpcap performance)
- **OS**: Linux kernel 4.15+ (BPF filter support, AWE-256-GCM acceleration)

### Configuration

**Environment Variables** (in `docker-compose.yml`):

```bash
NODE_ID=0                    # Unique node identifier
BLOCKCHAIN_PORT=5000         # Consensus port (inter-node)
ML_PORT=8000                 # ML inference port
CONSENSUS_TIMEOUT=500        # PBFT timeout (ms)
FLOW_IDLE_TIMEOUT=30         # Flow expiry (seconds)
BPF_FILTER="port 80 or port 443"  # Capture filter
```

---

##  Results

### Model Performance on CSE-CIC-IDS2018

**Supervised Ensemble (99.8%+ accuracy across 7 categories):**
- LightGBM primary classifier (nodes 0, 1)
- XGBoost backup (GPU-accelerated)
- Random Forest diversity layer

**Unsupervised Anomaly Detection:**
- Isolation Forest on benign-only features
- Detects novel attack patterns absent from training data
- Complements signature detection for zero-day coverage

### System-Wide Performance

 **Zero packet loss** at line rates (tested up to 1Gbps)
 **< 1 second** end-to-end latency from packet arrival to immutable blockchain commit
 **Byzantine fault tolerance** for f=1 compromised nodes in 5-node cluster
 **Tamper-proof audit trail** with cryptographic ECDSA signatures
 **Heterogeneous node diversity** prevents single model vulnerability

---

## 🔮 Conclusions & Future Scope

### Key Achievements

1. **Decentralization eliminates single point of failure**: PBFT consensus keeps system operational even if f nodes are compromised.

2. **Dual-layer ML provides complete threat coverage**: Supervised ensemble (known signatures) + Isolation Forest (zero-day anomalies) + 5-case fusion ensures no attack category bypasses detection.

3. **Native C++17 capture ensures zero packet loss**: libpcap + Welford O(1) statistics + ExpiryThread achieve sub-millisecond feature computation without JVM overhead.

4. **Blockchain immutability prevents evidence tampering**: ECDSA-signed alerts committed via PBFT consensus create verifiable audit trails attackers cannot retroactively modify.

5. **Heterogeneous node configurations add diversity**: Different ML model combinations (RF, LightGBM, XGBoost, Anomaly) prevent single model vulnerability from compromising entire network.

6. **End-to-end encryption secures detection infrastructure**: ECDH key exchange + AES-256-GCM authenticated encryption + ECDSA signatures ensure PBFT consensus messages cannot be intercepted or forged.

### Future Enhancements

- **Deep Learning Integration**: Transformer or 1D-CNN architectures for payload-level inspection and encrypted malware tunnel detection
- **Federated Learning**: Gradient update sharing across nodes while preserving privacy
- **Smart Contract Enforcement**: Auto-trigger network isolation (firewall rules) on critical-severity consensus alerts
- **Horizontal Scalability**: Sharding or layer-2 protocols (HotStuff, Tendermint) to scale beyond 20-node PBFT limit
- **Dashboard Enhancements**: Geographic origin mapping, attack correlation timelines, automated PDF reports, SIEM integration (syslog/CEF)
- **Adversarial ML Robustness**: Defend against adversarial evasion attacks designed to fool classifiers

---

##  References

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion Detection Using Machine Learning Techniques." *International Conference on Information Systems Security and Privacy (ICISSP)*.

2. Castro, M., & Liskov, B. (1999). "Practical Byzantine Fault Tolerance." *Proceedings of the Third Symposium on Operating Systems Design and Implementation (OSDI)*.

3. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). "Isolation Forest." *Eighth IEEE International Conference on Data Mining*.

4. Ferrag, M. A., et al. (2020). "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study." *Journal of Information Security and Applications*.

5. Ke, G., et al. (2017). "LightGBM: A Highly Efficient Gradient Boosting Decision Tree." *Advances in Neural Information Processing Systems (NeurIPS)*.

6. Alexopoulos, N., et al. (2020). "Blockchain-based Intrusion Detection Systems: A Survey." *ACM Computing Surveys*.

7. Chen, T., & Guestrin, C. (2016). "XGBoost: A Scalable Tree Boosting System." *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining*.


**Pranathi Udaya Kumar** — Creator, NIT Karnataka

For questions or collaborations, open an issue or contact via GitHub.
