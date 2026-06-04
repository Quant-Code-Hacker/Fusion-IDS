​
Aim
To design and implement a fully decentralized, real-time Intrusion Detection System (IDS) that addresses the critical vulnerabilities of traditional centralized IDS architectures — namely single points of failure and log tampering — by fusing high-throughput native packet capture, dual-layer machine learning (supervised + unsupervised), and cryptographically secured distributed ledger consensus, packaged as a production-ready Docker-orchestrated multi-node cluster.

Introduction
Modern network infrastructures face increasingly sophisticated cyber threats ranging from known attack vectors such as Distributed Denial-of-Service (DDoS), Brute Force, and Botnet infiltration, to completely novel zero-day exploits with no prior signature. Traditional centralized Intrusion Detection Systems, while effective at detecting known patterns, suffer from two fundamental weaknesses:

    1. Single Point of Failure: A centralized IDS server, once compromised, renders the entire monitoring pipeline inoperable. The attacker gains complete control over what is logged and what is silently discarded.

    2. Log Tampering: Even if the IDS detects malicious activity before being neutralized, a sophisticated attacker can retroactively delete or modify the alert logs stored on the same centralized infrastructure, effectively erasing all evidence of the intrusion.

FusionIDS addresses both weaknesses through a three-tier architecture:

    Tier 1 — Native C++17 Flow Capturer: A high-performance packet capture engine built in C++17 that hooks directly into the    network interface ( eth0 ) via libpcap . It assembles raw Ethernet frames into bidirectional network flows using a murmur-hashbased flow table keyed by the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) and computes 68 statistical features per flow in real-time using Welford's online algorithm for O(1) per-packet updates. The 68 features are divided into six purposebuilt statistical modules: LengthStats (payload-only packet lengths matching CICFlowMeter semantics), IATStats (inter-arrival time distributions), ActivityStats (active/idle period tracking with 1-second threshold), HeaderStats (forward/backward header byte totals), TCPStats (all 7 TCP flag counters, initial window sizes, active data packets), and VolumeStats (packet/byte rate metrics) Upon flow expiration (configurable timeout + dedicated ExpiryThread for idle flow detection), the feature vector is serialized as JSON and POSTed to the ML server via raw POSIX sockets.

    Tier 2 — Hybrid ML Inference Engine: A FastAPI-based microservice architecture running dual-layer machine learning. The supervised ensemble layer (LightGBM, XGBoost, Random Forest — each with balanced class weights and early stopping) detects known attack signatures with 99.5%+ accuracy across 7 traffic categories (Benign, BruteForce, DoS, PortScan, Bot, WebAttack, Infiltration), while a dedicated unsupervised Isolation Forest anomaly detector, trained exclusively on benign traffic, flags previously unseen traffic patterns that deviate from normal behavior — catching zero-day threats that bypass all signature databases. FusionEngine implements a 5-case decision matrix that combines both detectors' outputs into severity-graded alerts (Critical → Low), ensuring complete threat coverage.

    Tier 3 — PBFT Blockchain Consensus Network: When the ML engine raises an alert, it is not immediately trusted. The alert is submitted to a network of N distributed nodes running a leaderless Practical Byzantine Fault Tolerance (PBFT) consensus protocol. Each peer node independently re-validates the alert using its own local ML model (via a dedicated /validate endpoint that never triggers recursive alerts). Only when 2f+1 nodes cryptographically agree (with ECDSA secp256k1 signatures and AES-256-GCM encrypted inter-node communication derived from ECDH key exchange) does the alert get permanently committed to an immutable blockchain ledger backed by per-node SQLite databases. This guarantees that even if an attacker compromises a single node, they cannot delete or forge intrusion records.

The entire system is containerized using Docker with a multi-stage build (C++ compilation on Ubuntu 22.04 builder → slim runtime image) and orchestrated via Docker Compose with supervisord managing 4 processes per container (target server, blockchain node, ML server, C++ capturer). A React/Vite monitoring dashboard with a FastAPI backend reads directly from the SQLite databases to provide real-time attack visualization.

Literature Survey and Technologies Used
Literature Survey
Reference	Key Contribution	Relevance to FusionIDS
Sharafaldin et al. (2018)	CSE-CIC-IDS2018 dataset & CICFlowMeter	Training data + C++ capturer design
Ferrag et al. (2020)	ML/DL survey for NIDS	Justified ensemble over deep learning
Castro & Liskov (1999)	PBFT consensus protocol	Blockchain consensus foundation
Liu, Ting & Zhou (2008)	Isolation Forest algorithm	Zero-day anomaly detection layer
Alexopoulos et al. (2020)	Blockchain-based IDS	Tamper-proof alert ledger design
Technologies Used
Component
Technology 
Purpose
Packet Capture	C++17, libpcap, POSIX sockets	Native high-speed network flow extraction
Flow Tracking	Custom hash map, murmurhash (FlowKey)	Bidirectional flow assembly by 5- tuple
Statistical Engine (RunningStats)	Welford's online algorithm	O(1) mean/variance/std per packet update
Feature Extraction	FeatureExtractor (68 features, 6 modules)	CIC-IDS2018-compatible feature vectors
Build System	CMake 3.10+, GCC/G++ (Ubuntu 22.04)	Cross-platform C++ build pipeline
ML Inference	Python 3.11, LightGBM, XGBoost, scikit-learn	Supervised ensemble classification
Anomaly Detection	scikit-learn Isolation Forest	Unsupervised zero-day threat detection
API Server	FastAPI, Uvicorn, Pydantic	ML inference microservice ( /predict , /validate )
Blockchain	Core Python, ECDSA (secp256k1), SHA-256	Alert blocks, signing, chain validation
Consensus Protocol	Leaderless PBFT (custom Python)	Byzantine fault-tolerant alert agreement
Cryptography	ECDH key exchange, AES-256- GCM (AESGCM)	Encrypted inter-node PBFT communication
Node Networking	Flask, POSIX HTTP	Blockchain API endpoints and peer client
Persistence	SQLite (WAL mode), per-node databases	On-chain blocks + off-chain flow features
Containerization	Docker (multi-stage build), Docker Compose	Multi-node cluster orchestration
Process Management	supervisord	4 processes per container lifecycle
Data Pipeline	Pandas, NumPy, joblib	Feature engineering and model serialization
Dashboard Backend	FastAPI (reads SQLite directly)	Real-time monitoring data API
Dashboard Frontend	React (Vite), TailwindCSS	Real-time attack visualization UI
Methodology
1. Data Preprocessing Pipeline
The raw CSE-CIC-IDS2018 dataset undergoes a rigorous multi-step preprocessing pipeline:

  1. Merging: Raw CSV files from multiple capture sessions are merged into a unified dataset. Duplicate rows and overlapping      sessions are handled with deduplication logic.

  2. Cleaning: Infinite values are replaced, NaN entries are removed, and constant-value columns are dropped. Duplicate flows    are liminated.

  3. Label Encoding: Attack categories are encoded into 7 integer classes — Benign (0), BruteForce (1), DoS (2), PortScan (3),    Bot (4), WebAttack (5), Infiltration (6).

  4. Stratified Sampling & Splitting: The cleaned dataset is split into train/validation/test sets with stratified sampling to preserve    class distributions across all splits

  5. Feature Selection: A union of Random Forest feature importance (threshold > 0.001) and Mutual Information scores (top 90th  percentile) yields the final 63 optimized features, eliminating 5 low-signal columns ( Bwd PSH Flags , Fwd URG Flags ,                    Bwd URG Flags , FIN Flag Cnt , RST Flag Cnt ,  ECE Flag Cnt ) that contribute minimal discriminative power.

2. Native C++17 Flow Capture Engine
The C++ traffic capturer ( traffic_capturer_updated/ ) is the system's front-line component, designed for zero-packet-loss performance. The codebase is organized into 20 header files and 13 source files compiled via CMake.

  Packet Sniffing: Uses libpcap 's pcap_loop() with kernel-level buffering in promiscuous mode. A BPF filter excludes internal        PBFT (port 5000) and ML server (port 8000) traffic.

  Thread-Safe Queue: A producer-consumer queue ( ThreadSafeQueue ) with mutex + condition variable decouples the pcap      capture thread from N worker threads (autoscaled to hardware_concurrency/2 ).

  Packet Parsing: PacketParser dissects raw Ethernet frames through the protocol stack: Ethernet → IPv4 → TCP/UDP. It            extracts the 5-tuple, IP total length, IP header length (IHL×4), TCP header length (data offset×4), TCP flags, TCP window size,        and payload length into a PacketMeta struct.

  Flow Tracking: FlowTable maintains an unordered_map using a murmur-inspired hash function ( FlowKeyHash ) on the 5-tuple. Each packet is assigned to its parent flow. Forward/backward direction is determined by matching the packet's source against          the flow's originator.

  Statistical Feature Computation: Upon each packet arrival, Flow :update() delegates to all six stat modules — each performing O(1) updates using Welford's singlepass algorithm ( RunningStats ) for numerically stable online mean/variance computation          without storing individual samples.

  Feature Extraction: FeatureExtractor ::extract() produces a 68-element float vector in exact CIC-IDS2018 CSV column order, calling activity.finish() to finalize active/idle period statistics before reading. Safe division ( safe_div ) prevents division-by-zero          for single-packet flows.

  Feature Transmission: FeatureSender serializes the 68-feature vector as a JSON dictionary with proper CIC feature names and flow metadata ( src_ip , dst_ip , src_port , dst_port , protocol ) and POSTs to the ML server via raw POSIX sockets on localhost.

3. Hybrid Machine Learning Architecture
The ML inference layer implements a dual-strategy detection approach within a containerized FastAPI server ( updated_model/inference/ ):

3a. Supervised Signature Ensemble

Three gradient boosting classifiers are trained independently on 63 selected features:

    LightGBM: 500 estimators, 127 leaves, max_depth=8, learning_rate=0.1, balanced class weights, L1/L2 regularization (α=0.1, λ=1.5), early stopping at 20 rounds, column subsampling at 75%

   XGBoost: Similar hyperparameter configuration with GPU acceleration support and Optuna-tuned parameters stored in            config/xgb_best_params.json

   Random Forest: Sklearn implementation with balanced subsample weighting for class imbalance handling

All three models preserve feature names via feature_names_in_ for correct column alignment at inference time. A SignaturePredictor class handles transparent feature name normalization between underscore-style (LightGBM internally converts spaces to underscores) and space-style (CIC original).

3b. Unsupervised Anomaly Detection

An Isolation Forest model is trained exclusively on benign-only traffic using a specialized feature subset. During inference, AnomalyPredictor produces a scalar anomaly score for each flow via model.score_samples() . Missing values are imputed with column medians. The anomaly score is a real number where more negative values indicate stronger anomaly:

Score Range	Interpretation
> -.45	Normal
-0.55 to -0.45	Anomaly
< -0.55	Strong Anomaly
3c. Fusion Engine

The FusionEngine class implements a 6-case decision matrix that combines the signature and anomaly results:

Case	Signature Result	Anomaly Result	Final Verdict	Confidence
1	Attack Detected	Strong Anomaly	Attack Name	Critical
2	Attack Detected	Normal	Attack Name	High
3	Benign	Strong Anomaly	Unknown Attack	High
4	Benign(low conf)	Anomaly	Suspicios 	Low
5	Attack(low conf)	Anomaly	Suspicious (Attack Name)	Medium
6	Benign	Normal	Normal Flow	N.A

 

This fusion strategy ensures complete threat coverage — known attacks are caught by signatures (Cases 1-2), novel zero-day threats are flagged by the anomaly detector (Case 3), and edge cases where neither detector is individually confident are still surfaced (Cases 4-5).

3d. Server Architecture

Two FastAPI endpoints serve distinct roles: - /predict — Called by the C++ capturer. Runs both detectors, fuses results, and forwards non-null alerts to the blockchain node in a background thread. Returns full inference results to the capturer. - /validate — Called by peer blockchain nodes during PBFT PRE-PREPARE. Runs identical inference but never forwards results to the blockchain, preventing infinite recursive alert loops.

4. PBFT Blockchain Consensus
When the ML engine produces a non-null alert, the flow enters the blockchain consensus pipeline:

   1. Alert Creation & Signing ( NodeApi.py /alert ): The originating node's API endpoint receives the alert from ml_server.py constructs an AlertTransaction containing the alert type, detector outputs (signature confidence + anomaly score), and audit metadata (5-tuple, severity, fusion type). The transaction is signed using ECDSA (secp256k1 curve) via the node's private key. A unique tx_id is derived as SHA256(signing_data + signature_hex).

   2. Block Proposal ( Node.submit_alert() ): The signed alert is queued in the blockchain's pending alerts list. A new Block is created (one alert per block) with cryptographic linkage to the previous block. Raw flow features are attached to the block dict as  _raw_features for peer IDS validation. A watchdog thread monitors blocks that haven't committed within 5 seconds and drops them to prevent pool stagnation.

   3. Leaderless PBFT Consensus: - PRE-PREPARE: The proposing node broadcasts the block to all peers via encrypted channels - PREPARE: Each receiving node decrypts the message (AES-256-GCM with ECDH-derived session key), verifies the sender's ECDSA signature, then independently calls its local ML model's /validate endpoint on the raw flow features. If the local model also flags the traffic as non-benign, the node sends a PREPARE vote. The proposer's own vote is excluded from the 2f+1 quorum. - COMMIT: Once 2f+1 PREPARE votes are collected, nodes send COMMIT messages - DECIDED: After 2f+1 COMMIT votes, the block is permanently committed.

   4. Block Commitment ( Node.On_Block_Committed() ): The block is appended to the inmemory chain via blockchain.add_block() (which validates block number, previous hash linkage, and self-hash consistency), persisted to the local SQLite database via db.save_block() , raw flow features are stored in the off-chain flow_features table linked by tx_id, and the pool advances to the next candidate block.

   5. Immutable Storage: Each node maintains its own SQLite database with WAL mode enabled for concurrent read/write performance. The schema has two tables: - blocks : On-chain data (block hash, previous hash, alert metadata, PBFT signatures, detector outputs as JSON) with indexes on block_hash , alert_type , and node_id - flow_features : Off-chain raw CIC-IDS features (linked to blocks via tx_id ) for forensic analysis.

   6. Chain Synchronization: Nodes joining mid-session first restore their chain from local SQLite (trusted path — no hash      recompute), then sync with peers via replace_chain() (untrusted path — full hash verification on every block) to catch up on any blocks missed while offline.

5. Secure Inter-Node Communication
All PBFT messages between nodes are encrypted end-to-end:

        1. Key Exchange: Each node generates an ECDH keypair on startup. During the /dh handshake, nodes exchange DH public keys and identity public keys in a single round- trip. A shared secret is derived via elliptic curve scalar multiplication, from which a 256-bit AES session key is derived via SHA-256.

       2. Message Encryption: Before broadcasting, each PBFT message is encrypted with the recipient's unique session key using AES-256-GCM (authenticated encryption with 12- byte random nonce).

      3. Message Authentication: Each encrypted payload is signed with the sender's ECDSA private key. Recipients verify the signature against the sender's registered public key before decryption.



6. Containerized Deployment
The entire system is packaged as a multi-stage Docker image:

    Stage 1 ( cpp-builder ): Compiles the C++ capturer using CMake on Ubuntu 22.04 with libpcap-dev, Boost, and nlohmann-json

    Stage 2 ( runtime ): Copies the compiled binary, installs Python dependencies (FastAPI, LightGBM, XGBoost, ecdsa, cryptography), copies ML models and blockchain code into a slim runtime image

Docker Compose orchestrates 5 nodes on a shared bridge network ( ids-net ), each with: - A C++ packet capturer process (with BPF filter excluding internal ports) - A FastAPI ML inference server (port 8000) - A Flask blockchain node (port 5000) - A target TCP echo server (port 9000+) for attack simulation.

All 4 processes within each container are managed by supervisord with automatic restart, log rotation, and startup priority ordering (target → blockchain → ML server → capturer).



7. Real-Time Monitoring Dashboard
A separate React/Vite frontend with a FastAPI backend provides operational visibility:

    Backend: Reads directly from SQLite databases (mounted as Docker volumes at ./data/nodeX/ ), deduplicates blocks across    all 5 nodes by alert_tx_id , and serves REST endpoints: /api/nodes (node status + model info), /api/alerts (recent alerts), /api/blocks (full block list), /api/stats (attack distribution, severity breakdown, fusion method distribution)

    Frontend: TailwindCSS-styled React SPA with live node health monitoring, alert timeline, attack type breakdown charts, and      severity distribution visualization





Results
Model Performance
The supervised models were trained on the CSE-CIC-IDS2018 dataset with 63 selected features and evaluated on a held-out test split:
Model	Val Accuracy	Best Iteration	Training Notes
LightGBM	99.8%+	~200 (early stopped from 500)	Primary model for nodes 0,1; 127 leaves, balanced weights
XGBoost	99.6%+	Similar early stopping	GPU-accelerated training; Optuna hyperparameter tuning
Random Forest	99.5%+	N/A	Bagging-based diversity; balanced subsample weighting, Bayesian Optimization
Classification Categories
The system successfully classifies traffic into 7 categories: - Benign (0) — Normal network traffic - BruteForce (1) — Credential stuffing / password guessing attacks (high PSH count, bidirectional, persistent connections) - DoS (2) — Denial-of-Service flooding (thousands of packets, high byte rate) - PortScan (3) — Network reconnaissance via port enumeration (many short single-packet flows) - Bot (4) — Botnet command-and-control beaconing (long idle periods, periodic active bursts) - WebAttack (5) — SQL injection, XSS, and web exploitation - Infiltration (6) — Slow data exfiltration over persistent connections (high TotLen Fwd, sustained transfer)

System Performance
Metric	Value
C++ Feature Extraction Latency	Sub-millisecond (O(1) per packet, Welford's online algorithm)
ML Inference Latency	< 2ms per flow (single model), < 5ms (stacked 3-model voting)
PBFT Consensus Time	< 500ms (5-node cluster, parallel broadcast)
End-to-End Alert Latency	< 1 second (capture → classify → commit)
Blockchain Block Size	1 alert per block (granular audit trail)
Byzantine Fault Tolerance	f=1 (tolerates 1 compromised node in 5-node cluster)
Feature Dimensionality	68 extracted → 63 selected (5 dropped by feature selection)
Flow Expiry Detection	5-second scan interval (ExpiryThread) + packet-driven triggers
Encryption	AES-256-GCM (inter-node) + ECDSA secp256k1 (signatures)
 
(Place the video here)
Conclusions / Future Scope
Conclusions
    1. Decentralization eliminates single-point-of-failure: By distributing the IDS across N independent nodes with PBFT consensus, the system remains operational and trustworthy even if up to f individual nodes are compromised.

    2. Dual-layer ML provides complete threat coverage: The combination of supervised ensemble models (for known signatures  — Cases 1, 2, 5) and unsupervised Isolation Forest anomaly detection (for zero-day threats — Cases 3, 4) ensures no category of attack can bypass the system entirely. The 5-case fusion engine provides graduated alerting from Critical to Low severity.

    3. Native C++ capture ensures zero packet loss: By implementing the flow extraction engine in C++17 with direct libpcap bindings, Welford's O(1) online statistics, and a dedicated ExpiryThread for idle flow detection, the system achieves sub-millisecond feature computation without the overhead of interpreted language runtimes or the JVM (which limits Java-based CICFlowMeter to ~100 Mbps).

    4. Blockchain immutability prevents evidence tampering: ECDSA-signed alerts committed through PBFT consensus with peer re-validation create a cryptographically verifiable audit trail that attackers cannot retroactively modify. On-chain metadata is separated from off-chain raw features for storage efficiency, with SQLite per-node databases providing local data sovereignty.

    5. Heterogeneous node configurations add diversity: Each Docker node runs a different combination of ML models (RF,        LGBM, XGB, Anomaly), preventing a single model vulnerability from compromising the entire network's detection capability. Node 3's stacked majority voting provides the strongest individual classification, while Node 4's anomaly-only configuration specializes in zero-day detection.

   6. End-to-end encryption secures the detection infrastructure: ECDH key exchange with AES-256-GCM authenticated encryption and ECDSA signature verification ensures that the PBFT consensus messages themselves cannot be intercepted, forged, or replayed by an attacker monitoring inter-node traffic.

Future Scope
    1. Deep Learning Integration: Incorporate transformer-based or 1D-CNN architectures for payload-level inspection alongside  the current flow-level statistical analysis, enabling detection of encrypted malware tunnels.

    2. Federated Learning: Enable nodes to collaboratively improve their local models by sharing gradient updates rather than raw  data, preserving privacy across organizational boundaries while continuously adapting to evolving threats.

    3. Smart Contract Enforcement: Extend the blockchain layer with programmable smart contracts that can automatically triggers network isolation (firewall rules) when consensus confirms a critical-severity alert, reducing human response latency from  minutes to milliseconds.

    4. Horizontal Scalability: Implement sharding or layer-2 protocols to scale the blockchain beyond the current PBFT limit of approximately 20 nodes while maintaining Byzantine fault tolerance. Explore HotStuff or Tendermint as next-generation consensus alternatives.

    5. Real-time Dashboard Enhancements: Expand the React/Vite monitoring dashboard with live attack visualizations (geographic origin mapping, attack correlation timeline), historical trend analysis, automated PDF report generation, and SIEM integration via syslog/CEF export.

   6. Adversarial ML Robustness: Investigate and defend against adversarial evasion attacks where an attacker crafts traffic that  is specifically designed to fool the machine learning classifiers while maintaining attack effectiveness.

References / Links
   1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion     Detection Using Machine Learning Techniques." International Conference on Information Systems Security and Privacy (ICISSP).

   2. Castro, M., & Liskov, B. (1999). "Practical Byzantine Fault Tolerance." Proceedings of the Third Symposium on Operating Systems Design and Implementation (OSDI).

   3. Liu, F. T., Ting, K. M., & Zhou, Z.-H. (2008). "Isolation Forest." Eighth IEEE International Conference on Data Mining.

   4. Ferrag, M. A., et al. (2020). "Deep Learning for Cyber Security Intrusion Detection: Approaches, Datasets, and Comparative Study." Journal of Information Security and Applications.

   5. Ke, G., et al. (2017). "LightGBM: A Highly Efficient Gradient Boosting Decision Tree." Advances in Neural Information Processing Systems (NeurIPS).

   6. Alexopoulos, N., et al. (2020). "Blockchain-based Intrusion Detection Systems: A Survey." ACM Computing Surveys.

   7. Chen, T., & Guestrin, C. (2016). "XGBoost: A Scalable Tree Boosting System." Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining

GitHub Repository: FusionIDS
​
