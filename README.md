

# **Fusion-Based Blockchain-Integrated Intrusion Detection System (IDS)**

### **A Machine-Learning–Driven, Blockchain-Backed Intrusion Detection Architecture with eBPF Telemetry**


## **📌 Overview**

This project proposes a next-generation **fusion-based Intrusion Detection System (IDS)** that combines:

* **Machine learning–based anomaly detection**
* **Signature-based detection**
* **Blockchain-backed distributed alert logging**
* **Fusion/ensemble decision-making**
* **Kernel-level observability and enforcement via eBPF/XDP**

The goal is to build an IDS architecture that is **tamper-proof, collaborative, accurate, and resilient**—capable of detecting both traditional and modern network intrusions.

---

## **🎯 Problem Motivation**

Traditional IDS systems often face:

* **High false positives**
* **Lack of trusted evidence sharing**
* **Weak collaboration across nodes**
* **Difficulty detecting distributed or evolving attacks**
* **Centralized points of failure**

By integrating **blockchain + ML + eBPF**, this project addresses:

* Evidence tamper-resistance
* Distributed decision-making
* High-fidelity, kernel-level telemetry
* Reduced false positives via ensemble learning
* Immutable audit trail for all alerts

---

## **🧠 Architecture Summary**

### **1. Local Node IDS**

Each node runs:

#### ✔ Signature-Based IDS

* Predefined rule-set matching
* Detects known attack patterns

#### ✔ ML-Based Anomaly Detector

* Trained on DARPA '99 / similar datasets
* Extracts network features
* Identifies abnormal patterns unseen in signature DB

#### ✔ eBPF Telemetry

* kprobes/tracepoints for syscall & socket-level activity
* XDP programs for real-time packet filtering
* User-space agent updates BPF maps with block decisions

---

### **2. Permissioned Blockchain Layer**

A lightweight blockchain is used as:

* **Immutable log** for IDS alerts and anomaly scores
* **Tamper-proof evidence store**
* **Shared knowledge base** across nodes
* **Model provenance and version tracking**

The ledger ensures all detection evidence remains:

* Trusted
* Auditable
* Distributed

---

### **3. Fusion ML Engine**

A central (or hierarchical) fusion system:

* Consumes blockchain-recorded alerts
* Performs **weighted voting / ensemble fusion**
* Produces a **consensus intrusion verdict**
* Reduces false positives dramatically
* Handles conflicting or noisy node-level outputs

Fusion can integrate:

* Signature outputs
* ML anomaly scores
* eBPF event counts
* Node-specific trust weights

---

## **📐 High-Level Workflow**

1. Traffic hits each node
2. Local IDS (signature + ML) produces alerts
3. eBPF collects kernel-level telemetry
4. Evidence is written to blockchain ledger
5. Fusion engine reads ledger entries
6. Weighted fusion → Final intrusion verdict
7. If malicious → eBPF map updated → XDP blocks packets

---

## **📊 Evaluation Focus**

* Detection Accuracy
* False Positive Rate (FPR)
* Precision/Recall
* Throughput impact of blockchain logging
* eBPF overhead & enforcement latency

Datasets used:

* **DARPA 1999 IDS Dataset**
* **MIT Lincoln Labs IDS Dataset**
* Additional modern datasets (if applicable)

---

## **🛠️ Tech Stack**

### **Machine Learning**

* Python
* scikit-learn / PyTorch / XGBoost
* Feature engineering for IDS datasets
* Ensemble/Voting classifiers

### **Blockchain**

* Lightweight permissioned blockchain
* Smart contracts for:

  * Alert logging
  * Model/version provenance
  * Evidence hashing

### **System Programming & Kernel Observability**

* **eBPF**

  * tracepoints
  * kprobes
  * BPF maps
* **XDP** for packet-level blocking
* libbpf
* User-space agents in Python/Go/C

---

## **✨ Summary**

This project integrates **ML, blockchain, and kernel-level observability** to create a **trustworthy, distributed, modern IDS** capable of resisting tampering, reducing false positives, and improving visibility across nodes.

The system combines traditional rule-based detection with ML anomaly scoring and aggregates decisions through an immutable ledger for collaborative, auditable detection.

---
