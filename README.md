# FusionIDS: Fusion-Based Blockchain IDS with ML Orchestration

## Aim

To design and implement a fully decentralized, real-time Intrusion Detection System (IDS) that addresses the critical vulnerabilities of traditional centralized IDS architectures — namely single points of failure and log tampering — by fusing high-throughput native packet capture, dual-layer machine learning (supervised + unsupervised), and cryptographically secured distributed ledger consensus, packaged as a production-ready Docker-orchestrated multi-node cluster.

---

## Introduction

Modern network infrastructures face increasingly sophisticated cyber threats ranging from known attack vectors such as Distributed Denial-of-Service (DDoS), Brute Force, and Botnet infiltration, to completely novel zero-day exploits with no prior signature.

Traditional centralized Intrusion Detection Systems, while effective at detecting known patterns, suffer from two fundamental weaknesses:

1. **Single Point of Failure**
   - A centralized IDS server, once compromised, renders the entire monitoring pipeline inoperable.
   - The attacker gains complete control over what is logged and what is silently discarded.

2. **Log Tampering**
   - Even if the IDS detects malicious activity before being neutralized, a sophisticated attacker can retroactively delete or modify the alert logs stored on the same centralized infrastructure, effectively erasing all evidence of the intrusion.

FusionIDS addresses both weaknesses through a three-tier architecture:

### Tier 1 — Native C++17 Flow Capturer

A high-performance packet capture engine built in C++17 that hooks directly into the network interface (`eth0`) via `libpcap`.

It assembles raw Ethernet frames into bidirectional network flows using a murmur-hash-based flow table keyed by the 5-tuple:

```text
(src_ip, dst_ip, src_port, dst_port, protocol)
