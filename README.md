# Cross-Layer Fingerprint Impersonation Detector

A network security tool that detects fingerprint impersonation by analyzing and correlating **TLS, TCP, and HTTP fingerprints** across the same network connection.

Instead of relying on a single fingerprint or a predefined blocklist, the system checks whether the identities reported by different network layers are **consistent with each other**.

---

## Overview

Attackers and automated tools can make their network traffic look like it comes from a legitimate browser by copying browser characteristics such as TLS fingerprints and HTTP headers.

For example, a spoofing tool may claim to be **Google Chrome on Windows** at the TLS layer while its TCP behavior resembles a **Linux system** and its HTTP headers resemble a **Python-based client**.

A single fingerprint may not reveal this deception.

This project addresses the problem using **cross-layer fingerprint consistency**.

The system extracts:

* **JA4** → TLS/client fingerprint
* **JA4T** → TCP/network-stack fingerprint
* **JA4H** → HTTP fingerprint

It then compares the identities represented by these fingerprints and flags suspicious inconsistencies.

---

## Problem Statement

Traditional fingerprint-based detection commonly asks:

> "Is this fingerprint known to be malicious?"

This approach can struggle with new or previously unseen spoofing tools.

Our approach instead asks:

> **"Do the fingerprints from this connection agree with each other?"**

If the TLS layer claims to represent Chrome on Windows, but the TCP layer behaves like a Linux system, the connection can be flagged even if the individual fingerprints are not present on a blacklist.

---

## Core Concept

The detector works across three network layers:

```text
             Network Traffic
                    │
                    ▼
            ┌───────────────┐
            │ Traffic       │
            │ Capture       │
            └───────┬───────┘
                    │
                    ▼
       ┌─────────────────────────┐
       │ Fingerprint Extraction  │
       └────────────┬────────────┘
                    │
          ┌─────────┼─────────┐
          ▼         ▼         ▼
        JA4       JA4T      JA4H
        TLS       TCP       HTTP
          │         │         │
          └─────────┼─────────┘
                    ▼
          ┌───────────────────┐
          │ Consistency       │
          │ Engine             │
          └─────────┬─────────┘
                    │
             ┌──────┴──────┐
             ▼             ▼
        CONSISTENT       FLAGGED
                            │
                            ▼
                    Explanation Layer
                            │
                            ▼
                    Audit / CSV Log
```

---

## Example

### Legitimate Browser

```text
TLS  → Chrome / Windows
TCP  → Windows network stack
HTTP → Chrome headers

        ↓

Consistent Identity
        ↓

     ✅ NORMAL
```

### Spoofed Client

```text
TLS  → Chrome / Windows
TCP  → Linux network stack
HTTP → Python client

        ↓

Identity Mismatch
        ↓

     🚨 FLAGGED
```

The important point is that the system does not need to identify the exact attack tool. It detects the **inconsistency between network layers**.

---

## Features

### 1. Network Traffic Capture

Supports processing network traffic from:

* Live network interfaces
* PCAP files

The capture layer prepares network traffic for flow-based analysis.

---

### 2. Cross-Layer Fingerprinting

The system extracts multiple fingerprints from the same connection:

| Fingerprint | Layer | Purpose                               |
| ----------- | ----- | ------------------------------------- |
| JA4         | TLS   | Identifies TLS/client characteristics |
| JA4T        | TCP   | Represents TCP/network-stack behavior |
| JA4H        | HTTP  | Represents HTTP/client behavior       |

---

### 3. Fingerprint Consistency Detection

The system compares the identities represented by the three fingerprint layers.

It can identify situations such as:

```text
TLS identity  ≠ TCP identity
TLS identity  ≠ HTTP identity
TCP identity  ≠ HTTP identity
```

A mismatch can result in the flow being flagged for further investigation.

---

### 4. Reference Identity Table

A small reference table is used to associate fingerprints with expected client or operating-system characteristics.

The table is designed around plausible TCP/OS behavior and known client characteristics.

---

### 5. Explainable Detection

When a flow is flagged, the system generates a human-readable explanation.

Example:

```text
FLAGGED

Reason:
TLS fingerprint indicates Chrome/Windows,
but TCP fingerprint indicates a Linux network stack.
```

An LLM-based explanation layer can be used to convert technical detection results into plain English.

---

### 6. Audit Logging

Each analyzed flow can be recorded in an audit log.

The audit log is stored in **CSV format**, making it easy to:

* Review detected traffic
* Track previous analysis
* Filter suspicious connections
* Analyze results
* Reuse the collected data as a dataset

Example fields include:

```text
timestamp
flow_id
source_ip
source_port
destination_ip
destination_port
protocol
ja4
ja4t
ja4h
tls_identity
tcp_identity
http_identity
verdict
mismatch_layer
explanation
actual_label
correct
```

---

### 7. Accuracy & Evaluation

The system supports evaluation against traffic with known ground-truth labels.

The following metrics can be calculated:

* Accuracy
* Precision
* Recall
* F1 Score
* True Positives (TP)
* True Negatives (TN)
* False Positives (FP)
* False Negatives (FN)
* Confusion Matrix

This allows the detector's performance to be measured rather than relying only on individual detection examples.

---

### 8. Dataset Generation

The audit CSV can also serve as a structured dataset.

The dataset can contain both:

```text
Predicted Label
Actual Label
```

This allows the collected traffic to be used for:

* System evaluation
* Accuracy measurement
* Future experimentation
* Statistical analysis
* Testing different detection rules

---

## System Components

The project consists of the following major components:

### Capture Layer

Responsible for obtaining network traffic from live interfaces or PCAP files.

Possible technologies:

* PyShark
* Scapy

### Fingerprint Extractor

Extracts:

```text
JA4
JA4T
JA4H
```

from network flows.

### Reference Table

Maps fingerprint characteristics to expected client/OS identities.

### Consistency Engine

The core detection component.

It compares the fingerprints from different network layers and determines whether they represent a consistent identity.

### Test Data Generator

Provides traffic examples for testing the detector.

The project can use:

* Real browser traffic
* Spoofed browser traffic
* curl-impersonate examples

No malware is required for testing.

### Explanation Layer

Converts technical detection results into understandable explanations.

### Audit & Evaluation Layer

Stores analysis results and calculates detection performance using the generated CSV dataset.

---

## Main Functions

The planned system is organized around the following functions.

### Traffic Capture

```text
capture_live_traffic()
load_pcap()
create_flows()
```

### Fingerprint Extraction

```text
extract_ja4()
extract_ja4t()
extract_ja4h()
extract_all_fingerprints()
```

### Identity & Reference

```text
load_reference_table()
lookup_tls_identity()
lookup_tcp_identity()
lookup_http_identity()
```

### Detection

```text
compare_fingerprints()
detect_mismatch()
generate_verdict()
```

### Explanation

```text
generate_explanation()
explain_flag_with_llm()
```

### Audit Logging

```text
create_audit_record()
write_audit_log()
load_audit_log()
export_audit_log()
search_audit_logs()
```

### Evaluation

```text
assign_actual_label()
calculate_accuracy()
calculate_precision()
calculate_recall()
calculate_f1_score()
generate_confusion_matrix()
```

### Dataset Management

```text
build_dataset_from_logs()
validate_dataset()
split_dataset()
export_dataset()
```

### Reporting

```text
generate_report()
generate_flow_report()
generate_statistics()
```

---

## Detection Output

For every analyzed flow, the system can produce a result similar to:

```text
Flow ID: 1024

JA4:  Chrome/Windows
JA4T: Windows
JA4H: Chrome

Verdict: CONSISTENT
Status: NORMAL
```

or:

```text
Flow ID: 1025

JA4:  Chrome/Windows
JA4T: Linux
JA4H: Python

Verdict: FLAGGED
Mismatch: TCP + HTTP
Status: SUSPICIOUS

Explanation:
The TLS fingerprint claims to represent Chrome on Windows,
while TCP and HTTP characteristics indicate a different client
environment.
```

---

## Expected Project Structure

```text
Cross-Layer-Fingerprint-Impersonation-Detector/
│
├── capture/
│   ├── live_capture.py
│   └── pcap_loader.py
│
├── fingerprint/
│   └── extractor.py
│
├── reference/
│   └── reference_table.csv
│
├── detection/
│   └── consistency_engine.py
│
├── explanation/
│   └── llm_explainer.py
│
├── logging/
│   └── audit_logger.py
│
├── evaluation/
│   ├── metrics.py
│   └── confusion_matrix.py
│
├── dataset/
│   └── dataset_builder.py
│
├── reports/
│   └── report_generator.py
│
├── data/
│   ├── pcaps/
│   └── audit_logs/
│
├── requirements.txt
└── README.md
```

*The exact directory structure may change as implementation progresses.*

---

## Testing Approach

The project can be tested using two main categories of traffic.

### Normal Traffic

Real browser traffic is captured and analyzed.

Expected result:

```text
Chrome TLS
    +
Windows TCP
    +
Chrome HTTP

        ↓

CONSISTENT ✅
```

### Spoofed Traffic

Traffic generated using browser-impersonation techniques is analyzed.

Expected result:

```text
Chrome TLS
    +
Different TCP behavior
    +
Different HTTP behavior

        ↓

FLAGGED 🚨
```

The results are then stored in the audit CSV for evaluation.

---

## Evaluation Workflow

```text
Generate / Capture Traffic
          ↓
     Analyze Flows
          ↓
 Extract JA4 / JA4T / JA4H
          ↓
   Generate Prediction
          ↓
 Compare With Actual Label
          ↓
     Store in CSV
          ↓
 Calculate Metrics
          ↓
 Accuracy / Precision / Recall / F1
```

---

## Security Use Case

The detector is intended to help identify network clients that attempt to hide their real identity by impersonating another client or operating system.

Potential applications include:

* Network monitoring
* Threat detection
* Security research
* Bot detection
* Scraper detection
* C2 traffic analysis
* Browser impersonation detection
* Network forensics

---

## Project Status

**Academic / Research Project**

This project is being developed as a Network Security semester project.

The current focus is on:

* Cross-layer fingerprint extraction
* Fingerprint consistency analysis
* Spoofing detection
* Explainable detection results
* Audit logging
* CSV dataset generation
* Accuracy and performance evaluation

---

## Limitations

Cross-layer inconsistency does not automatically mean that traffic is malicious.

Legitimate situations such as proxies, VPNs, NAT, unusual network configurations, custom clients, and privacy tools may produce unexpected combinations of fingerprints.

Therefore, a flagged connection should be treated as **suspicious and requiring further investigation**, rather than automatically classified as malicious.

---

## Project Goal

The main goal of this project is to demonstrate that combining multiple network fingerprinting layers can provide stronger detection of identity impersonation than relying on a single fingerprint.

The central idea is:

> **Don't just ask whether a fingerprint is known. Ask whether the fingerprints agree with each other.**

---

## Project

**Cross-Layer Fingerprint Impersonation Detector**

**Domain:** Network Security / Cybersecurity

**Purpose:** Academic Semester Project

---

## Disclaimer

This project is developed for **educational, research, and authorized security-testing purposes**.

Only analyze network traffic that you own or have explicit permission to inspect.
