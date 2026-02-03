# IoT-Scanner
A multi‑stage IoT network scanning and device‑response framework designed to discover, analyze, and eventually isolate IoT devices based on behavior, protocols, and risk level.

---

## 📌 Overview

**IoT‑Scanner** is an experimental tool that currently focuses on **network scanning only**.  
The idea behind the project is to build a flexible IoT security framework over time, starting with basic device discovery and expanding into deeper analysis and automated responses.

This project began as a personal technical experiment — not a formal research study — and it grows through trial, error, and continuous improvement.

---

## ⚠️ Project Status

The project is **not perfect**, still evolving, and may contain bugs, missing features, or non‑optimal logic.  
It should be considered a **work‑in‑progress**, not a finished or production‑ready tool.

At the moment, only the **network scanning phase** is implemented, including:

- ARP‑based device discovery  
- ICMP probing  
- Basic SNMP enumeration  
- MAC vendor lookup  

More advanced features will be added gradually.

---

## 🌐 Vision & Scope

IoT devices behave differently depending on vendor, firmware, communication style, and purpose.  
Because of this, the long‑term vision of IoT‑Scanner is to become a **general‑purpose IoT security engine** that adapts to each device individually.

The framework aims to eventually understand:

- normal vs abnormal behavior  
- device roles inside the network  
- communication patterns  
- risk levels  
- how each device should be handled  

This repository is only the **starting point** of a much larger idea.

---

## 🛡️ Isolation & Response Concept (Future Goal)

A major future direction of the project is **adaptive isolation**, where the tool may:

### Soft Isolation  
Restrict a suspicious device inside the same network while monitoring it.

### Hard Isolation  
Completely block or quarantine a device that shows dangerous or malicious behavior.

### Remediation Attempts  
When possible, the tool may try to:

- limit harmful traffic  
- recommend fixes  
- provide warnings  
- attempt basic automated responses  

These features are experimental and extremely challenging, but they represent the long‑term goal of the project.

---

## 🚀 Roadmap

### **Phase 1 — Network Scanning (Current)**
- ARP sweep  
- ICMP probing  
- Basic SNMP detection  
- MAC vendor classification  

### **Phase 2 — Device Fingerprinting**
- Protocol‑based fingerprinting  
- Port behavior analysis  
- OS and device‑type inference  

### **Phase 3 — Risk Scoring**
- Weak‑credential detection  
- Open‑service analysis  
- Behavior deviation detection  

### **Phase 4 — Isolation Engine**
- Soft isolation  
- Hard isolation  
- Automated response logic  

### **Phase 5 — Dashboard & Reporting**
- JSON/CSV export  
- Web dashboard  
- Real‑time monitoring  

---

## 🛠️ Technologies Used

- **C (GCC)**  
- **libpcap** for packet capture  
- **net‑snmp** for SNMP enumeration  
- **Raw sockets** for ARP/ICMP  
- **MAC vendor database parsing**  

---

## ⚖️ Legal Notice

All source code, structure, and implementation details in this repository are original work created by the author.  
While ideas cannot be copyrighted, the **actual code, logic, file structure, and documentation are protected intellectual property**.

You may view, use, or modify the code under the terms of the selected license, but **copying the project as‑is, redistributing it without attribution, or claiming ownership of the code is not permitted**.

This project is provided for educational and experimental purposes.

---

## 💬 Final Notes

This is only the beginning.  
The tool will grow, change, break, improve, and evolve — and that’s part of the journey.

Feedback and suggestions are always welcome.
