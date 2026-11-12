# Security Investigation Tool & Threat Detection Scripting Suite

An automated PowerShell-based security investigation and log analysis framework engineered to parse system logs, detect adversary techniques, cross-reference Indicators of Compromise (IoCs), and query external threat intelligence APIs. 

Developed as part of the **Advanced Scripting (COMP H2705)** module at **Technological University Dublin (TU Dublin)**.

---

## 🚀 Key Features

* **SSH Brute-Force Detection (`detect_bruteforce.ps1`)**: Parses authentication logs (`auth.log`) to identify and flag repeated failed login attempts and potential brute-force campaigns.
* **Indicator of Compromise (IoC) Matching (`detect_ioc.ps1`)**: Cross-references system logs (`auth.log` and `access.log`) against a curated threat list (`ioc.txt`) to surface known malicious IP addresses and web paths.
* **Suspicious PowerShell Execution Analysis (`detect_powershell.ps1`)**: Scans PowerShell execution logs (`powershell_log.txt`) for malicious cmdlet patterns and suspicious administrative behaviors.
* **Malicious IP Threat Intelligence Lookup (`detect_malicious.ps1`)**: Extracts high-frequency source IPs from web access logs and performs automated API queries to evaluate external threat posture.
* **Unified Orchestration & Reporting (`run.ps1`)**: Automatically chains all detection modules, computes aggregated risk ratings, and generates a structured, human-readable forensic summary (`investigation_report.txt`)[cite: 1].

---

## 🛠️ Project Architecture & Workflow

The suite is modularized into discrete PowerShell scripts controlled by a master orchestration script (`run.ps1`)[cite: 1]:

```text
├── ProjectDataset/
│   ├── auth.log
│   ├── access.log
│   ├── powershell_log.txt
│   └── ioc.txt
├── modules/
│   ├── detect_bruteforce.ps1
│   ├── detect_ioc.ps1
│   ├── detect_powershell.ps1
│   └── detect_malicious.ps1
├── run.ps1
└── investigation_report.txt  (Generated post-execution)
