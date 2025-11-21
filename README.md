# Security Automation Engine

Python-based security automation engine for parsing SAST (SonarQube) and SCA (OWASP Dependency-Check) reports, merging them into a unified view, tagging findings with OWASP Top 10 categories, and exporting a clean Excel report for developers and security teams.

This is a personal learning and portfolio project focused on security automation, DevSecOps, and practical AppSec workflows. All sample data is synthetic and not tied to any real organization.

---

## Features

- ✅ Parse **SonarQube SAST** JSON issue reports
- ✅ Parse **OWASP Dependency-Check SCA** XML reports
- ✅ Normalize SAST + SCA into a **single unified schema**
- ✅ Add **OWASP Top 10 (2021)** classification (conservative rule-based mapping)
- ✅ Export results to **Excel (.xlsx)** or **CSV (.csv)**
- ✅ Ready for integration into CI/CD or security tooling

---

## Project Structure

```text
security-automation-engine/
├── security_automation/
│   └── sast_sca_parser.py      # Core parser + merge + export logic
│
├── sample_data/
│   ├── sonar_sast_sample.json  # Example SonarQube SAST export
│   └── dependency_check_sample.xml  # Example Dependency-Check SCA report
│
├── reports/
│   └── sast_sca_findings.xlsx  # Generated report (created at runtime)
│
├── README.md
└── requirements.txt            # Python dependencies