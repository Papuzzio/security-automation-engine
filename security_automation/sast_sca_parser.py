import json
from pathlib import Path
import pandas as pd
from xml.etree import ElementTree as ET


def parse_sonar_report(path: Path) -> list[dict]:
    """
    Parse a simple SonarQube issues JSON export.

    Expected format (simplified):
    {
      "issues": [
        {
          "rule": "java:S1192",
          "severity": "MAJOR",
          "component": "myapp:src/file.py",
          "line": 42,
          "message": "Some issue message"
        },
        ...
      ]
    }
    """
    path = Path(path)
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    for issue in data.get("issues", []):
        findings.append(
            {
                "Source": "SAST",
                "Tool": "SonarQube",
                "Severity": issue.get("severity", ""),
                "Type": "Code",
                "File/Dependency": issue.get("component", ""),
                "Location": issue.get("line", ""),
                "Identifier": issue.get("rule", ""),
                "CVE": "",
                "Summary": issue.get("message", ""),
            }
        )
    return findings

def classify_owasp_top10(record: dict) -> str:
    """
    Conservative, rule-based OWASP Top 10 (2021) classification.
    - SCA findings are mapped to A06 (Vulnerable and Outdated Components).
    - SAST findings are mapped only when we are reasonably confident based on text.
    Anything that doesn't match stays blank so we never over-claim.
    """
    source = (record.get("Source") or "").upper()
    summary = (record.get("Summary") or "").lower()
    identifier = (record.get("Identifier") or "").lower()

    # All SCA = OWASP A06: Vulnerable and Outdated Components
    if source == "SCA":
        return "A06: Vulnerable and Outdated Components"

    # SAST rules: conservative keyword-based mapping

    # Injection patterns
    if "sql injection" in summary or "os command injection" in summary:
        return "A03: Injection"
    if "xss" in summary or "cross-site scripting" in summary:
        return "A03: Injection"

    # Auth / identity issues
    if "hard-coded credential" in summary or "hardcoded credential" in summary:
        return "A07: Identification and Authentication Failures"
    if "authentication" in summary or "login" in summary or "password" in summary:
        return "A07: Identification and Authentication Failures"

    # Access control / authorization
    if "authorization" in summary or "access control" in summary or "privilege escalation" in summary:
        return "A01: Broken Access Control"

    # Crypto / TLS
    if "encryption" in summary or "tls" in summary or "ssl" in summary or "certificate" in summary:
        return "A02: Cryptographic Failures"

    # Logging / monitoring
    if "logging" in summary or "audit" in summary or "monitoring" in summary:
        return "A09: Security Logging and Monitoring Failures"

    # Default: unknown / not mapped
    return ""
  
def parse_dependency_check_report(path: Path) -> list[dict]:
    """
    Parse an OWASP Dependency-Check XML report (simplified).

    Expected high-level structure:
    <analysis>
      <dependencies>
        <dependency>
          <fileName>Azure.Identity.dll</fileName>
          <vulnerabilities>
            <vulnerability>
              <name>CVE-2023-12345</name>
              <severity>HIGH</severity>
              <description>...</description>
              <cwe>CWE-79</cwe>
            </vulnerability>
          </vulnerabilities>
        </dependency>
      </dependencies>
    </analysis>
    """
    path = Path(path)
    tree = ET.parse(path)
    root = tree.getroot()

    ns = ""  # adjust if your XML has namespaces

    findings = []
    for dep in root.findall(".//dependency"):
        file_name_el = dep.find("fileName")
        file_name = file_name_el.text if file_name_el is not None else ""

        vulns = dep.findall(".//vulnerability")
        for v in vulns:
            cve_el = v.find("name")
            severity_el = v.find("severity")
            desc_el = v.find("description")
            cwe_el = v.find("cwe")

            findings.append(
                {
                    "Source": "SCA",
                    "Tool": "Dependency-Check",
                    "Severity": (severity_el.text if severity_el is not None else ""),
                    "Type": "Library",
                    "File/Dependency": file_name,
                    "Location": "",
                    "Identifier": (cwe_el.text if cwe_el is not None else ""),
                    "CVE": (cve_el.text if cve_el is not None else ""),
                    "Summary": (desc_el.text if desc_el is not None else "").strip(),
                }
            )

    return findings


def merge_findings(sast: list[dict], sca: list[dict]) -> pd.DataFrame:
    """
    Merge SAST + SCA findings into a single DataFrame and add OWASP Top 10 classification.
    """
    all_findings = sast + sca

    # Add OWASP Top 10 label to each record
    for rec in all_findings:
        rec["OWASP_Top10"] = classify_owasp_top10(rec)

    df = pd.DataFrame(all_findings)

    # Enforce a consistent column order
    cols = [
        "Source",
        "Tool",
        "Severity",
        "Type",
        "File/Dependency",
        "Location",
        "CVE",
        "Identifier",
        "Summary",
        "OWASP_Top10",
    ]
    for c in cols:
        if c not in df.columns:
            df[c] = ""
    df = df[cols]

    return df


def export_findings(df: pd.DataFrame, output_path: Path) -> None:
    """
    Export merged findings to Excel or CSV.
    """
    output_path = Path(output_path)
    if output_path.suffix.lower() == ".xlsx":
        df.to_excel(output_path, index=False)
    elif output_path.suffix.lower() == ".csv":
        df.to_csv(output_path, index=False)
    else:
        raise ValueError("Unsupported file format. Use .xlsx or .csv")


def main():
    """Local test runner for SAST/SCA parsing."""

    sonar_path = Path("sample_data/sonar_sast_sample.json")
    depcheck_path = Path("sample_data/dependency_check_sca.xml")
    output = Path("reports/sast_sca_findings.xlsx")

    sast_findings = parse_sonar_report(sonar_path)
    sca_findings = parse_dependency_check_report(depcheck_path)
    df = merge_findings(sast_findings, sca_findings)
    export_findings(df, output)

    print(f"[+] SAST/SCA report generated: {output}")


if __name__ == "__main__":
    main()
