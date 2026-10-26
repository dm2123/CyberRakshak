"""Scan reporters - JSON, text, and PDF output for CyberRakshak results."""

import json
import os
from datetime import datetime


class Reporter:
    def __init__(self, target):
        self.target = target
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def build_data(self, open_ports=None, udp_results=None, services=None,
                   tls_findings=None, tls_info=None, vuln_hints=None,
                   web_findings=None, web_info=None):
        """Assemble a single result dict from all scan stages."""
        return {
            "tool": "CyberRakshak",
            "version": "0.3.0",
            "tagline": "Hacker se pehle - CyberRakshak!",
            "target": self.target,
            "scan_time": self.timestamp,
            "open_tcp_ports": open_ports or [],
            "udp_results": [{"port": p, "state": s} for p, s in (udp_results or [])],
            "services": services or [],
            "tls_findings": tls_findings or [],
            "tls_info": tls_info or {},
            "web_findings": web_findings or [],
            "web_info": web_info or {},
            "vulnerability_hints": vuln_hints or [],
        }

    @staticmethod
    def _finding_headline(f):
        """One-line summary of a finding dict (TLS or Web).

        The v0.3 check ID / CVE keys are shown only when present, so
        v0.2-shaped findings render exactly as before.
        """
        head = f"[{f['severity']}] {f['issue']}"
        if f.get("check"):
            head += f" [{f['check']}]"
        if f.get("cve"):
            head += f" ({f['cve']})"
        return head

    @staticmethod
    def _hint_headline(h):
        """One-line summary of a vulnerability hint (CVE shown if known)."""
        head = (f"[{h['severity']}] Port {h['port']}: "
                f"{h['product']} {h['detected_version']}")
        if h.get("cve"):
            head += f" ({h['cve']})"
        return head

    # ---------- JSON ----------
    def to_json(self, data, path):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        return path

    # ---------- Plain text ----------
    def to_text(self, data, path):
        lines = []
        lines.append("=" * 60)
        lines.append("  CYBERRAKSHAK SCAN REPORT v0.3.0")
        lines.append(f"  Target    : {data['target']}")
        lines.append(f"  Scan time : {data['scan_time']}")
        lines.append("=" * 60)
        lines.append("")

        lines.append("[*] OPEN TCP PORTS")
        if data["open_tcp_ports"]:
            for p in data["open_tcp_ports"]:
                lines.append(f"    {p}/tcp open")
        else:
            lines.append("    (none found)")
        lines.append("")

        if data["udp_results"]:
            lines.append("[*] UDP PORTS")
            for u in data["udp_results"]:
                lines.append(f"    {u['port']}/udp {u['state']}")
            lines.append("")

        lines.append("[*] DETECTED SERVICES")
        if data["services"]:
            for s in data["services"]:
                ver = f" {s['version']}" if s.get("version") else ""
                lines.append(f"    Port {s['port']}: {s['service']}{ver}")
                if s.get("banner"):
                    lines.append(f"      banner: {s['banner'][:80]}")
        else:
            lines.append("    (no service detection run)")
        lines.append("")

        lines.append("[*] TLS AUDIT FINDINGS")
        if data["tls_findings"]:
            for f in data["tls_findings"]:
                lines.append(f"    {self._finding_headline(f)}")
                lines.append(f"      -> {f['detail']}")
        else:
            lines.append("    (no TLS issues found / not audited)")
        lines.append("")

        # v0.3: Web section appears only when the web audit produced
        # findings, so plain port-scan reports stay identical to v0.2.
        if data.get("web_findings"):
            lines.append("[*] WEB FINDINGS")
            for f in data["web_findings"]:
                lines.append(f"    {self._finding_headline(f)}")
                lines.append(f"      -> {f['detail']}")
            lines.append("")

        lines.append("[*] VULNERABILITY HINTS (defensive)")
        if data["vulnerability_hints"]:
            for h in data["vulnerability_hints"]:
                lines.append(f"    {self._hint_headline(h)}")
                lines.append(f"      -> {h['guidance']}")
        else:
            lines.append("    (none)")
        lines.append("")
        lines.append("=" * 60)
        lines.append("  Defensive note: scan only systems you own or are")
        lines.append("  explicitly authorized to test.")
        lines.append("=" * 60)

        with open(path, "w") as f:
            f.write("\n".join(lines))
        return path

    # ---------- PDF ----------
    def to_pdf(self, data, path):
        try:
            from fpdf import FPDF
        except ImportError:
            raise RuntimeError("fpdf2 is required for PDF reports: pip install fpdf2")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, "CyberRakshak Scan Report", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, "'Hacker se pehle - CyberRakshak!'", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 7, f"Target: {data['target']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, f"Scan time: {data['scan_time']}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 7, "Version: 0.3.0 (defensive scan - authorized targets only)", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        def section(title):
            pdf.set_font("Helvetica", "B", 13)
            pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 10)

        def bullet(text):
            pdf.multi_cell(0, 6, f"  - {text}", new_x="LMARGIN", new_y="NEXT")

        section("Open TCP Ports")
        if data["open_tcp_ports"]:
            for p in data["open_tcp_ports"]:
                bullet(f"{p}/tcp open")
        else:
            bullet("(none found)")

        if data["udp_results"]:
            section("UDP Ports")
            for u in data["udp_results"]:
                bullet(f"{u['port']}/udp {u['state']}")

        section("Detected Services")
        if data["services"]:
            for s in data["services"]:
                ver = f" {s['version']}" if s.get("version") else ""
                bullet(f"Port {s['port']}: {s['service']}{ver}")
        else:
            bullet("(no service detection run)")

        section("TLS Audit Findings")
        if data["tls_findings"]:
            for f in data["tls_findings"]:
                pdf.set_font("Helvetica", "B", 10)
                pdf.multi_cell(0, 6, f"  {self._finding_headline(f)}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(0, 6, f"      {f['detail']}", new_x="LMARGIN", new_y="NEXT")
        else:
            bullet("(no TLS issues found / not audited)")

        # v0.3: Web section only when web findings exist (as in text).
        if data.get("web_findings"):
            section("Web Findings")
            for f in data["web_findings"]:
                pdf.set_font("Helvetica", "B", 10)
                pdf.multi_cell(0, 6, f"  {self._finding_headline(f)}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(0, 6, f"      {f['detail']}", new_x="LMARGIN", new_y="NEXT")

        section("Vulnerability Hints (defensive)")
        if data["vulnerability_hints"]:
            for h in data["vulnerability_hints"]:
                pdf.set_font("Helvetica", "B", 10)
                pdf.multi_cell(0, 6, f"  {self._hint_headline(h)}", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 10)
                pdf.multi_cell(0, 6, f"      {h['guidance']}", new_x="LMARGIN", new_y="NEXT")
        else:
            bullet("(none)")

        pdf.ln(4)
        pdf.set_font("Helvetica", "I", 9)
        pdf.multi_cell(0, 6, "Defensive note: scan only systems you own or are "
                             "explicitly authorized to test.", new_x="LMARGIN", new_y="NEXT")

        pdf.output(path)
        return path

    def save(self, data, path):
        """Save in the format implied by the file extension."""
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            return self.to_json(data, path)
        if ext == ".pdf":
            return self.to_pdf(data, path)
        return self.to_text(data, path)
