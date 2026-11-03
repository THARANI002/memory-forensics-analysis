"""
Enterprise Memory Forensics Platform - Reporting Engine
========================================================
Generates comprehensive forensic reports in PDF, HTML, and JSON formats.
"""

import html as html_module
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class ReportData:
    """Data structure for report generation."""
    title: str = "Memory Forensics Report"
    case_number: str = ""
    analyst: str = ""
    investigation_date: str = ""
    snapshot_id: str = ""
    baseline_id: str = ""
    
    # Scores
    threat_score: float = 0.0
    confidence_score: float = 0.0
    memory_health_score: float = 100.0
    
    # Verdict
    executive_verdict: str = "CLEAN"
    verdict_description: str = "No significant threats detected."
    
    # Most dangerous
    most_dangerous_process: str = "N/A"
    most_dangerous_ip: str = "N/A"
    top_mitre_technique: str = "N/A"
    
    # Counts
    total_threats: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_iocs: int = 0
    
    # Sections
    executive_summary: str = ""
    threat_findings: List[Dict] = field(default_factory=list)
    ioc_list: List[Dict] = field(default_factory=list)
    mitre_mapping: List[Dict] = field(default_factory=list)
    timeline_summary: Dict = field(default_factory=dict)
    comparison_result: Dict = field(default_factory=dict)
    process_tree_summary: Dict = field(default_factory=dict)
    detection_results: List[Dict] = field(default_factory=list)
    engine_results: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return asdict(self)


class ReportEngine:
    """
    Forensic Report Generation Engine.
    
    Supports:
    - PDF reports (via ReportLab)
    - HTML reports
    - JSON reports
    """
    
    def __init__(self, output_dir: Optional[str] = None):
        if output_dir is None:
            from config.settings import REPORTS_DIR
            output_dir = str(REPORTS_DIR)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _esc(value) -> str:
        """HTML-escape a value to prevent XSS injection in reports."""
        return html_module.escape(str(value) if value is not None else "")
    
    def generate_report(self, data: ReportData, format: str = "all") -> Dict[str, str]:
        """
        Generate report in specified format(s).
        
        Args:
            data: ReportData object with all findings
            format: 'pdf', 'html', 'json', or 'all'
        
        Returns:
            Dict mapping format to file path
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        generated_files = {}
        
        if format in ("json", "all"):
            path = self.output_dir / f"report_{timestamp}.json"
            self._generate_json(data, str(path))
            generated_files["json"] = str(path)
        
        if format in ("html", "all"):
            path = self.output_dir / f"report_{timestamp}.html"
            self._generate_html(data, str(path))
            generated_files["html"] = str(path)
        
        if format in ("pdf", "all"):
            path = self.output_dir / f"report_{timestamp}.pdf"
            self._generate_pdf(data, str(path))
            generated_files["pdf"] = str(path)
        
        return generated_files
    
    def _generate_json(self, data: ReportData, output_path: str) -> None:
        """Generate JSON report."""
        report = {
            "report_metadata": {
                "title": data.title,
                "case_number": data.case_number,
                "analyst": data.analyst,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "investigation_date": data.investigation_date,
                "version": "1.0",
                "format": "json"
            },
            "scores": {
                "threat_score": data.threat_score,
                "confidence_score": data.confidence_score,
                "memory_health_score": data.memory_health_score,
            },
            "verdict": {
                "executive_verdict": data.executive_verdict,
                "description": data.verdict_description,
                "most_dangerous_process": data.most_dangerous_process,
                "most_dangerous_ip": data.most_dangerous_ip,
                "top_mitre_technique": data.top_mitre_technique,
            },
            "summary": {
                "total_threats": data.total_threats,
                "critical": data.critical_count,
                "high": data.high_count,
                "medium": data.medium_count,
                "low": data.low_count,
                "total_iocs": data.total_iocs,
            },
            "executive_summary": data.executive_summary,
            "threat_findings": data.threat_findings,
            "iocs": data.ioc_list,
            "mitre_mapping": data.mitre_mapping,
            "timeline": data.timeline_summary,
            "memory_comparison": data.comparison_result,
            "process_tree": data.process_tree_summary,
            "detection_results": data.detection_results,
            "engine_results": data.engine_results,
            "recommendations": data.recommendations,
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _generate_html(self, data: ReportData, output_path: str) -> None:
        """Generate HTML report with all user-controlled values HTML-escaped."""
        e = self._esc  # shorthand

        # Safe CSS class for verdict (only allow known safe class names)
        verdict_upper = data.executive_verdict.upper()
        _safe_verdict_classes = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL", "CLEAN"}
        verdict_css = verdict_upper.lower().replace(" ", "-") if verdict_upper in _safe_verdict_classes else "clean"

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{e(data.title)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f1923;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{
            background: linear-gradient(135deg, #1a2a3a 0%, #0d1b2a 100%);
            border: 1px solid #2a4a6f;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            color: #00d4ff;
            font-size: 2em;
            margin-bottom: 10px;
        }}
        .meta {{ color: #8899aa; font-size: 0.9em; }}
        .meta span {{ margin-right: 20px; }}
        
        .scores-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }}
        .score-card {{
            background: #1a2a3a;
            border: 1px solid #2a4a6f;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .score-label {{ color: #8899aa; font-size: 0.85em; text-transform: uppercase; }}
        .score-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .score-critical {{ color: #ff4444; }}
        .score-high {{ color: #ff8800; }}
        .score-medium {{ color: #ffcc00; }}
        .score-low {{ color: #00cc66; }}
        .score-clean {{ color: #00ddff; }}
        
        .section {{
            background: #1a2a3a;
            border: 1px solid #2a4a6f;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            color: #00d4ff;
            font-size: 1.3em;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #2a4a6f;
        }}
        
        .verdict {{
            padding: 15px 20px;
            border-radius: 8px;
            font-size: 1.2em;
            font-weight: bold;
            text-align: center;
            margin-bottom: 15px;
        }}
        .verdict-critical {{ background: rgba(255,68,68,0.2); border: 1px solid #ff4444; color: #ff4444; }}
        .verdict-high {{ background: rgba(255,136,0,0.2); border: 1px solid #ff8800; color: #ff8800; }}
        .verdict-medium {{ background: rgba(255,204,0,0.2); border: 1px solid #ffcc00; color: #ffcc00; }}
        .verdict-low {{ background: rgba(0,204,102,0.2); border: 1px solid #00cc66; color: #00cc66; }}
        .verdict-clean {{ background: rgba(0,221,255,0.2); border: 1px solid #00ddff; color: #00ddff; }}
        
        .finding {{
            background: #0f1923;
            border-left: 4px solid #2a4a6f;
            border-radius: 0 6px 6px 0;
            padding: 15px;
            margin-bottom: 10px;
        }}
        .finding-critical {{ border-left-color: #ff4444; }}
        .finding-high {{ border-left-color: #ff8800; }}
        .finding-medium {{ border-left-color: #ffcc00; }}
        .finding-low {{ border-left-color: #00cc66; }}
        
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .finding-title {{ font-weight: bold; color: #ffffff; }}
        .finding-severity {{
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .sev-critical {{ background: #ff4444; color: white; }}
        .sev-high {{ background: #ff8800; color: white; }}
        .sev-medium {{ background: #ffcc00; color: black; }}
        .sev-low {{ background: #00cc66; color: white; }}
        
        .ioc-table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
        }}
        .ioc-table th {{
            background: #0d1b2a;
            color: #00d4ff;
            padding: 10px;
            text-align: left;
            font-size: 0.85em;
            text-transform: uppercase;
        }}
        .ioc-table td {{
            padding: 10px;
            border-bottom: 1px solid #2a4a6f;
            font-size: 0.9em;
        }}
        .ioc-table tr:hover {{ background: rgba(0,212,255,0.05); }}
        
        .recommendation {{
            background: #0f1923;
            border: 1px solid #2a4a6f;
            border-radius: 6px;
            padding: 12px 15px;
            margin-bottom: 8px;
        }}
        .recommendation::before {{
            content: "➤";
            color: #00d4ff;
            margin-right: 10px;
        }}
        
        .mitre-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
            gap: 8px;
            margin-top: 10px;
        }}
        .mitre-item {{
            background: #0f1923;
            border: 1px solid #2a4a6f;
            border-radius: 6px;
            padding: 10px;
            text-align: center;
            font-size: 0.85em;
        }}
        .mitre-id {{ color: #00d4ff; font-weight: bold; }}
        .mitre-name {{ color: #8899aa; margin-top: 4px; }}
        
        .footer {{
            text-align: center;
            color: #8899aa;
            padding: 20px;
            font-size: 0.85em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>{e(data.title)}</h1>
            <div class="meta">
                <span>Case: {e(data.case_number or 'N/A')}</span>
                <span>Analyst: {e(data.analyst or 'N/A')}</span>
                <span>Date: {e(data.investigation_date or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M'))}</span>
                <span>Snapshot: {e(data.snapshot_id or 'N/A')}</span>
            </div>
        </div>
        
        <!-- Scores -->
        <div class="scores-grid">
            <div class="score-card">
                <div class="score-label">Threat Score</div>
                <div class="score-value {self._score_class(data.threat_score)}">{data.threat_score:.1f}</div>
            </div>
            <div class="score-card">
                <div class="score-label">Confidence</div>
                <div class="score-value {self._score_class(data.confidence_score)}">{data.confidence_score:.1f}</div>
            </div>
            <div class="score-card">
                <div class="score-label">Memory Health</div>
                <div class="score-value {self._health_class(data.memory_health_score)}">{data.memory_health_score:.1f}</div>
            </div>
        </div>
        
        <!-- Verdict -->
        <div class="section">
            <h2>Executive Verdict</h2>
            <div class="verdict verdict-{verdict_css}">
                {e(data.executive_verdict)}
            </div>
            <p>{e(data.verdict_description)}</p>
            <div style="margin-top: 15px;">
                <strong>Most Dangerous Process:</strong> {e(data.most_dangerous_process)}<br>
                <strong>Most Dangerous IP:</strong> {e(data.most_dangerous_ip)}<br>
                <strong>Top MITRE Technique:</strong> {e(data.top_mitre_technique)}
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <p>{e(data.executive_summary or 'No summary available.')}</p>
            <div style="margin-top: 15px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; text-align: center;">
                <div><span style="color: #ff4444; font-size: 1.5em; font-weight: bold;">{data.critical_count}</span><br><span style="color: #8899aa; font-size: 0.85em;">Critical</span></div>
                <div><span style="color: #ff8800; font-size: 1.5em; font-weight: bold;">{data.high_count}</span><br><span style="color: #8899aa; font-size: 0.85em;">High</span></div>
                <div><span style="color: #ffcc00; font-size: 1.5em; font-weight: bold;">{data.medium_count}</span><br><span style="color: #8899aa; font-size: 0.85em;">Medium</span></div>
                <div><span style="color: #00cc66; font-size: 1.5em; font-weight: bold;">{data.low_count}</span><br><span style="color: #8899aa; font-size: 0.85em;">Low</span></div>
            </div>
        </div>
"""

        # Threat Findings
        if data.threat_findings:
            html_doc += """
        <div class="section">
            <h2>Threat Findings</h2>
"""
            for finding in data.threat_findings[:50]:  # Limit to 50
                sev_raw = finding.get("severity", "medium").lower()
                _safe_sevs = {"critical", "high", "medium", "low"}
                sev = sev_raw if sev_raw in _safe_sevs else "medium"
                html_doc += f"""
            <div class="finding finding-{sev}">
                <div class="finding-header">
                    <span class="finding-title">{e(finding.get("title", "Unknown"))}</span>
                    <span class="finding-severity sev-{sev}">{e(sev.upper())}</span>
                </div>
                <p>{e(finding.get("description", ""))}</p>
                <div style="color: #8899aa; font-size: 0.85em; margin-top: 5px;">
                    Engine: {e(finding.get("engine", "Unknown"))} | 
                    Confidence: {finding.get("confidence", 0):.1f}%
                </div>
            </div>
"""
            html_doc += "        </div>"

        # IOCs
        if data.ioc_list:
            html_doc += """
        <div class="section">
            <h2>Indicators of Compromise</h2>
            <table class="ioc-table">
                <thead>
                    <tr><th>Type</th><th>Value</th><th>Confidence</th><th>Source</th></tr>
                </thead>
                <tbody>
"""
            for ioc in data.ioc_list[:100]:
                html_doc += f"""
                    <tr>
                        <td>{e(ioc.get("type", ""))}</td>
                        <td style="font-family: monospace;">{e(ioc.get("value", ""))}</td>
                        <td>{ioc.get("confidence", 0):.1f}%</td>
                        <td>{e(ioc.get("source", ""))}</td>
                    </tr>
"""
            html_doc += """
                </tbody>
            </table>
        </div>
"""

        # MITRE Mapping
        if data.mitre_mapping:
            html_doc += """
        <div class="section">
            <h2>MITRE ATT&amp;CK Mapping</h2>
            <div class="mitre-grid">
"""
            seen_techs = set()
            for mapping in data.mitre_mapping:
                tech_id = mapping.get("technique_id", "")
                if tech_id not in seen_techs:
                    seen_techs.add(tech_id)
                    html_doc += f"""
                <div class="mitre-item">
                    <div class="mitre-id">{e(tech_id)}</div>
                    <div class="mitre-name">{e(mapping.get("technique_name", ""))}</div>
                </div>
"""
            html_doc += """
            </div>
        </div>
"""

        # Recommendations
        if data.recommendations:
            html_doc += """
        <div class="section">
            <h2>Recommendations</h2>
"""
            for rec in data.recommendations:
                html_doc += f"""
            <div class="recommendation">{e(rec)}</div>
"""
            html_doc += "        </div>"

        html_doc += """
        <div class="footer">
            <p>Generated by Enterprise Memory Forensics Platform</p>
            <p>""" + html_module.escape(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")) + """</p>
        </div>
    </div>
</body>
</html>"""

        with open(output_path, 'w') as f:
            f.write(html_doc)

    def _generate_pdf(self, data: ReportData, output_path: str) -> None:
        """Generate PDF report."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak, ListFlowable, ListItem
            )
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            
            doc = SimpleDocTemplate(output_path, pagesize=letter,
                                    rightMargin=72, leftMargin=72,
                                    topMargin=72, bottomMargin=18)
            
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a5276'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            story.append(Paragraph(html_module.escape(data.title or ""), title_style))
            story.append(Spacer(1, 20))
            
            # Metadata table
            meta_data = [
                ['Case Number:', data.case_number or 'N/A'],
                ['Analyst:', data.analyst or 'N/A'],
                ['Date:', data.investigation_date or datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')],
                ['Snapshot ID:', data.snapshot_id or 'N/A'],
            ]
            meta_table = Table(meta_data, colWidths=[2*inch, 4*inch])
            meta_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ]))
            story.append(meta_table)
            story.append(Spacer(1, 30))
            
            # Scores
            story.append(Paragraph("Risk Scores", styles['Heading2']))
            scores_data = [
                ['Threat Score', 'Confidence Score', 'Memory Health'],
                [f"{data.threat_score:.1f}", f"{data.confidence_score:.1f}", f"{data.memory_health_score:.1f}"],
            ]
            scores_table = Table(scores_data, colWidths=[2*inch, 2*inch, 2*inch])
            scores_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('FONTSIZE', (0, 1), (-1, -1), 18),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            story.append(scores_table)
            story.append(Spacer(1, 20))
            
            # Verdict
            verdict_style = ParagraphStyle(
                'Verdict',
                parent=styles['Normal'],
                fontSize=16,
                textColor=self._get_verdict_color(data.executive_verdict),
                alignment=TA_CENTER,
                spaceAfter=10,
            )
            story.append(Paragraph("Verdict: " + html_module.escape(data.executive_verdict or ""), verdict_style))
            story.append(Paragraph(html_module.escape(data.verdict_description or ""), styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            story.append(Paragraph(html_module.escape(data.executive_summary or "No summary available."), styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Threat counts
            counts_data = [
                ['Critical', 'High', 'Medium', 'Low'],
                [str(data.critical_count), str(data.high_count), str(data.medium_count), str(data.low_count)],
            ]
            counts_table = Table(counts_data, colWidths=[1.5*inch]*4)
            counts_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ]))
            story.append(counts_table)
            story.append(Spacer(1, 30))
            
            # Recommendations
            if data.recommendations:
                story.append(Paragraph("Recommendations", styles['Heading2']))
                for rec in data.recommendations:
                    story.append(Paragraph(f"• {html_module.escape(str(rec))}", styles['Normal']))
                    story.append(Spacer(1, 5))
            
            story.append(Spacer(1, 30))
            story.append(Paragraph(
                html_module.escape(f"Generated by Enterprise Memory Forensics Platform - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"),
                styles['Italic']
            ))
            
            doc.build(story)
            
        except ImportError:
            # Fallback: generate a text-based PDF note
            with open(output_path.replace('.pdf', '.txt'), 'w') as f:
                f.write("PDF generation requires reportlab. Install with: pip install reportlab\n")
                f.write(f"JSON report available instead.\n\n")
                f.write(f"Title: {data.title}\n")
                f.write(f"Verdict: {data.executive_verdict}\n")
                f.write(f"Threat Score: {data.threat_score}\n")
    
    def _score_class(self, score: float) -> str:
        """Get CSS class for score."""
        if score >= 90: return "score-critical"
        if score >= 70: return "score-high"
        if score >= 50: return "score-medium"
        if score >= 30: return "score-low"
        return "score-clean"
    
    def _health_class(self, score: float) -> str:
        """Get CSS class for health score (inverted)."""
        if score <= 30: return "score-critical"
        if score <= 50: return "score-high"
        if score <= 70: return "score-medium"
        return "score-clean"
    
    def _get_verdict_color(self, verdict: str):
        """Get color for verdict."""
        try:
            from reportlab.lib import colors
            verdict_colors = {
                "CRITICAL": colors.red,
                "HIGH": colors.orange,
                "MEDIUM": colors.yellow,
                "LOW": colors.green,
                "CLEAN": colors.HexColor('#00ddff'),
            }
            return verdict_colors.get(verdict.upper(), colors.black)
        except ImportError:
            return None