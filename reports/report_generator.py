"""Report Generator"""

import os
import sys
from datetime import datetime

def generate_pdf_report(networks: list, stats: dict, output_path: str = None) -> str:
    """Generate a professional PDF security audit report."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
        from reportlab.platypus import KeepTogether
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    except ImportError:
        return None

    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"/home/claude/wifi-security-toolkit/reports/audit_report_{ts}.pdf"

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    story = []

    DARK = colors.HexColor("#0f172a")
    ACCENT = colors.HexColor("#3b82f6")
    SUCCESS = colors.HexColor("#22c55e")
    WARNING = colors.HexColor("#f59e0b")
    DANGER = colors.HexColor("#ef4444")
    CRITICAL = colors.HexColor("#dc2626")
    LIGHT_BG = colors.HexColor("#f8fafc")
    MID_BG = colors.HexColor("#e2e8f0")

    title_style = ParagraphStyle("title", fontSize=24, textColor=DARK,
                                  fontName="Helvetica-Bold", alignment=TA_CENTER, spaceAfter=6)
    subtitle_style = ParagraphStyle("subtitle", fontSize=11, textColor=ACCENT,
                                     fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)
    heading_style = ParagraphStyle("heading", fontSize=14, textColor=DARK,
                                    fontName="Helvetica-Bold", spaceBefore=12, spaceAfter=6)
    body_style = ParagraphStyle("body", fontSize=9, textColor=DARK,
                                 fontName="Helvetica", spaceAfter=3)
    small_style = ParagraphStyle("small", fontSize=8, textColor=colors.HexColor("#64748b"),
                                  fontName="Helvetica", spaceAfter=2)

    def risk_color(risk):
        return {
            "Critical": CRITICAL,
            "High": DANGER,
            "Medium": WARNING,
            "Medium-High": DANGER,
            "Low": SUCCESS,
            "None": SUCCESS,
            "Informational": ACCENT,
        }.get(risk, colors.grey)

    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("🛡 Wi-Fi Security Audit Report", title_style))
    story.append(Paragraph("Authorized Network Security Assessment", subtitle_style))
    story.append(Paragraph(f"Generated: {stats.get('scan_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}", small_style))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=12))

    story.append(Paragraph("Executive Summary", heading_style))

    summary_data = [
        ["Metric", "Value", "Status"],
        ["Total Networks Discovered", str(stats["total"]), "—"],
        ["Open Networks (No Encryption)", str(stats["open"]), "⚠ Critical" if stats["open"] > 0 else "✓ None"],
        ["WEP Networks (Broken)", str(stats["wep"]), "⚠ High Risk" if stats["wep"] > 0 else "✓ None"],
        ["WPA Legacy Networks", str(stats["wpa"]), "⚠ Medium" if stats["wpa"] > 0 else "✓ None"],
        ["WPA2 Networks", str(stats["wpa2"]), "ℹ Acceptable"],
        ["WPA3 Networks (Best)", str(stats["wpa3"]), "✓ Excellent"],
        ["WPS Enabled Networks", str(stats["wps_enabled"]), "⚠ High" if stats["wps_enabled"] > 0 else "✓ None"],
        ["Hidden SSIDs", str(stats["hidden"]), "ℹ Informational"],
        ["Suspected Rogue APs", str(stats["rogue"]), "⚠ Critical" if stats["rogue"] > 0 else "✓ None"],
        ["Average Security Score", f"{stats['avg_security_score']}/100", ""],
    ]

    col_widths = [9*cm, 3*cm, 5*cm]
    t = Table(summary_data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), DARK),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ALIGN", (1,0), (-1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT_BG, colors.white]),
        ("GRID", (0,0), (-1,-1), 0.5, MID_BG),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph("Detailed Network Analysis", heading_style))

    for i, net in enumerate(networks, 1):
        ssid_display = net["ssid"] if net["ssid"] else "[Hidden Network]"
        enc = net["encryption"]
        rc = risk_color(net["overall_risk"])

        net_data = [
            [f"#{i} — {ssid_display}", f"Risk: {net['overall_risk']}", f"Score: {net['score']}/100"],
            ["BSSID", net["bssid"], net["vendor"]],
            ["Channel / Frequency", f"{net['channel']} / {net['frequency']}", ""],
            ["Signal Strength", f"{net['signal']} dBm ({net['signal_quality']})", ""],
            ["Encryption", enc, "WPS: " + ("Enabled ⚠" if net["wps_enabled"] else "Disabled ✓")],
            ["Connected Clients", str(net["clients_connected"]), "Rogue AP: " + ("Suspected ⚠" if net["is_rogue"] else "No")],
        ]

        nt = Table(net_data, colWidths=[5*cm, 7*cm, 5*cm])
        nt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), rc),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("SPAN", (0,0), (0,0)),
            ("FONTSIZE", (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT_BG, colors.white]),
            ("GRID", (0,0), (-1,-1), 0.3, MID_BG),
            ("TOPPADDING", (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING", (0,0), (-1,-1), 6),
            ("ALIGN", (1,0), (-1,0), "RIGHT"),
        ]))

        recs = net.get("recommendations", [])
        rec_paragraphs = [nt]
        if recs:
            rec_text = "<b>Recommendations:</b> " + " | ".join(recs)
            rec_paragraphs.append(Paragraph(rec_text, small_style))

        rec_paragraphs.append(Spacer(1, 0.3*cm))
        story.append(KeepTogether(rec_paragraphs))

    story.append(HRFlowable(width="100%", thickness=1, color=MID_BG, spaceBefore=8, spaceAfter=8))
    story.append(Paragraph("Risk Matrix Summary", heading_style))

    risk_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0}
    for n in networks:
        r = n["overall_risk"]
        if r in risk_counts:
            risk_counts[r] += 1

    matrix_data = [["Risk Level", "Count", "Action Required"]]
    risk_actions = {
        "Critical": "Immediate action required",
        "High": "Fix within 24 hours",
        "Medium": "Schedule fix within 1 week",
        "Low": "Monitor and plan upgrade",
        "None": "No action needed",
    }
    for level, count in risk_counts.items():
        matrix_data.append([level, str(count), risk_actions[level]])

    mt = Table(matrix_data, colWidths=[4*cm, 3*cm, 10*cm])
    mt.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), DARK),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ALIGN", (1,0), (1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [LIGHT_BG, colors.white]),
        ("GRID", (0,0), (-1,-1), 0.5, MID_BG),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
    ]))
    story.append(mt)

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        "<b>DISCLAIMER:</b> This report is generated for authorized security auditing purposes only. "
        "Only scan networks you own or have explicit written permission to audit. "
        "Unauthorized network scanning may be illegal under applicable laws.",
        small_style
    ))
    story.append(Paragraph("Wi-Fi Security Audit Toolkit — Confidential Security Report", small_style))

    doc.build(story)
    return output_path