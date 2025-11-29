"""
reports/pdf_generator.py

PDF Report Generator for CTIA System
Generates professional PDF reports of threat intelligence data.
"""

import sys
import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import sqlite3
import json

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.config import DB_PATH


def get_threat_statistics():
    """Get comprehensive threat statistics from database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    stats = {}
    
    # Total IOCs
    cur.execute("SELECT COUNT(*) as total FROM iocs")
    stats['total'] = cur.fetchone()['total']
    
    # By type
    cur.execute("SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type")
    stats['by_type'] = {row['ioc_type']: row['count'] for row in cur.fetchall()}
    
    # By threat level
    cur.execute("""
        SELECT 
            CASE 
                WHEN score >= 75 THEN 'Malicious'
                WHEN score >= 50 THEN 'Suspicious'
                WHEN score >= 25 THEN 'Low'
                ELSE 'Informational'
            END as label,
            COUNT(*) as count
        FROM iocs
        GROUP BY label
    """)
    stats['by_label'] = {row['label']: row['count'] for row in cur.fetchall()}
    
    # Enriched count
    cur.execute("SELECT COUNT(*) as enriched FROM iocs WHERE metadata IS NOT NULL AND metadata != '{}'")
    stats['enriched'] = cur.fetchone()['enriched']
    
    conn.close()
    return stats


def get_top_threats(limit=20):
    """Get top threats by score."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
        SELECT value, ioc_type, score, source, score_updated_at
        FROM iocs 
        WHERE score > 0 
        ORDER BY score DESC 
        LIMIT ?
    """, (limit,))
    
    threats = [dict(row) for row in cur.fetchall()]
    conn.close()
    return threats


def get_threat_label(score):
    """Get threat label and color based on score."""
    if score >= 75:
        return "Malicious", colors.red
    elif score >= 50:
        return "Suspicious", colors.orange
    elif score >= 25:
        return "Low", colors.yellow
    else:
        return "Informational", colors.green


def generate_pdf_report(output_path="ctia_report.pdf", include_top_threats=True, top_count=20):
    """
    Generate a comprehensive PDF report.
    
    Args:
        output_path: Path to save the PDF report
        include_top_threats: Whether to include top threats table
        top_count: Number of top threats to include
    
    Returns:
        Path to generated PDF file
    """
    print(f"[*] Generating PDF report: {output_path}")
    
    # Create document
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=72,
        leftMargin=72,
        topMargin=72,
        bottomMargin=18
    )
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1f77b4'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=12,
        spaceBefore=12,
        fontName='Helvetica-Bold'
    )
    
    normal_style = styles['Normal']
    
    # Title
    title = Paragraph("CTIA Threat Intelligence Report", title_style)
    elements.append(title)
    
    # Report metadata
    report_date = datetime.now().strftime("%B %d, %Y at %H:%M:%S")
    metadata = Paragraph(f"<b>Generated:</b> {report_date}", normal_style)
    elements.append(metadata)
    elements.append(Spacer(1, 0.2*inch))
    
    # Horizontal line
    elements.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#1f77b4')))
    elements.append(Spacer(1, 0.3*inch))
    
    # Executive Summary
    elements.append(Paragraph("Executive Summary", heading_style))
    
    stats = get_threat_statistics()
    
    summary_text = f"""
    This report provides a comprehensive overview of the current threat intelligence landscape 
    as captured by the CTIA (Cyber Threat Intelligence Automation) system. The system has collected 
    and analyzed <b>{stats['total']:,}</b> indicators of compromise (IOCs) from multiple threat feeds.
    """
    elements.append(Paragraph(summary_text, normal_style))
    elements.append(Spacer(1, 0.2*inch))
    
    # Statistics Section
    elements.append(Paragraph("Threat Statistics", heading_style))
    
    # Statistics table
    stats_data = [
        ['Metric', 'Count', 'Percentage'],
        ['Total IOCs', f"{stats['total']:,}", '100%'],
        ['Enriched IOCs', f"{stats['enriched']:,}", f"{(stats['enriched']/stats['total']*100):.1f}%" if stats['total'] > 0 else '0%'],
        ['Malicious (≥75)', f"{stats['by_label'].get('Malicious', 0):,}", f"{(stats['by_label'].get('Malicious', 0)/stats['total']*100):.1f}%" if stats['total'] > 0 else '0%'],
        ['Suspicious (50-74)', f"{stats['by_label'].get('Suspicious', 0):,}", f"{(stats['by_label'].get('Suspicious', 0)/stats['total']*100):.1f}%" if stats['total'] > 0 else '0%'],
        ['Low (25-49)', f"{stats['by_label'].get('Low', 0):,}", f"{(stats['by_label'].get('Low', 0)/stats['total']*100):.1f}%" if stats['total'] > 0 else '0%'],
        ['Informational (0-24)', f"{stats['by_label'].get('Informational', 0):,}", f"{(stats['by_label'].get('Informational', 0)/stats['total']*100):.1f}%" if stats['total'] > 0 else '0%'],
    ]
    
    stats_table = Table(stats_data, colWidths=[3*inch, 1.5*inch, 1.5*inch])
    stats_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f77b4')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))
    
    elements.append(stats_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # IOC Type Distribution
    elements.append(Paragraph("IOC Type Distribution", heading_style))
    
    type_data = [['IOC Type', 'Count', 'Percentage']]
    for ioc_type, count in stats['by_type'].items():
        percentage = f"{(count/stats['total']*100):.1f}%" if stats['total'] > 0 else '0%'
        type_data.append([ioc_type.upper(), f"{count:,}", percentage])
    
    type_table = Table(type_data, colWidths=[2*inch, 2*inch, 2*inch])
    type_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
    ]))
    
    elements.append(type_table)
    elements.append(Spacer(1, 0.3*inch))
    
    # Top Threats Section
    if include_top_threats:
        elements.append(PageBreak())
        elements.append(Paragraph(f"Top {top_count} Threats", heading_style))
        
        threats = get_top_threats(limit=top_count)
        
        if threats:
            threat_data = [['#', 'IOC Value', 'Type', 'Score', 'Label']]
            
            for i, threat in enumerate(threats, 1):
                value = threat['value'][:40] + "..." if len(threat['value']) > 40 else threat['value']
                label, color = get_threat_label(threat['score'])
                
                threat_data.append([
                    str(i),
                    value,
                    threat['ioc_type'].upper(),
                    str(threat['score']),
                    label
                ])
            
            threat_table = Table(threat_data, colWidths=[0.4*inch, 3*inch, 0.8*inch, 0.8*inch, 1*inch])
            
            # Build table style with conditional coloring
            table_style = [
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#c0392b')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]
            
            # Color code threat labels
            for i, threat in enumerate(threats, 1):
                label, color = get_threat_label(threat['score'])
                table_style.append(('BACKGROUND', (4, i), (4, i), color))
                table_style.append(('TEXTCOLOR', (4, i), (4, i), colors.white))
            
            threat_table.setStyle(TableStyle(table_style))
            elements.append(threat_table)
        else:
            elements.append(Paragraph("No threats found in database.", normal_style))
    
    # Footer
    elements.append(Spacer(1, 0.5*inch))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    footer_text = f"""
    <i>This report was automatically generated by the CTIA (Cyber Threat Intelligence Automation) system.<br/>
    For more information, visit the CTIA dashboard or contact your security team.</i>
    """
    elements.append(Paragraph(footer_text, normal_style))
    
    # Build PDF
    doc.build(elements)
    
    print(f"[+] PDF report generated successfully: {output_path}")
    return output_path


if __name__ == "__main__":
    """
    Generate PDF report from command line.
    Usage: python reports/pdf_generator.py [output_path] [top_count]
    """
    output_path = sys.argv[1] if len(sys.argv) > 1 else "ctia_threat_report.pdf"
    top_count = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    
    print(f"""
╔════════════════════════════════════════════════════════════════╗
║         CTIA PDF Report Generator - Phase 10                   ║
║         Cyber Threat Intelligence Automation                   ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    try:
        pdf_path = generate_pdf_report(output_path=output_path, top_count=top_count)
        print(f"\n[✓] Report saved to: {pdf_path}")
        print(f"[*] Open the PDF to view the threat intelligence report.")
    except Exception as e:
        print(f"\n[!] Error generating PDF report: {e}")
        sys.exit(1)
