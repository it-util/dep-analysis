from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from datetime import datetime
from typing import List, Dict
import os

def register_russian_font():
    """Регистрирует шрифт с поддержбой кириллицы"""
    try:
        font_paths = [
            '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',
            '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf',
            'C:/Windows/Fonts/arial.ttf',
            '/System/Library/Fonts/Helvetica.ttc'
        ]
        
        for font_path in font_paths:
            if os.path.exists(font_path):
                pdfmetrics.registerFont(TTFont('RussianFont', font_path))
                return 'RussianFont'
        
        return 'Helvetica'
    except Exception:
        return 'Helvetica'

def create_vulnerability_pdf(data: List[Dict], output_filename: str = "vulnerability_report.pdf"):
    """
    Создает PDF отчет с уязвимостями на весь экран
    """
    
    font_name = register_russian_font()
    
    # Используем A4 в альбомной ориентации с минимальными отступами
    doc = SimpleDocTemplate(
        output_filename,
        pagesize=landscape(A4),
        rightMargin=5,
        leftMargin=5,
        topMargin=10,
        bottomMargin=10
    )
    
    styles = getSampleStyleSheet()
    
    header_style = ParagraphStyle(
        'Header',
        parent=styles['Normal'],
        fontSize=8,
        textColor=colors.white,
        alignment=1,
        fontName=font_name,
        leading=10
    )
    
    cell_style = ParagraphStyle(
        'Cell',
        parent=styles['Normal'],
        fontSize=7,
        alignment=0,
        leading=9,
        fontName=font_name
    )
    
    elements = []
    
    # Заголовки таблицы
    headers = [
        "Пакет", "Версия", "ID уязвимости", "Severity", "CVSS",
        "Опубликовано", "Fixed Version", "Описание"
    ]
    
    # Собираем данные для таблицы
    table_data = [headers]
    
    for item in data:
        name = item.get('name', 'N/A')
        version = item.get('version', 'N/A')
        vulns = item.get('vulnerabilities', [])
        
        if not vulns:
            continue
        
        for vuln in vulns:
            description = vuln.get('summary', 'Нет описания')
            description = description.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            row = [
                Paragraph(name[:40], cell_style),
                Paragraph(version, cell_style),
                Paragraph(vuln.get('id', 'N/A')[:25], cell_style),
                Paragraph(_get_severity(vuln), cell_style),
                Paragraph(_get_cvss_score(vuln), cell_style),
                Paragraph(vuln.get('published', 'N/A')[:10] if vuln.get('published') else 'N/A', cell_style),
                Paragraph(_get_fixed_version(vuln)[:50], cell_style),
                Paragraph(_shorten_text(description, 120), cell_style)
            ]
            table_data.append(row)
    
    # Ширина колонок - распределяем всю доступную ширину страницы
    # Общая ширина страницы A4 landscape = 297mm = ~11.7 inch
    # Вычитаем отступы, получаем ~11.5 inch для таблицы
    col_widths = [
        1.4*inch,   # Пакет
        0.6*inch,   # Версия
        1.0*inch,   # ID уязвимости
        0.6*inch,   # Severity
        0.5*inch,   # CVSS
        0.7*inch,   # Опубликовано
        1.0*inch,   # Fixed Version
        3.7*inch    # Описание (оставшееся место)
    ]
    
    table = Table(table_data, colWidths=col_widths, repeatRows=1)
    
    table.setStyle(TableStyle([
        # Заголовок
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2C3E50')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), font_name),
        ('FONTSIZE', (0, 0), (-1, 0), 8),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
        ('TOPPADDING', (0, 0), (-1, 0), 5),
        
        # Сетка
        ('GRID', (0, 0), (-1, -1), 0.3, colors.grey),
        
        # Выравнивание
        ('ALIGN', (0, 1), (0, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        
        # Отступы
        ('TOPPADDING', (0, 1), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
        ('LEFTPADDING', (0, 0), (-1, -1), 3),
        ('RIGHTPADDING', (0, 0), (-1, -1), 3),
        
        # Шрифт для данных
        ('FONTNAME', (0, 1), (-1, -1), font_name),
        ('FONTSIZE', (0, 1), (-1, -1), 7),
    ]))
    
    # Подсветка строк по severity
    for i in range(1, len(table_data)):
        severity_cell = table_data[i][3]
        severity_text = severity_cell.text.lower() if hasattr(severity_cell, 'text') else str(severity_cell).lower()
        
        if 'high' in severity_text or 'critical' in severity_text:
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.HexColor('#FFEBEE'))]))
        elif 'moderate' in severity_text or 'medium' in severity_text:
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.HexColor('#FFF8E1'))]))
        elif 'low' in severity_text:
            table.setStyle(TableStyle([('BACKGROUND', (0, i), (-1, i), colors.HexColor('#E8F5E9'))]))
    
    elements.append(table)
    
    doc.build(elements)
    print(f"✅ PDF отчет создан: {output_filename}")

def _get_severity(vuln: Dict) -> str:
    db_specific = vuln.get('database_specific', {})
    severity = db_specific.get('severity', 'N/A')
    if isinstance(severity, list):
        return severity[0] if severity else 'N/A'
    return str(severity)

def _get_cvss_score(vuln: Dict) -> str:
    severity_list = vuln.get('severity', [])
    for sev in severity_list:
        score = sev.get('score', '')
        if score:
            if isinstance(score, str) and 'CVSS:' in score:
                parts = score.split('/')
                if parts:
                    return parts[0].replace('CVSS:', '').strip()
            return str(score)[:5]
    return 'N/A'

def _get_fixed_version(vuln: Dict) -> str:
    fixed_versions = []
    for affected in vuln.get('affected', []):
        for range_info in affected.get('ranges', []):
            for event in range_info.get('events', []):
                if 'fixed' in event:
                    fixed_versions.append(event['fixed'])
    if fixed_versions:
        return ', '.join(set(fixed_versions))
    return 'Не указано'

def _shorten_text(text: str, max_length: int = 120) -> str:
    if not text:
        return 'Нет описания'
    text = text.replace('\n', ' ').replace('\r', ' ')
    if len(text) <= max_length:
        return text
    return text[:max_length] + '...'