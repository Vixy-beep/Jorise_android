from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, JsonResponse
from django.template.loader import render_to_string
from django.contrib import messages
from django.utils import timezone
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import io
from .models import Report
# LAZY IMPORT: ScanResult se importa donde se usa para evitar dependencias circulares


def reports_list(request):
    """Listar todos los reportes"""
    reports = Report.objects.all()
    return render(request, 'reports/list.html', {'reports': reports})


def generate_report(request):
    """Generar nuevo reporte"""
    from scan.models import ScanResult  # Import aquí para evitar circular dependency
    
    if request.method == 'POST':
        report_type = request.POST.get('report_type', 'summary')
        format_type = request.POST.get('format', 'html')
        title = request.POST.get('title', f'Reporte {timezone.now().strftime("%Y-%m-%d")}')
        
        # Crear el reporte
        report = Report.objects.create(
            title=title,
            report_type=report_type,
            format=format_type
        )
        
        # Agregar resultados de escaneo según el tipo
        if report_type == 'individual':
            scan_id = request.POST.get('scan_id')
            if scan_id:
                scan_result = get_object_or_404(ScanResult, id=scan_id)
                report.scan_results.add(scan_result)
        else:
            # Para reportes de resumen o detallados, incluir todos los escaneos
            scan_results = ScanResult.objects.all()
            report.scan_results.set(scan_results)
        
        if format_type == 'pdf':
            return generate_pdf_report(report)
        else:
            return generate_html_report(request, report)
    
    # GET request - mostrar formulario
    from scan.models import ScanResult  # Import aquí también
    scans = ScanResult.objects.all()
    return render(request, 'reports/generate.html', {'scans': scans})


def generate_html_report(request, report):
    """Generar reporte en HTML"""
    scan_results = report.scan_results.all()
    
    # Calcular estadísticas
    stats = {
        'total_files': scan_results.count(),
        'clean_files': scan_results.filter(virustotal_positives=0).count(),
        'suspicious_files': scan_results.filter(virustotal_positives__gt=0).count(),
        'high_risk': scan_results.filter(risk_level__in=['high', 'critical']).count(),
    }
    
    context = {
        'report': report,
        'scan_results': scan_results,
        'stats': stats,
        'generated_date': timezone.now(),
    }
    
    return render(request, 'reports/html_report.html', context)


def generate_pdf_report(report):
    """Generar reporte en PDF"""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Título del reporte
    title = Paragraph(f"<b>{report.title}</b>", styles['Title'])
    story.append(title)
    story.append(Spacer(1, 20))
    
    # Información general
    info_text = f"""
    <b>Tipo de Reporte:</b> {report.get_report_type_display()}<br/>
    <b>Fecha de Generación:</b> {timezone.now().strftime('%d/%m/%Y %H:%M')}<br/>
    <b>Total de Archivos Analizados:</b> {report.scan_results.count()}
    """
    info_para = Paragraph(info_text, styles['Normal'])
    story.append(info_para)
    story.append(Spacer(1, 20))
    
    # Tabla de resultados
    scan_results = report.scan_results.all()
    if scan_results:
        # Cabeceras de la tabla
        data = [['Archivo', 'Estado', 'Detecciones', 'Riesgo']]
        
        # Agregar datos
        for scan in scan_results:
            data.append([
                scan.file_name[:30] + '...' if len(scan.file_name) > 30 else scan.file_name,
                scan.get_scan_status_display(),
                f'{scan.virustotal_positives}/{scan.virustotal_total}',
                scan.get_risk_level_display()
            ])
        
        # Crear tabla
        table = Table(data, colWidths=[200, 80, 80, 80])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(table)
    
    # Generar PDF
    doc.build(story)
    buffer.seek(0)
    
    response = HttpResponse(buffer.getvalue(), content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{report.title}.pdf"'
    
    return response


def view_report(request, report_id):
    """Ver reporte específico"""
    report = get_object_or_404(Report, id=report_id)
    
    if report.format == 'pdf' and report.file_path:
        # Servir archivo PDF guardado
        with open(report.file_path.path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/pdf')
            response['Content-Disposition'] = f'inline; filename="{report.title}.pdf"'
            return response
    else:
        # Mostrar reporte HTML
        return generate_html_report(request, report)


def delete_report(request, report_id):
    """Eliminar reporte"""
    if request.method == 'POST':
        report = get_object_or_404(Report, id=report_id)
        report.delete()
        messages.success(request, 'Reporte eliminado exitosamente.')
    
    return redirect('reports_list')
