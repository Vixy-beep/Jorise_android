from django.shortcuts import render
from django.http import JsonResponse
from django.utils import timezone


def report_dashboard(request):
    """Dashboard principal de reportes empresariales"""
    
    recent_reports = [
        {
            'title': 'Security Assessment Q4 2025',
            'type': 'Executive Summary', 
            'date': '2025-10-09',
            'status': 'Completed'
        }
    ]
    
    context = {
        'page_title': 'Enterprise Security Reports',
        'recent_reports': recent_reports
    }
    
    return render(request, 'reports/dashboard.html', context)


def export_json(request, report_id):
    """Exportar reporte en JSON"""
    data = {
        'report_id': report_id,
        'generated_at': timezone.now().isoformat(),
        'status': 'success'
    }
    return JsonResponse(data)
