from django.shortcuts import render
from django.http import JsonResponse
from django.views.generic import TemplateView
import json
import datetime


class SecurityDashboardView(TemplateView):
    template_name = 'frontend/security_dashboard.html'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'page_title': 'Jorise v2 - Suite Completa de Ciberseguridad',
            'version': '2.0 Enterprise',
            'security_modules': [
                {
                    'name': 'SIEM',
                    'full_name': 'Security Information and Event Management',
                    'status': 'Activo',
                    'icon': 'fas fa-chart-line',
                    'color': 'success',
                    'alerts': 12,
                    'description': 'Monitoreo y análisis de eventos de seguridad en tiempo real'
                },
                {
                    'name': 'EDR',
                    'full_name': 'Endpoint Detection and Response',
                    'status': 'Monitoring',
                    'icon': 'fas fa-desktop',
                    'color': 'primary',
                    'alerts': 3,
                    'description': 'Detección y respuesta en endpoints corporativos'
                },
                {
                    'name': 'WAF',
                    'full_name': 'Web Application Firewall',
                    'status': 'Protecting',
                    'icon': 'fas fa-shield-alt',
                    'color': 'warning',
                    'alerts': 8,
                    'description': 'Protección de aplicaciones web contra ataques'
                },
                {
                    'name': 'ANTIVIRUS',
                    'full_name': 'Motor Antivirus Avanzado',
                    'status': 'Scanning',
                    'icon': 'fas fa-virus-slash',
                    'color': 'danger',
                    'alerts': 0,
                    'description': 'Engine antimalware con múltiples motores de detección'
                },
                {
                    'name': 'SANDBOX',
                    'full_name': 'Análisis en Entorno Aislado',
                    'status': 'Ready',
                    'icon': 'fas fa-cube',
                    'color': 'info',
                    'alerts': 1,
                    'description': 'Ejecución segura de archivos sospechosos'
                }
            ],
            'threat_stats': {
                'total_threats_blocked': 1247,
                'active_incidents': 5,
                'endpoints_protected': 156,
                'uptime': '99.97%'
            },
            'recent_incidents': [
                {'time': '10:34', 'type': 'Malware Blocked', 'source': 'EDR', 'severity': 'High'},
                {'time': '09:51', 'type': 'Intrusion Attempt', 'source': 'WAF', 'severity': 'Medium'},
                {'time': '09:12', 'type': 'Suspicious Process', 'source': 'SIEM', 'severity': 'Low'},
                {'time': '08:44', 'type': 'File Quarantined', 'source': 'Antivirus', 'severity': 'Medium'},
            ]
        })
        return context


def threat_intelligence_api(request):
    """API endpoint para inteligencia de amenazas"""
    data = {
        'status': 'active',
        'threat_level': 'medium',
        'active_threats': [
            {'name': 'Trojan.GenKryptor', 'count': 12, 'blocked': 12},
            {'name': 'Ransom.Lockbit', 'count': 3, 'blocked': 3}, 
            {'name': 'Adware.BrowseFox', 'count': 8, 'blocked': 7},
        ],
        'geographic_threats': {
            'high_risk_countries': ['CN', 'RU', 'IR'],
            'blocked_ips': 2341,
            'suspicious_domains': 89
        }
    }
    return JsonResponse(data)


def security_compliance_report(request):
    """Vista para reportes de cumplimiento"""
    return render(request, 'frontend/compliance.html', {
        'page_title': 'Reportes de Cumplimiento - Jorise v2',
        'compliance_frameworks': [
            {'name': 'ISO 27001', 'status': 'Compliant', 'score': 94},
            {'name': 'NIST Framework', 'status': 'Partial', 'score': 87},
            {'name': 'SOC 2 Type II', 'status': 'Compliant', 'score': 96},
            {'name': 'GDPR', 'status': 'Compliant', 'score': 98}
        ]
    })


def incident_response_center(request):
    """Centro de respuesta a incidentes"""
    return render(request, 'frontend/incident_response.html', {
        'page_title': 'Centro de Respuesta a Incidentes',
        'active_incidents': [
            {
                'id': 'INC-2025-001',
                'title': 'Potential APT Activity Detected',
                'severity': 'Critical',
                'status': 'Investigating',
                'assigned': 'Security Team Alpha',
                'created': '2025-10-09 14:23'
            },
            {
                'id': 'INC-2025-002', 
                'title': 'Multiple Failed Login Attempts',
                'severity': 'Medium',
                'status': 'Contained',
                'assigned': 'SOC Analyst',
                'created': '2025-10-09 13:15'
            }
        ]
    })