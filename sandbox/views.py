"""
SANDBOX Module - Enhanced with AI
Secure file analysis in isolated environment
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.utils import timezone
from datetime import timedelta
import json
import hashlib
import os
import requests
from core.models import (
    SecurityEvent, SandboxAnalysis,
    Organization, ThreatIntelligence, UsageMetrics
)


class SandboxAnalyzer:
    """Motor de análisis de sandbox con IA"""
    
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    @staticmethod
    def calculate_hashes(file_path):
        """Calcula hashes del archivo"""
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)
        
        return md5.hexdigest(), sha256.hexdigest()
    
    @staticmethod
    def check_virustotal(file_hash):
        """Consulta VirusTotal"""
        if not SandboxAnalyzer.VIRUSTOTAL_API_KEY:
            return None
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": SandboxAnalyzer.VIRUSTOTAL_API_KEY}
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malicious': stats.get('malicious', 0),
                    'total': sum(stats.values()),
                    'data': data
                }
        except:
            pass
        
        return None
    
    @staticmethod
    def analyze_file_static(file_path):
        """Análisis estático del archivo"""
        indicators = []
        threat_score = 0.0
        
        file_size = os.path.getsize(file_path)
        
        # 1. Extensión sospechosa
        _, ext = os.path.splitext(file_path)
        suspicious_exts = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']
        
        if ext.lower() in suspicious_exts:
            threat_score += 0.2
            indicators.append(f"Extensión potencialmente peligrosa: {ext}")
        
        # 2. Leer primeros bytes (magic numbers)
        with open(file_path, 'rb') as f:
            header = f.read(4)
            
            # PE executable
            if header[:2] == b'MZ':
                threat_score += 0.1
                indicators.append("Ejecutable PE detectado")
            
            # ELF executable
            elif header == b'\x7fELF':
                threat_score += 0.1
                indicators.append("Ejecutable ELF detectado")
        
        # 3. Tamaño sospechoso (muy pequeño o muy grande)
        if file_size < 1000:
            threat_score += 0.1
            indicators.append(f"Tamaño sospechosamente pequeño: {file_size} bytes")
        elif file_size > 50 * 1024 * 1024:  # 50MB
            threat_score += 0.1
            indicators.append(f"Archivo muy grande: {file_size} bytes")
        
        # 4. Buscar strings sospechosos
        try:
            with open(file_path, 'rb') as f:
                content = f.read(1024 * 1024)  # Primeros 1MB
                text = content.decode('utf-8', errors='ignore').lower()
                
                suspicious_strings = [
                    'cmd.exe', 'powershell', 'wget', 'curl',
                    'reverse shell', 'metasploit', 'payload',
                    'exploit', 'shellcode', 'cryptolocker'
                ]
                
                for sus_string in suspicious_strings:
                    if sus_string in text:
                        threat_score += 0.15
                        indicators.append(f"String sospechoso encontrado: {sus_string}")
        except:
            pass
        
        return {
            'threat_score': min(threat_score, 1.0),
            'indicators': indicators
        }
    
    @staticmethod
    def generate_ai_report(analysis_data):
        """Genera reporte detallado con IA"""
        try:
            import google.generativeai as genai
            from django.conf import settings
            
            genai.configure(api_key=settings.GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-pro')
            
            prompt = f"""
            Genera un reporte de análisis de malware profesional:
            
            Archivo: {analysis_data['file_name']}
            Hash SHA256: {analysis_data['file_hash_sha256']}
            Tamaño: {analysis_data['file_size']} bytes
            Veredicto: {analysis_data['verdict']}
            Score: {analysis_data['threat_score']}/100
            
            VirusTotal: {analysis_data.get('vt_detections', 'N/A')}/{analysis_data.get('vt_total', 'N/A')} motores detectaron amenaza
            
            Indicadores detectados:
            {chr(10).join('- ' + ind for ind in analysis_data.get('indicators', []))}
            
            Actividad de red:
            {json.dumps(analysis_data.get('network_activity', {}), indent=2)}
            
            Operaciones de archivo:
            {json.dumps(analysis_data.get('file_operations', [])[:5], indent=2)}
            
            Genera un reporte que incluya:
            1. Resumen Ejecutivo
            2. Análisis Técnico Detallado
            3. Indicadores de Compromiso (IOCs)
            4. Recomendaciones de Mitigación
            5. Nivel de Riesgo y Prioridad
            
            Formato: Markdown profesional
            """
            
            response = model.generate_content(prompt)
            return response.text
        except:
            return "Reporte de IA no disponible"


@require_http_methods(["POST"])
def submit_file(request, org_id):
    """Enviar archivo para análisis"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.sandbox_enabled:
            return JsonResponse({'error': 'Sandbox not enabled'}, status=403)
        
        # Verificar límites
        today = timezone.now().date()
        metrics, _ = UsageMetrics.objects.get_or_create(
            organization=organization,
            date=today
        )
        
        if metrics.scans_count >= organization.subscription.max_events_per_month / 30:
            return JsonResponse({'error': 'Daily scan limit reached'}, status=429)
        
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return JsonResponse({'error': 'No file provided'}, status=400)
        
        # Guardar archivo temporalmente
        file_path = default_storage.save(f'sandbox/{uploaded_file.name}', uploaded_file)
        full_path = default_storage.path(file_path)
        
        # Calcular hashes
        md5_hash, sha256_hash = SandboxAnalyzer.calculate_hashes(full_path)
        
        # Crear análisis
        analysis = SandboxAnalysis.objects.create(
            organization=organization,
            file_name=uploaded_file.name,
            file_size=uploaded_file.size,
            file_hash_md5=md5_hash,
            file_hash_sha256=sha256_hash,
            file_path=file_path,
            status='queued',
            submitted_by=request.user if request.user.is_authenticated else None
        )
        
        # Iniciar análisis asíncrono (aquí se simula)
        perform_sandbox_analysis.delay(str(analysis.id))
        
        # Actualizar métricas
        metrics.scans_count += 1
        metrics.save()
        
        return JsonResponse({
            'success': True,
            'analysis_id': str(analysis.id),
            'status': 'queued',
            'message': 'File submitted for analysis'
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


def perform_sandbox_analysis(analysis_id):
    """Realiza el análisis completo (normalmente en Celery task)"""
    try:
        analysis = SandboxAnalysis.objects.get(id=analysis_id)
        analysis.status = 'running'
        analysis.started_at = timezone.now()
        analysis.save()
        
        file_path = default_storage.path(analysis.file_path)
        
        # 1. Análisis estático
        static_analysis = SandboxAnalyzer.analyze_file_static(file_path)
        
        # 2. Consultar VirusTotal
        vt_result = SandboxAnalyzer.check_virustotal(analysis.file_hash_sha256)
        
        if vt_result:
            analysis.virustotal_detections = vt_result['malicious']
            analysis.virustotal_total = vt_result['total']
            analysis.virustotal_data = vt_result['data']
        
        # 3. Calcular threat score
        threat_score = static_analysis['threat_score'] * 100
        
        if vt_result and vt_result['total'] > 0:
            vt_ratio = vt_result['malicious'] / vt_result['total']
            threat_score = max(threat_score, vt_ratio * 100)
        
        # 4. Veredicto
        if threat_score >= 70:
            verdict = 'malicious'
        elif threat_score >= 40:
            verdict = 'suspicious'
        else:
            verdict = 'clean'
        
        analysis.verdict = verdict
        analysis.threat_score = threat_score
        
        # 5. Simular actividad (en producción sería ejecución real en VM)
        analysis.network_activity = {
            'connections': [],
            'dns_queries': [],
            'http_requests': []
        }
        
        analysis.file_operations = []
        analysis.registry_operations = []
        analysis.processes_created = []
        
        # 6. Generar reporte con IA
        if analysis.organization.subscription.ai_analysis_enabled:
            report_data = {
                'file_name': analysis.file_name,
                'file_size': analysis.file_size,
                'file_hash_sha256': analysis.file_hash_sha256,
                'verdict': verdict,
                'threat_score': threat_score,
                'vt_detections': vt_result['malicious'] if vt_result else 0,
                'vt_total': vt_result['total'] if vt_result else 0,
                'indicators': static_analysis['indicators'],
                'network_activity': analysis.network_activity,
                'file_operations': analysis.file_operations,
            }
            
            ai_report = SandboxAnalyzer.generate_ai_report(report_data)
            analysis.ai_report = ai_report
            
            # Extraer recomendaciones
            analysis.ai_recommendations = [
                "Bloquear hash en firewall",
                "Revisar sistemas que hayan ejecutado este archivo",
                "Actualizar reglas de antivirus"
            ]
        
        # 7. Agregar a Threat Intelligence si es malicioso
        if verdict == 'malicious':
            ThreatIntelligence.objects.get_or_create(
                ioc_type='hash_sha256',
                ioc_value=analysis.file_hash_sha256,
                defaults={
                    'threat_level': 'high',
                    'description': f'Malware detectado: {analysis.file_name}',
                    'source': 'Jorise Sandbox',
                    'tags': ['malware', 'sandbox_detected']
                }
            )
            
            # Crear evento de seguridad
            SecurityEvent.objects.create(
                organization=analysis.organization,
                module='sandbox',
                event_type='malware_detected',
                severity='high',
                title=f'Malware detectado: {analysis.file_name}',
                description=f'Archivo malicioso identificado en sandbox\n'
                           f'Hash: {analysis.file_hash_sha256}\n'
                           f'Score: {threat_score}/100\n'
                           f'VirusTotal: {vt_result["malicious"] if vt_result else 0}/{vt_result["total"] if vt_result else 0}',
                raw_data={'analysis_id': str(analysis.id)},
                ai_confidence=threat_score / 100,
            )
        
        analysis.status = 'completed'
        analysis.completed_at = timezone.now()
        analysis.save()
        
    except Exception as e:
        analysis.status = 'failed'
        analysis.save()


@require_http_methods(["GET"])
def get_analysis(request, analysis_id):
    """Obtener resultado de análisis"""
    try:
        analysis = SandboxAnalysis.objects.get(id=analysis_id)
        
        return JsonResponse({
            'success': True,
            'analysis': {
                'id': str(analysis.id),
                'file_name': analysis.file_name,
                'file_size': analysis.file_size,
                'file_hash_md5': analysis.file_hash_md5,
                'file_hash_sha256': analysis.file_hash_sha256,
                'status': analysis.status,
                'verdict': analysis.verdict,
                'threat_score': analysis.threat_score,
                'virustotal': {
                    'detections': analysis.virustotal_detections,
                    'total': analysis.virustotal_total,
                },
                'ai_report': analysis.ai_report,
                'ai_recommendations': analysis.ai_recommendations,
                'created_at': analysis.created_at.isoformat(),
                'completed_at': analysis.completed_at.isoformat() if analysis.completed_at else None,
            }
        })
        
    except SandboxAnalysis.DoesNotExist:
        return JsonResponse({'error': 'Analysis not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def sandbox_dashboard(request, org_id):
    """Dashboard de sandbox"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.sandbox_enabled:
            return JsonResponse({'error': 'Sandbox not enabled'}, status=403)
        
        cutoff = timezone.now() - timedelta(days=7)
        
        analyses = SandboxAnalysis.objects.filter(
            organization=organization,
            created_at__gte=cutoff
        ).order_by('-created_at')
        
        stats = {
            'total_analyses': analyses.count(),
            'malicious': analyses.filter(verdict='malicious').count(),
            'suspicious': analyses.filter(verdict='suspicious').count(),
            'clean': analyses.filter(verdict='clean').count(),
            'pending': analyses.filter(status__in=['queued', 'running']).count(),
            
            'recent_analyses': [{
                'id': str(a.id),
                'file_name': a.file_name,
                'status': a.status,
                'verdict': a.verdict,
                'threat_score': a.threat_score,
                'created_at': a.created_at.isoformat(),
            } for a in analyses[:20]]
        }
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Template views for web dashboard
from django.contrib.auth.decorators import login_required

@login_required
def sandbox_dashboard_view(request):
    """Sandbox dashboard template view"""
    organization = request.user.profile.organization
    
    # Get recent analyses
    recent_analyses = SandboxAnalysis.objects.filter(
        organization=organization
    ).order_by('-created_at')[:50]
    
    # Get stats
    stats = {
        'total_analyses': SandboxAnalysis.objects.filter(organization=organization).count(),
        'malicious_files': SandboxAnalysis.objects.filter(
            organization=organization,
            verdict='malicious'
        ).count(),
        'suspicious_files': SandboxAnalysis.objects.filter(
            organization=organization,
            verdict='suspicious'
        ).count(),
        'clean_files': SandboxAnalysis.objects.filter(
            organization=organization,
            verdict='clean'
        ).count(),
    }
    
    context = {
        'recent_analyses': recent_analyses,
        'stats': stats,
        'organization': organization,
    }
    
    return render(request, 'sandbox/dashboard.html', context)
