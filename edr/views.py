"""
EDR (Endpoint Detection and Response) Module
IA-powered endpoint monitoring and threat detection
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from datetime import timedelta
import json
from core.models import (
    SecurityEvent, EDRAgent, EDRProcess,
    Organization, ThreatIntelligence
)
from django.db.models import Count, Q
import hashlib

# Motor ML de Jorise
try:
    from training.jorise_engine import JoriseEngine as _JoriseEngine
    JORISE_ML_AVAILABLE = True
except Exception:
    _JoriseEngine = None
    JORISE_ML_AVAILABLE = False


class EDRAnalyzer:
    """Motor de análisis EDR con IA"""
    
    # Procesos conocidos como sospechosos
    SUSPICIOUS_PROCESSES = [
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'reg.exe', 'net.exe', 'sc.exe', 'taskkill.exe', 'psexec.exe',
        'mimikatz.exe', 'procdump.exe', 'psexec.exe'
    ]
    
    # Patrones de command line sospechosos
    SUSPICIOUS_PATTERNS = [
        r'invoke-expression',
        r'downloadstring',
        r'iex\s*\(',
        r'bypass\s+executionpolicy',
        r'hidden\s+window',
        r'encode.*command',
        r'base64',
        r'-nop\s+-w\s+hidden',
        r'net\s+user\s+.*\s+/add',
        r'reg\s+add.*run',
    ]
    
    @staticmethod
    def analyze_process(process_data):
        """Analiza un proceso usando IA y heurística"""
        threat_score = 0.0
        indicators = []
        
        process_name = process_data.get('process_name', '').lower()
        command_line = process_data.get('command_line', '').lower()
        user = process_data.get('user', '')
        file_path = process_data.get('file_path', '').lower()
        
        # 1. Proceso sospechoso
        if any(susp in process_name for susp in EDRAnalyzer.SUSPICIOUS_PROCESSES):
            threat_score += 0.3
            indicators.append(f"Proceso potencialmente peligroso: {process_name}")
        
        # 2. Comandos sospechosos
        import re
        for pattern in EDRAnalyzer.SUSPICIOUS_PATTERNS:
            if re.search(pattern, command_line):
                threat_score += 0.4
                indicators.append(f"Patrón sospechoso en comando: {pattern}")
        
        # 3. Ejecución desde directorios temporales
        temp_dirs = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp', 'downloads']
        if any(temp_dir in file_path for temp_dir in temp_dirs):
            threat_score += 0.2
            indicators.append("Ejecución desde directorio temporal")
        
        # 4. Usuario sospechoso (SYSTEM ejecutando cosas raras)
        if user.lower() == 'system' and process_name not in ['svchost.exe', 'services.exe']:
            threat_score += 0.25
            indicators.append("Proceso ejecutado como SYSTEM")
        
        # 5. Verificar hash contra threat intelligence
        file_hash = process_data.get('file_hash')
        if file_hash:
            threat = ThreatIntelligence.objects.filter(
                Q(ioc_type='hash_md5') | Q(ioc_type='hash_sha256'),
                ioc_value=file_hash
            ).first()
            
            if threat:
                threat_score = 1.0
                indicators.append(f"Hash malicioso conocido: {threat.description}")
        
        # Normalizar score
        threat_score = min(threat_score, 1.0)
        
        # 6. Jorise ML — clasifica comportamiento del proceso
        if JORISE_ML_AVAILABLE and _JoriseEngine is not None:
            try:
                ml_result = _JoriseEngine.analyze_process(process_data)
                if ml_result.is_threat and ml_result.threat_score > threat_score:
                    threat_score = ml_result.threat_score
                    indicators.extend(ml_result.reasons)
                    indicators.append(
                        f"[Jorise ML — {ml_result.model_name}] "
                        f"{ml_result.attack_type} (confianza {ml_result.confidence:.0%})"
                    )
            except Exception:
                pass
        
        # Veredicto
        if threat_score >= 0.8:
            verdict = 'malicious'
        elif threat_score >= 0.5:
            verdict = 'suspicious'
        else:
            verdict = 'clean'
        
        return {
            'threat_score': threat_score,
            'verdict': verdict,
            'indicators': indicators,
            'is_suspicious': threat_score >= 0.5
        }
    
    @staticmethod
    def detect_lateral_movement(agent):
        """Detecta movimiento lateral en la red"""
        # Buscar procesos de red/remotos
        recent_processes = EDRProcess.objects.filter(
            agent=agent,
            timestamp__gte=timezone.now() - timedelta(minutes=10)
        )
        
        lateral_indicators = []
        
        for process in recent_processes:
            # PSExec, WMI, RDP
            if any(tool in process.command_line.lower() for tool in ['psexec', 'wmic', 'mstsc']):
                lateral_indicators.append({
                    'process': process.process_name,
                    'command': process.command_line,
                    'type': 'remote_execution'
                })
            
            # Montaje de recursos compartidos
            if 'net use' in process.command_line.lower():
                lateral_indicators.append({
                    'process': process.process_name,
                    'command': process.command_line,
                    'type': 'network_share'
                })
        
        return lateral_indicators


@require_http_methods(["POST"])
def agent_heartbeat(request, agent_id):
    """Heartbeat del agente EDR"""
    try:
        data = json.loads(request.body)
        
        agent = EDRAgent.objects.get(agent_id=agent_id)
        agent.status = 'online'
        agent.last_seen = timezone.now()
        agent.save()
        
        return JsonResponse({'success': True})
        
    except EDRAgent.DoesNotExist:
        return JsonResponse({'error': 'Agent not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def report_process(request, agent_id):
    """Agente reporta un nuevo proceso"""
    try:
        agent = EDRAgent.objects.get(agent_id=agent_id)
        
        if not agent.organization.subscription.edr_enabled:
            return JsonResponse({'error': 'EDR not enabled'}, status=403)
        
        data = json.loads(request.body)
        
        # Analizar proceso
        analysis = EDRAnalyzer.analyze_process(data)
        
        # Crear registro
        process = EDRProcess.objects.create(
            agent=agent,
            process_name=data.get('process_name'),
            process_id=data.get('process_id'),
            parent_process_id=data.get('parent_process_id'),
            command_line=data.get('command_line', ''),
            user=data.get('user', ''),
            file_hash=data.get('file_hash'),
            file_path=data.get('file_path', ''),
            is_suspicious=analysis['is_suspicious'],
            threat_score=analysis['threat_score'],
            ai_verdict=analysis['verdict'],
        )
        
        # Si es sospechoso, crear evento y potencialmente bloquear
        action_taken = None
        if analysis['is_suspicious']:
            severity = 'critical' if analysis['threat_score'] >= 0.8 else 'high'
            
            event = SecurityEvent.objects.create(
                organization=agent.organization,
                module='edr',
                event_type='suspicious_process',
                severity=severity,
                title=f"Proceso sospechoso detectado: {data.get('process_name')}",
                description=f"Host: {agent.hostname}\nUsuario: {data.get('user')}\n"
                           f"Comando: {data.get('command_line')}\n\n"
                           f"Indicadores:\n" + "\n".join(f"- {ind}" for ind in analysis['indicators']),
                source_ip=agent.ip_address,
                raw_data=data,
                ai_confidence=analysis['threat_score'],
            )
            
            # Acción automática si es malicioso
            if analysis['verdict'] == 'malicious':
                action_taken = 'block'
                process.blocked = True
                process.action_taken = 'blocked'
                process.save()
                
                event.action_taken = 'blocked_process'
                event.action_details = {
                    'process_id': data.get('process_id'),
                    'process_name': data.get('process_name')
                }
                event.save()
        
        # Detectar movimiento lateral
        lateral_movement = EDRAnalyzer.detect_lateral_movement(agent)
        if lateral_movement:
            SecurityEvent.objects.create(
                organization=agent.organization,
                module='edr',
                event_type='lateral_movement',
                severity='high',
                title=f"Posible movimiento lateral detectado en {agent.hostname}",
                description=f"Actividades sospechosas:\n" + 
                           "\n".join(f"- {lm['type']}: {lm['command']}" for lm in lateral_movement),
                source_ip=agent.ip_address,
                raw_data={'lateral_indicators': lateral_movement},
            )
        
        return JsonResponse({
            'success': True,
            'process_id': process.id,
            'verdict': analysis['verdict'],
            'threat_score': analysis['threat_score'],
            'action': action_taken,
            'indicators': analysis['indicators']
        })
        
    except EDRAgent.DoesNotExist:
        return JsonResponse({'error': 'Agent not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def edr_dashboard(request, org_id):
    """Dashboard EDR"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.edr_enabled:
            return JsonResponse({'error': 'EDR not enabled'}, status=403)
        
        agents = EDRAgent.objects.filter(organization=organization)
        
        cutoff = timezone.now() - timedelta(hours=24)
        
        # Procesos sospechosos recientes
        suspicious_processes = EDRProcess.objects.filter(
            agent__organization=organization,
            is_suspicious=True,
            timestamp__gte=cutoff
        ).select_related('agent').order_by('-timestamp')[:50]
        
        stats = {
            'total_agents': agents.count(),
            'online_agents': agents.filter(status='online').count(),
            'offline_agents': agents.filter(status='offline').count(),
            'suspicious_processes_24h': suspicious_processes.count(),
            'blocked_processes_24h': suspicious_processes.filter(blocked=True).count(),
            
            'agents': [{
                'id': str(a.agent_id),
                'hostname': a.hostname,
                'ip': a.ip_address,
                'os': f"{a.os_type} {a.os_version}",
                'status': a.status,
                'last_seen': a.last_seen.isoformat(),
            } for a in agents],
            
            'suspicious_processes': [{
                'id': p.id,
                'timestamp': p.timestamp.isoformat(),
                'agent': p.agent.hostname,
                'process_name': p.process_name,
                'command_line': p.command_line[:200],
                'threat_score': p.threat_score,
                'verdict': p.ai_verdict,
                'blocked': p.blocked,
            } for p in suspicious_processes]
        }
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def register_agent(request, org_id):
    """Registra un nuevo agente EDR"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.edr_enabled:
            return JsonResponse({'error': 'EDR not enabled'}, status=403)
        
        data = json.loads(request.body)
        
        agent, created = EDRAgent.objects.get_or_create(
            organization=organization,
            hostname=data.get('hostname'),
            defaults={
                'ip_address': data.get('ip_address'),
                'os_type': data.get('os_type'),
                'os_version': data.get('os_version'),
                'agent_version': data.get('agent_version', '1.0.0'),
                'status': 'online',
            }
        )
        
        if not created:
            agent.ip_address = data.get('ip_address')
            agent.status = 'online'
            agent.last_seen = timezone.now()
            agent.save()
        
        return JsonResponse({
            'success': True,
            'agent_id': str(agent.agent_id),
            'message': 'Agent registered' if created else 'Agent updated'
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Template views for web dashboard
from django.contrib.auth.decorators import login_required

@login_required
def edr_dashboard_view(request):
    """EDR dashboard template view"""
    organization = request.user.profile.organization
    
    if not organization.subscription.edr_enabled:
        return render(request, 'dashboard/module_disabled.html', {
            'module_name': 'EDR',
            'plan_required': 'Pro'
        })
    
    # Get agents
    agents = EDRAgent.objects.filter(organization=organization).order_by('-last_seen')
    
    # Get stats
    now = timezone.now()
    active_threshold = now - timedelta(minutes=15)
    
    stats = {
        'total_agents': agents.count(),
        'active_agents': agents.filter(status='active', last_seen__gte=active_threshold).count(),
        'offline_agents': agents.filter(last_seen__lt=active_threshold).count(),
        'threats_detected': SecurityEvent.objects.filter(
            organization=organization,
            event_type='edr',
            severity__in=['critical', 'high']
        ).count(),
    }
    
    context = {
        'agents': agents,
        'stats': stats,
        'organization': organization,
    }
    
    return render(request, 'edr/dashboard.html', context)
