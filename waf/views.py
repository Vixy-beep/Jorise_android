"""
WAF (Web Application Firewall) Module  
IA-powered web attack detection and blocking
"""

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.utils import timezone
from django.db.models import Count
from datetime import timedelta
import json
import re
from core.models import (
    SecurityEvent, WAFRule, WAFLog,
    Organization, UsageMetrics
)

# Motor ML de Jorise
try:
    from training.jorise_engine import JoriseEngine as _JoriseEngine
    JORISE_ML_AVAILABLE = True
except Exception:
    _JoriseEngine = None
    JORISE_ML_AVAILABLE = False


class WAFAnalyzer:
    """Motor de análisis WAF con IA"""
    
    # Patrones de ataque conocidos
    ATTACK_PATTERNS = {
        'sql_injection': [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
        ],
        'xss': [
            r"<script[^>]*>.*?</script>",
            r"javascript\s*:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"eval\s*\(",
            r"expression\s*\(",
        ],
        'lfi': [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"c:\\windows",
            r"boot\.ini",
        ],
        'command_injection': [
            r";\s*(ls|cat|wget|curl|nc|bash|sh)",
            r"\|\s*(ls|cat|wget|curl)",
            r"`.*`",
            r"\$\(.*\)",
        ],
        'xxe': [
            r"<!DOCTYPE[^>]*\[.*\]>",
            r"<!ENTITY",
            r"SYSTEM\s+['\"]",
        ],
    }
    
    @staticmethod
    def analyze_request(request_data):
        """Analiza una petición HTTP en busca de amenazas"""
        threat_score = 0.0
        rules_triggered = []
        attack_types = []
        
        method = request_data.get('method', '').upper()
        url = request_data.get('url', '')
        headers = request_data.get('headers', {})
        body = request_data.get('body', '')
        user_agent = headers.get('User-Agent', '')
        
        # Combinar todos los datos para análisis
        full_data = f"{url} {body} {json.dumps(headers)}"
        
        # 1. Verificar patrones de ataque
        for attack_type, patterns in WAFAnalyzer.ATTACK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, full_data, re.IGNORECASE):
                    threat_score += 0.3
                    rules_triggered.append(f"{attack_type}_{pattern[:20]}")
                    if attack_type not in attack_types:
                        attack_types.append(attack_type)
        
        # 2. User-Agent sospechoso
        suspicious_uas = ['sqlmap', 'nikto', 'nmap', 'masscan', 'burp', 'metasploit']
        if any(ua in user_agent.lower() for ua in suspicious_uas):
            threat_score += 0.5
            rules_triggered.append('suspicious_user_agent')
            attack_types.append('scanning')
        
        # 3. Método HTTP inusual
        if method in ['TRACE', 'TRACK', 'CONNECT']:
            threat_score += 0.2
            rules_triggered.append('unusual_http_method')
        
        # 4. Tamaño de body sospechoso (muy grande = posible DoS)
        if len(body) > 100000:  # 100KB
            threat_score += 0.3
            rules_triggered.append('large_body_size')
        
        # 5. Headers malformados
        if 'Host' not in headers:
            threat_score += 0.2
            rules_triggered.append('missing_host_header')
        
        # 6. Path traversal
        if '../' in url or '..\\' in url:
            threat_score += 0.4
            rules_triggered.append('path_traversal')
            attack_types.append('lfi')
        
        # Normalizar score
        threat_score = min(threat_score, 1.0)
        
        # 7. Jorise ML — modelo entrenado en WebAttacks (XSS/SQLi/BruteForce)
        if JORISE_ML_AVAILABLE and _JoriseEngine is not None:
            try:
                ml_result = _JoriseEngine.analyze_http_request(request_data)
                if ml_result.is_threat and ml_result.threat_score > threat_score:
                    threat_score = ml_result.threat_score
                    rules_triggered.append(f'jorise_ml:{ml_result.attack_type}')
                    if ml_result.attack_type not in attack_types:
                        attack_types.append(ml_result.attack_type)
            except Exception:
                pass
        
        # Decidir acción
        if threat_score >= 0.7:
            action = 'block'
        elif threat_score >= 0.4:
            action = 'challenge'
        else:
            action = 'allow'
        
        return {
            'threat_score': threat_score,
            'action': action,
            'rules_triggered': rules_triggered,
            'attack_types': attack_types,
            'blocked': action == 'block'
        }
    
    @staticmethod
    def apply_custom_rules(request_data, organization):
        """Aplica reglas personalizadas de la organización"""
        rules = WAFRule.objects.filter(
            organization=organization,
            is_enabled=True
        )
        
        triggered_rules = []
        max_severity = 'info'
        
        for rule in rules:
            full_data = f"{request_data.get('url')} {request_data.get('body')} {json.dumps(request_data.get('headers', {}))}"
            
            if re.search(rule.pattern, full_data, re.IGNORECASE):
                triggered_rules.append({
                    'rule_id': rule.id,
                    'name': rule.name,
                    'action': rule.action,
                    'severity': rule.severity,
                })
                
                # Actualizar estadísticas
                rule.times_triggered += 1
                rule.last_triggered = timezone.now()
                rule.save()
                
                # Guardar severidad máxima
                severities = ['info', 'low', 'medium', 'high', 'critical']
                if severities.index(rule.severity) > severities.index(max_severity):
                    max_severity = rule.severity
        
        return triggered_rules, max_severity
    
    @staticmethod
    def detect_rate_limit(source_ip, organization, window_minutes=1, threshold=100):
        """Detecta rate limiting / DoS"""
        cutoff = timezone.now() - timedelta(minutes=window_minutes)
        
        recent_requests = WAFLog.objects.filter(
            organization=organization,
            source_ip=source_ip,
            timestamp__gte=cutoff
        ).count()
        
        if recent_requests > threshold:
            return True, recent_requests
        
        return False, recent_requests


@require_http_methods(["POST"])
def analyze_request(request, org_id):
    """Analiza una petición HTTP"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.waf_enabled:
            return JsonResponse({'error': 'WAF not enabled'}, status=403)
        
        data = json.loads(request.body)
        
        # Análisis automático
        analysis = WAFAnalyzer.analyze_request(data)
        
        # Aplicar reglas personalizadas
        custom_rules, max_severity = WAFAnalyzer.apply_custom_rules(data, organization)
        
        # Verificar si la IP está bloqueada manualmente
        source_ip = data.get('source_ip')
        ip_is_blocked = WAFRule.objects.filter(
            organization=organization,
            rule_type='ip_block',
            pattern=source_ip,
            is_enabled=True,
        ).exists()
        if ip_is_blocked:
            analysis['action'] = 'block'
            analysis['blocked'] = True
            analysis['rules_triggered'].append('manual_ip_block')

        # Verificar rate limiting
        is_rate_limited, request_count = WAFAnalyzer.detect_rate_limit(source_ip, organization)
        
        if is_rate_limited:
            analysis['action'] = 'block'
            analysis['rules_triggered'].append(f'rate_limit_exceeded_{request_count}')
        
        # Crear log
        waf_log = WAFLog.objects.create(
            organization=organization,
            method=data.get('method'),
            url=data.get('url'),
            headers=data.get('headers', {}),
            body=data.get('body', ''),
            source_ip=source_ip,
            user_agent=data.get('headers', {}).get('User-Agent', ''),
            blocked=analysis['blocked'],
            rules_triggered=analysis['rules_triggered'] + [r['name'] for r in custom_rules],
            threat_score=analysis['threat_score'],
            action_taken=analysis['action'],
        )
        
        # Si bloqueado, crear evento
        if analysis['blocked']:
            SecurityEvent.objects.create(
                organization=organization,
                module='waf',
                event_type='attack_blocked',
                severity=max_severity if custom_rules else 'medium',
                title=f"Ataque web bloqueado desde {source_ip}",
                description=f"Tipos de ataque: {', '.join(analysis['attack_types']) if analysis['attack_types'] else 'Genérico'}\n"
                           f"URL: {data.get('url')}\n"
                           f"Reglas activadas: {len(analysis['rules_triggered'])}\n"
                           f"Score: {analysis['threat_score']:.2f}",
                source_ip=source_ip,
                raw_data=data,
                ai_confidence=analysis['threat_score'],
                action_taken='blocked',
            )
        
        # Actualizar métricas
        today = timezone.now().date()
        metrics, _ = UsageMetrics.objects.get_or_create(
            organization=organization,
            date=today
        )
        metrics.api_calls_count += 1
        metrics.save()
        
        return JsonResponse({
            'success': True,
            'action': analysis['action'],
            'blocked': analysis['blocked'],
            'threat_score': analysis['threat_score'],
            'attack_types': analysis['attack_types'],
            'rules_triggered': len(analysis['rules_triggered']),
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def waf_dashboard(request, org_id):
    """Dashboard WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.waf_enabled:
            return JsonResponse({'error': 'WAF not enabled'}, status=403)
        
        cutoff = timezone.now() - timedelta(hours=24)
        
        logs = WAFLog.objects.filter(
            organization=organization,
            timestamp__gte=cutoff
        )
        
        stats = {
            'total_requests': logs.count(),
            'blocked_requests': logs.filter(blocked=True).count(),
            'allowed_requests': logs.filter(blocked=False).count(),
            
            'top_blocked_ips': list(
                logs.filter(blocked=True)
                .values('source_ip')
                .annotate(count=Count('id'))
                .order_by('-count')[:10]
            ),
            
            'recent_blocks': [{
                'timestamp': log.timestamp.isoformat(),
                'source_ip': log.source_ip,
                'method': log.method,
                'url': log.url[:100],
                'threat_score': log.threat_score,
                'rules_triggered': len(log.rules_triggered),
            } for log in logs.filter(blocked=True).order_by('-timestamp')[:20]],
            
            'active_rules': WAFRule.objects.filter(
                organization=organization,
                is_enabled=True
            ).count(),
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
def create_rule(request, org_id):
    """Crea una nueva regla WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        
        if not organization.subscription.waf_enabled:
            return JsonResponse({'error': 'WAF not enabled'}, status=403)
        
        data = json.loads(request.body)
        
        rule = WAFRule.objects.create(
            organization=organization,
            name=data.get('name'),
            description=data.get('description', ''),
            rule_type=data.get('rule_type', 'custom'),
            pattern=data.get('pattern'),
            severity=data.get('severity', 'medium'),
            action=data.get('action', 'alert'),
            is_enabled=data.get('is_enabled', True),
        )
        
        return JsonResponse({
            'success': True,
            'rule_id': rule.id,
            'message': 'Rule created successfully'
        })
        
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def list_rules(request, org_id):
    """Lista todas las reglas WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        rules = WAFRule.objects.filter(organization=organization).order_by('-created_at')
        return JsonResponse({
            'success': True,
            'rules': [{
                'id': r.id,
                'name': r.name,
                'rule_type': r.rule_type,
                'severity': r.severity,
                'action': r.action,
                'is_enabled': r.is_enabled,
                'times_triggered': r.times_triggered,
                'last_triggered': r.last_triggered.isoformat() if r.last_triggered else None,
                'is_ip_block': r.rule_type == 'ip_block',
            } for r in rules]
        })
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def toggle_rule(request, org_id, rule_id):
    """Activa o desactiva una regla WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        rule = WAFRule.objects.get(id=rule_id, organization=organization)
        rule.is_enabled = not rule.is_enabled
        rule.save()
        return JsonResponse({'success': True, 'is_enabled': rule.is_enabled})
    except (Organization.DoesNotExist, WAFRule.DoesNotExist):
        return JsonResponse({'error': 'Not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def delete_rule(request, org_id, rule_id):
    """Elimina una regla WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        rule = WAFRule.objects.get(id=rule_id, organization=organization)
        rule.delete()
        return JsonResponse({'success': True})
    except (Organization.DoesNotExist, WAFRule.DoesNotExist):
        return JsonResponse({'error': 'Not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def block_ip(request, org_id):
    """Bloquea una IP creando una regla WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        data = json.loads(request.body)
        ip = data.get('ip', '').strip()
        reason = data.get('reason', 'Bloqueado manualmente')

        if not ip:
            return JsonResponse({'error': 'IP requerida'}, status=400)

        # Evitar duplicados
        if WAFRule.objects.filter(organization=organization, rule_type='ip_block', name=f'IP Block: {ip}').exists():
            return JsonResponse({'error': 'IP ya bloqueada'}, status=400)

        rule = WAFRule.objects.create(
            organization=organization,
            name=f'IP Block: {ip}',
            description=reason,
            rule_type='ip_block',
            pattern=ip,
            severity='high',
            action='block',
            is_enabled=True,
        )
        return JsonResponse({'success': True, 'rule_id': rule.id, 'ip': ip})
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["POST"])
def unblock_ip(request, org_id):
    """Desbloquea una IP eliminando su regla WAF"""
    try:
        organization = Organization.objects.get(id=org_id)
        data = json.loads(request.body)
        ip = data.get('ip', '').strip()

        deleted, _ = WAFRule.objects.filter(
            organization=organization,
            rule_type='ip_block',
            name=f'IP Block: {ip}'
        ).delete()
        if deleted:
            return JsonResponse({'success': True})
        return JsonResponse({'error': 'IP no estaba bloqueada'}, status=404)
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@require_http_methods(["GET"])
def list_blocked_ips(request, org_id):
    """Lista las IPs bloqueadas manualmente"""
    try:
        organization = Organization.objects.get(id=org_id)
        rules = WAFRule.objects.filter(
            organization=organization,
            rule_type='ip_block',
        ).order_by('-created_at')
        return JsonResponse({
            'success': True,
            'blocked_ips': [{
                'rule_id': r.id,
                'ip': r.pattern,
                'reason': r.description,
                'blocked_at': r.created_at.isoformat(),
                'is_enabled': r.is_enabled,
            } for r in rules]
        })
    except Organization.DoesNotExist:
        return JsonResponse({'error': 'Organization not found'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# Template views for web dashboard
from django.contrib.auth.decorators import login_required

@login_required
def waf_dashboard_view(request):
    """WAF dashboard template view"""
    organization = request.user.profile.organization
    
    if not organization.subscription.waf_enabled:
        return render(request, 'dashboard/module_disabled.html', {
            'module_name': 'WAF',
            'plan_required': 'Pro'
        })
    
    # Get recent logs
    recent_logs = WAFLog.objects.filter(
        organization=organization
    ).order_by('-timestamp')[:50]
    
    # Get stats
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    
    stats = {
        'total_requests': WAFLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h
        ).count(),
        'blocked_requests': WAFLog.objects.filter(
            organization=organization,
            timestamp__gte=last_24h,
            blocked=True
        ).count(),
        'active_rules': WAFRule.objects.filter(
            organization=organization,
            is_enabled=True
        ).count(),
    }
    
    context = {
        'recent_logs': recent_logs,
        'stats': stats,
        'organization': organization,
    }
    
    return render(request, 'waf/dashboard.html', context)
