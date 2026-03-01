#!/usr/bin/env python
"""
Quick setup script for Jorise SOC
Creates demo organization and sample data
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

from core.models import (
    Organization, Subscription, SecurityEvent,
    ThreatIntelligence, EDRAgent, WAFRule
)
from django.utils import timezone
from datetime import timedelta
import uuid


def create_demo_organization():
    """Create demo organization with all modules enabled"""
    print("🏢 Creating demo organization...")
    
    org, created = Organization.objects.get_or_create(
        domain="demo.jorise.com",
        defaults={
            'name': 'Demo Organization',
            'is_active': True
        }
    )
    
    if created:
        print(f"   ✅ Organization created: {org.name}")
    else:
        print(f"   ℹ️  Organization already exists: {org.name}")
    
    # Create Enterprise subscription
    subscription, created = Subscription.objects.get_or_create(
        organization=org,
        defaults={
            'plan': 'enterprise',
            'status': 'active',
            'siem_enabled': True,
            'edr_enabled': True,
            'waf_enabled': True,
            'antivirus_enabled': True,
            'sandbox_enabled': True,
            'ai_analysis_enabled': True,
            'max_events_per_month': 1000000,
            'max_endpoints': 1000,
            'max_api_calls_per_day': 100000,
        }
    )
    
    if created:
        print(f"   ✅ Enterprise subscription created")
    else:
        print(f"   ℹ️  Subscription already exists")
    
    print(f"\n📋 Organization ID: {org.id}")
    print(f"   Use this ID in API calls: /api/soc/{org.id}/")
    
    return org


def create_sample_events(org):
    """Create sample security events"""
    print("\n🔔 Creating sample security events...")
    
    events_data = [
        {
            'module': 'edr',
            'event_type': 'malware_detected',
            'severity': 'critical',
            'title': 'Ransomware WannaCry detectado',
            'description': 'Ransomware WannaCry detectado en endpoint LAPTOP-001. Proceso bloqueado automáticamente.',
            'source_ip': '192.168.1.100',
        },
        {
            'module': 'waf',
            'event_type': 'sql_injection',
            'severity': 'high',
            'title': 'SQL Injection bloqueado',
            'description': 'Intento de SQL Injection en /api/users. Ataque bloqueado.',
            'source_ip': '203.0.113.45',
        },
        {
            'module': 'siem',
            'event_type': 'brute_force',
            'severity': 'high',
            'title': 'Ataque de fuerza bruta detectado',
            'description': 'Múltiples intentos de login fallidos desde 198.51.100.23',
            'source_ip': '198.51.100.23',
        },
        {
            'module': 'sandbox',
            'event_type': 'malware_detected',
            'severity': 'high',
            'title': 'Archivo malicioso en sandbox',
            'description': 'Archivo suspicious.exe identificado como Trojan.Generic',
            'source_ip': None,
        },
        {
            'module': 'edr',
            'event_type': 'lateral_movement',
            'severity': 'medium',
            'title': 'Posible movimiento lateral',
            'description': 'Actividad sospechosa de red detectada en SERVER-02',
            'source_ip': '192.168.1.50',
        },
    ]
    
    for event_data in events_data:
        SecurityEvent.objects.create(
            organization=org,
            timestamp=timezone.now() - timedelta(hours=2),
            **event_data
        )
    
    print(f"   ✅ Created {len(events_data)} sample events")


def create_threat_intelligence():
    """Create sample threat intelligence entries"""
    print("\n🎯 Creating threat intelligence data...")
    
    threats_data = [
        {
            'ioc_type': 'ip',
            'ioc_value': '198.51.100.23',
            'threat_level': 'high',
            'description': 'Known malicious IP - Brute force attacks',
            'source': 'AlienVault OTX',
        },
        {
            'ioc_type': 'hash_sha256',
            'ioc_value': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'threat_level': 'critical',
            'description': 'WannaCry ransomware sample',
            'source': 'VirusTotal',
        },
        {
            'ioc_type': 'domain',
            'ioc_value': 'malicious-site.com',
            'threat_level': 'high',
            'description': 'Phishing domain distributing malware',
            'source': 'Jorise Sandbox',
        },
    ]
    
    for threat_data in threats_data:
        ThreatIntelligence.objects.get_or_create(
            ioc_type=threat_data['ioc_type'],
            ioc_value=threat_data['ioc_value'],
            defaults=threat_data
        )
    
    print(f"   ✅ Created {len(threats_data)} threat intelligence entries")


def create_edr_agents(org):
    """Create sample EDR agents"""
    print("\n💻 Creating sample EDR agents...")
    
    agents_data = [
        {
            'hostname': 'LAPTOP-001',
            'ip_address': '192.168.1.100',
            'os_type': 'Windows',
            'os_version': 'Windows 11 Pro',
            'status': 'online',
            'agent_version': '1.0.0',
        },
        {
            'hostname': 'SERVER-02',
            'ip_address': '192.168.1.50',
            'os_type': 'Linux',
            'os_version': 'Ubuntu 22.04 LTS',
            'status': 'online',
            'agent_version': '1.0.0',
        },
        {
            'hostname': 'WORKSTATION-03',
            'ip_address': '192.168.1.101',
            'os_type': 'Windows',
            'os_version': 'Windows 10 Enterprise',
            'status': 'offline',
            'agent_version': '1.0.0',
        },
    ]
    
    for agent_data in agents_data:
        EDRAgent.objects.get_or_create(
            organization=org,
            hostname=agent_data['hostname'],
            defaults=agent_data
        )
    
    print(f"   ✅ Created {len(agents_data)} EDR agents")


def create_waf_rules(org):
    """Create sample WAF rules"""
    print("\n🛡️  Creating sample WAF rules...")
    
    rules_data = [
        {
            'name': 'Block SQL Injection',
            'description': 'Blocks common SQL injection patterns',
            'rule_type': 'sql_injection',
            'pattern': r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
            'severity': 'high',
            'action': 'block',
            'is_enabled': True,
        },
        {
            'name': 'Block XSS Attempts',
            'description': 'Blocks cross-site scripting attacks',
            'rule_type': 'xss',
            'pattern': r"<script[^>]*>.*?</script>",
            'severity': 'high',
            'action': 'block',
            'is_enabled': True,
        },
        {
            'name': 'Rate Limiting',
            'description': 'Rate limit to 100 requests per minute',
            'rule_type': 'rate_limit',
            'pattern': r".*",
            'severity': 'medium',
            'action': 'challenge',
            'is_enabled': True,
        },
    ]
    
    for rule_data in rules_data:
        WAFRule.objects.get_or_create(
            organization=org,
            name=rule_data['name'],
            defaults=rule_data
        )
    
    print(f"   ✅ Created {len(rules_data)} WAF rules")


def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║           JORISE SOC - QUICK SETUP SCRIPT                 ║
║     Enterprise Security Operations Center with AI         ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Create demo organization
        org = create_demo_organization()
        
        # Create sample data
        create_sample_events(org)
        create_threat_intelligence()
        create_edr_agents(org)
        create_waf_rules(org)
        
        print("""
╔═══════════════════════════════════════════════════════════╗
║                  ✅ SETUP COMPLETED!                      ║
╚═══════════════════════════════════════════════════════════╝

📋 Next steps:

1. Start Django server:
   python manage.py runserver 8000

2. Start Celery worker:
   celery -A jorise worker -l info --pool=solo

3. Access SOC Dashboard API:
   GET http://localhost:8000/api/soc/{}/dashboard/

4. Start Astro frontend:
   cd ../.. && npm run dev

5. Access landing page:
   http://localhost:4321

🎉 Your Enterprise SOC is ready to use!
        """.format(org.id))
        
    except Exception as e:
        print(f"\n❌ Error during setup: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
