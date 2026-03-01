import django, os
os.environ['DJANGO_SETTINGS_MODULE'] = 'jorise.settings'
django.setup()

from training.models import TrainedModel, TrainingJob

print("=== MODELOS ENTRENADOS ===")
models = TrainedModel.objects.select_related('job').all().order_by('created_at')
if not models:
    print("  (ninguno)")
for m in models:
    algo = m.job.algorithm if m.job else "?"
    feats = len(m.features_json) if m.features_json else 0
    print(f"  [{str(m.id)[:8]}] {m.name:35s} | algo={algo:20s} | features={feats} | {m.created_at.strftime('%Y-%m-%d %H:%M')}")

print()
print("=== JOBS ===")
for j in TrainingJob.objects.all().order_by('created_at'):
    ds = j.dataset.name if j.dataset else "?"
    err = (" | ERR: " + j.error_msg[:60]) if j.error_msg else ""
    print(f"  {j.status:10s} | algo={j.algorithm:20s} | {ds}{err}")
