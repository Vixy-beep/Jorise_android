from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='securityevent',
            name='source_country',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='securityevent',
            name='source_city',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name='securityevent',
            name='source_lat',
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='securityevent',
            name='source_lon',
            field=models.FloatField(blank=True, null=True),
        ),
    ]
