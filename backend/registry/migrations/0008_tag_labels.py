from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registry', '0007_sbom_report'),
    ]

    operations = [
        migrations.AddField(
            model_name='tag',
            name='labels',
            field=models.ManyToManyField(
                to='registry.Label',
                blank=True,
                related_name='tags',
                help_text='Labels attached to this tag within its project.',
            ),
        ),
    ]
