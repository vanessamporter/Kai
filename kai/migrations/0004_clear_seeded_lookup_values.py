from django.db import migrations


def clear_lookup_values(apps, schema_editor):
    apps.get_model("kai", "LookupValue").objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [("kai", "0003_harden_authentication")]

    operations = [migrations.RunPython(clear_lookup_values, migrations.RunPython.noop)]
