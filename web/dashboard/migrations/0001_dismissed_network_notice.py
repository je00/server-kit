"""新增按账号持久化的网络提示关闭记录。"""

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [migrations.swappable_dependency(settings.AUTH_USER_MODEL)]

    operations = [
        migrations.CreateModel(
            name="DismissedNetworkNotice",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("notice_id", models.CharField(max_length=16)),
                ("dismissed_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-dismissed_at",)},
        ),
        migrations.AddConstraint(
            model_name="dismissednetworknotice",
            constraint=models.UniqueConstraint(
                fields=("user", "notice_id"),
                name="dashboard_unique_dismissed_network_notice",
            ),
        ),
    ]

