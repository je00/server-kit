"""管理网站自身的轻量状态，不保存主机配置或敏感数据。"""

from django.conf import settings
from django.db import models


class DismissedNetworkNotice(models.Model):
    """记录用户已经关闭的网络事件提示。"""

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    notice_id = models.CharField(max_length=16)
    dismissed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=("user", "notice_id"),
                name="dashboard_unique_dismissed_network_notice",
            )
        ]
        ordering = ("-dismissed_at",)

