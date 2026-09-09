"""交互创建首个超级管理员。"""

from __future__ import annotations

import getpass

from django.contrib.auth import get_user_model, password_validation
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "创建首个 server-kit 超级管理员"

    def add_arguments(self, parser) -> None:
        parser.add_argument("--username", required=True)

    def handle(self, *args, **options) -> None:
        user_model = get_user_model()
        username = options["username"].strip()
        if not username or len(username) > 150:
            raise CommandError("管理员用户名格式不正确")
        existing = user_model.objects.filter(username=username).first()
        if existing:
            if not existing.is_superuser:
                raise CommandError("同名账号存在但不是超级管理员")
            self.stdout.write("超级管理员已存在，未修改密码。")
            return
        password = getpass.getpass("管理密码：")
        confirmation = getpass.getpass("再次输入：")
        if password != confirmation:
            raise CommandError("两次输入的密码不一致")
        candidate = user_model(username=username)
        try:
            password_validation.validate_password(password, candidate)
        except Exception as exc:
            raise CommandError("管理密码不符合安全要求：" + "；".join(exc.messages)) from exc
        user_model.objects.create_superuser(username=username, password=password)
        self.stdout.write(self.style.SUCCESS("首个超级管理员已创建。"))
