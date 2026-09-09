#!/usr/bin/env python3
"""验证 Linux 节点综合脚本只有一个外部入口。"""

from __future__ import annotations

import platform
import subprocess
import unittest
from pathlib import Path

from web.dashboard.ssh_scripts import SshScriptBundle


class LinuxNodeScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1]
        self.bundle = SshScriptBundle(root / "web" / "dashboard" / "script_templates")

    def test_combined_script_exposes_awg_and_ssh_without_remote_shell_pipe(self) -> None:
        script = self.bundle.download("linux").payload.decode("utf-8")
        for action in (
            "awg-install", "awg-status", "awg-enable", "awg-use", "awg-autostart",
            "awg-disable", "awg-remove", "ssh-menu", "ssh-network-add",
            "lid-status", "lid-ignore", "lid-default", "devtools-menu",
            "devtools-list", "devtools-plan", "devtools-install",
            "userdirs-menu", "userdirs-status", "userdirs-plan", "userdirs-english",
        ):
            self.assertIn(action, script)
        self.assertIn("apt-get install -y amneziawg", script)
        self.assertIn("signed-by=/usr/share/keyrings/amnezia.gpg", script)
        self.assertIn('if [[ "$distribution" == "ubuntu" ]]', script)
        self.assertIn("apt-get install -y ca-certificates curl dkms gnupg", script)
        self.assertIn("apt-get install -y software-properties-common python3-launchpadlib", script)
        self.assertIn("linux-image-cloud-amd64 linux-headers-cloud-amd64", script)
        self.assertIn("HandleLidSwitch=ignore", script)
        self.assertIn("/etc/systemd/logind.conf.d/80-server-kit-lid.conf", script)
        self.assertNotIn("curl | bash", script)
        self.assertNotIn("wget | bash", script)

    def test_developer_tools_use_catalog_and_preview_the_exact_plan(self) -> None:
        script = self.bundle.download("linux").payload.decode("utf-8")
        for tool in ("git", "vim", "codex", "claude", "openclaw", "hermes", "tmux", "mosh", "docker"):
            self.assertIn(f'register_tool "{tool}"', script)
        for marker in (
            "软件目录 + 安装适配器",
            "即将执行以下命令",
            "输入 yes 确认安装",
            'bash "$plan_file"',
            "https://github.com/openai/codex/releases/latest/download/",
            "https://claude.ai/install.sh",
            "https://openclaw.ai/install-cli.sh",
            "https://hermes-agent.nousresearch.com/install.sh",
            "--skip-setup --non-interactive",
            "https://download.docker.com/linux/",
            "Docker 发布容器端口可能绕过 UFW / firewalld",
            "只安装 CLI，不运行 onboarding、不启动 Gateway、不开放端口",
        ):
            self.assertIn(marker, script)
        self.assertNotIn('eval "$plan"', script)
        self.assertIn('[[ "$confirm_option" == "--yes" ]]', script)

    def test_user_directories_are_a_separate_planned_module(self) -> None:
        script = self.bundle.download("linux").payload.decode("utf-8")
        for marker in (
            "###SERVER_KIT_USERDIRS_PAYLOAD###",
            "Debian / Ubuntu 用户目录语言管理器",
            "xdg-user-dirs-update --set",
            "切换为英文目录",
            "即将执行以下命令",
            "输入 yes 确认执行",
            "--yes",
            "不覆盖目标目录中的同名文件",
        ):
            self.assertIn(marker, script)

    @unittest.skipIf(platform.system() == "Windows", "Windows 环境没有可用的原生 Bash")
    def test_developer_tools_plan_and_cancel_cross_the_same_interface(self) -> None:
        template = (
            Path(__file__).resolve().parents[1]
            / "web" / "dashboard" / "script_templates" / "server-kit-devtools-linux.sh"
        )
        preview = subprocess.run(
            ["bash", str(template), "plan", "git,codex"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(preview.returncode, 0, preview.stderr)
        self.assertIn("即将执行以下命令", preview.stdout)
        self.assertIn("apt-get install -y git ca-certificates curl tar", preview.stdout)
        self.assertIn("github.com/openai/codex/releases/latest/download", preview.stdout)
        self.assertIn("这里只显示计划，没有执行安装", preview.stdout)

        cancelled = subprocess.run(
            ["bash", str(template), "install", "git"],
            input="no\n",
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(cancelled.returncode, 0, cancelled.stderr)
        self.assertIn("已取消，没有执行任何安装命令", cancelled.stdout)


if __name__ == "__main__":
    unittest.main()
