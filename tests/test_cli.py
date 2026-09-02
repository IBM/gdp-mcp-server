"""Tests for Guard CLI client — destructive pattern detection and command handling."""

import re

import pytest

from src.cli import _DESTRUCTIVE_PATTERNS, _INTERACTIVE_CMDS, GDPCLIClient
from src.config import GDPConfig


# ── Destructive pattern detection ───────────────────────────────


@pytest.mark.parametrize("cmd", [
    "restart system",
    "reboot appliance",
    "shutdown now",
    "delete backup 2024-01-01",
    "remove stap s-tap-linux",
    "drop audit data",
    "restore backup latest",
    "reset configuration",
    "purge audit trail",
    "truncate logs",
    "kill process 1234",
    "stop inspection_engine",
    "disable monitoring",
    "decommission collector01",
    "uninstall agent",
    "format disk",
    "wipe data",
    "store full-bypass on",
    "store system domain foo",
    "halt",
    "set system hostname x",
    "create user alice",
    "enable inspection_engine",
    "apply policy",
    # Mixed case
    "RESTART system",
    "Delete Backup",
    "PURGE audit trail",
])
def test_destructive_pattern_matches(cmd: str):
    """Known destructive commands should be detected."""
    assert _DESTRUCTIVE_PATTERNS.search(cmd) is not None, f"Should match: {cmd}"


@pytest.mark.parametrize("cmd", [
    "show system info",
    "diag system memory",
    "list inspection_engines",
    "show network interface all",
    "show unit uptime",
    "list datasources",
    "show system storage",
    "diag network traceroute 8.8.8.8",
    "show firewall",
    "list stap",
    # Words that contain destructive substrings but aren't full words
    "show restored_backups",
    "list formatted_reports",
])
def test_safe_pattern_does_not_match(cmd: str):
    """Safe commands should NOT be flagged as destructive."""
    assert _DESTRUCTIVE_PATTERNS.search(cmd) is None, f"Should NOT match: {cmd}"


# ── GDPCLIClient unit tests ────────────────────────────────────


@pytest.fixture
def unconfigured_config(monkeypatch):
    """Returns a GDPConfig with no CLI password."""
    monkeypatch.delenv("GDP_CLI_PASS", raising=False)
    monkeypatch.setenv("GDP_HOST", "test-host")
    return GDPConfig()


@pytest.fixture
def configured_config(monkeypatch):
    """Returns a GDPConfig with CLI password set."""
    monkeypatch.setenv("GDP_HOST", "test-host")
    monkeypatch.setenv("GDP_CLI_PASS", "test-pass")
    monkeypatch.setenv("GDP_CLI_HOST", "cli-host")
    monkeypatch.setenv("GDP_CLI_PORT", "2222")
    monkeypatch.setenv("GDP_CLI_USER", "cli")
    return GDPConfig()


def test_cli_not_configured(unconfigured_config):
    """Client with no password should report not configured."""
    client = GDPCLIClient(unconfigured_config)
    assert client.configured is False


def test_cli_configured(configured_config):
    """Client with password should report configured."""
    client = GDPCLIClient(configured_config)
    assert client.configured is True


@pytest.mark.asyncio
async def test_cli_not_configured_returns_message(unconfigured_config):
    """Executing on unconfigured client should return helpful message."""
    client = GDPCLIClient(unconfigured_config)
    result = await client.execute("show system info")
    assert "not configured" in result.lower()
    assert "GDP_CLI_PASS" in result


@pytest.mark.asyncio
async def test_cli_empty_command(configured_config):
    """Empty command should be rejected."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("")
    assert "no command" in result.lower()


@pytest.mark.asyncio
async def test_cli_destructive_blocked_by_default(configured_config):
    """Destructive commands should be blocked when confirm_destructive=False."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("restart system")
    assert "BLOCKED" in result
    assert "destructive" in result.lower()


@pytest.mark.asyncio
async def test_cli_store_and_halt_blocked_by_default(configured_config):
    """Guardium store/halt verbs need confirm_destructive, same as restart."""
    client = GDPCLIClient(configured_config)
    store = await client.execute("store full-bypass on")
    halt = await client.execute("halt")
    assert "BLOCKED" in store
    assert "BLOCKED" in halt


@pytest.mark.asyncio
async def test_cli_destructive_allowed_when_confirmed(configured_config, mocker):
    """Destructive commands should proceed when confirm_destructive=True (mock SSH)."""
    client = GDPCLIClient(configured_config)
    mocker.patch.object(client, "_ssh_exec", return_value="System restarting...")
    result = await client.execute("restart system", confirm_destructive=True)
    assert result == "System restarting..."


@pytest.mark.asyncio
async def test_cli_ssh_auth_failure(configured_config, mocker):
    """SSH auth failure should return helpful error message."""
    import paramiko
    mocker.patch.object(
        client := GDPCLIClient(configured_config),
        "_ssh_exec",
        side_effect=lambda cmd, timeout: (
            f"SSH authentication failed for cli@cli-host:2222. "
            f"Check GDP_CLI_USER and GDP_CLI_PASS."
        ),
    )
    result = await client.execute("show system info")
    assert "authentication failed" in result.lower()


# ── Interactive command detection ───────────────────────────────


@pytest.mark.parametrize("cmd", [
    # TUI
    "diag",
    "diag system",
    "DIAG",
    "  diag",
    "iptraf",
    "IPTRAF",
    # Password prompts
    "change_cli_password",
    "store user password",
    "STORE USER PASSWORD",
    "store alerter smtp authentication password",
    # Paste / console prompts
    "store certificate gui console",
    "store certificate gim client console",
    "store certificate gim server console",
    "store certificate insights console",
    "store certificate keystore myalias console",
    "store certificate mysql client cert console",
    "store certificate mysql server ca console",
    "store certificate privatekey gim console",
    "store certificate privatekey gui console",
    "store certificate rsa_securid console",
    "store certificate starttls console",
    "store cert_key mysql client console",
    "store cert_key mysql server console",
    "store cert_key sniffer console",
    "store stap certificate",
    # Cipher menu
    "store ssl_configuration",
    # Wizards
    "configure_archive",
    "configure_export",
    "configure_purge",
    "configure_results_archive",
    "configure_cold_storage",
    "configure_cold_storage_data_streaming",
    # Destructive + interactive
    "backup system",
    "backup system DATA",
    "restore backup",
    "import file",
    # Long-running
    "fileserver 10.0.0.1 300",
])
def test_interactive_pattern_matches(cmd: str):
    """Known interactive TUI commands should be detected."""
    assert _INTERACTIVE_CMDS.match(cmd) is not None, f"Should match: {cmd}"


@pytest.mark.parametrize("cmd", [
    "show system hostname",
    "show buffer",
    "store system domain foo",
    "support show hardware-info",
    "show inspection-engines all",
    "show network interface all",
    "store alerter smtp relay 10.0.0.1",
    "store alerter smtp authentication type auth",
    "store alerter smtp authentication username admin",
    "show certificate summary",
    "store certificate gui external",
    "store certificate gim client auto-generate",
    "store certificate keystore myalias external",
    "show stap approval",
    "store stap approval ON",
    "show ssl_configuration",
    "export file /tmp/x user@host:/path",
    "show auth",
    "show account lockout",
    "store account lockout on",
    "store password expiration cli 90",
])
def test_non_interactive_does_not_match(cmd: str):
    """Normal commands should NOT be flagged as interactive."""
    assert _INTERACTIVE_CMDS.match(cmd) is None, f"Should NOT match: {cmd}"


@pytest.mark.asyncio
async def test_cli_interactive_command_blocked(configured_config):
    """Interactive TUI commands should return a warning without SSH."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("diag")
    assert "interactive input" in result.lower()
    assert "cannot be automated" in result.lower()


@pytest.mark.asyncio
async def test_cli_iptraf_blocked(configured_config):
    """iptraf should be blocked as interactive."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("iptraf")
    assert "interactive input" in result.lower()


@pytest.mark.asyncio
async def test_cli_password_prompt_blocked(configured_config):
    """Password prompt commands should be blocked."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("change_cli_password")
    assert "cannot be automated" in result.lower()


@pytest.mark.asyncio
async def test_cli_console_paste_blocked(configured_config):
    """Console paste commands should be blocked."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("store certificate gui console")
    assert "cannot be automated" in result.lower()


@pytest.mark.asyncio
async def test_cli_wizard_blocked(configured_config):
    """Wizard commands should be blocked."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("configure_archive")
    assert "cannot be automated" in result.lower()


@pytest.mark.asyncio
async def test_cli_backup_system_blocked(configured_config):
    """backup system is both interactive and destructive — interactive wins."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("backup system")
    assert "cannot be automated" in result.lower()


@pytest.mark.asyncio
async def test_cli_fileserver_blocked(configured_config):
    """fileserver is a long-running blocking process."""
    client = GDPCLIClient(configured_config)
    result = await client.execute("fileserver 10.0.0.1 300")
    assert "cannot be automated" in result.lower()
