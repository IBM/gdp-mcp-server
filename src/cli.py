"""Guard CLI client — execute GDP CLI commands over SSH.

The Guard CLI uses a forced ``cli_wrapper`` login shell that only accepts
commands via an interactive PTY (``invoke_shell``).  ``exec_command`` always
fails with "Incorrect number of arguments / Usage: cli_wrapper".
"""

import asyncio
import logging
import re
import time

import paramiko

from .config import GDPConfig

logger = logging.getLogger("gdp_mcp.cli")

# Strip ANSI escape sequences from CLI output
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

# Commands that modify system state — blocked unless confirm_destructive=True
_DESTRUCTIVE_PATTERNS = re.compile(
    r"\b(restart|reboot|shutdown|delete|remove|drop|restore|"
    r"reset|purge|truncate|kill|stop|disable|decommission|"
    r"uninstall|format|wipe)\b",
    re.IGNORECASE,
)

# Guard CLI prompt pattern — e.g. "guardiumdpdp.ibm.com> "
_PROMPT_RE = re.compile(r"[\w.\-]+>\s*$")

# Commands that require interactive input — cannot be automated via paramiko.
# Categories:
#   TUI:        diag, iptraf (curses menu)
#   WIZARD:     configure_*, backup system, restore backup, import file
#   PASSWORD:   change_cli_password, store user password,
#               store alerter smtp authentication password
#   PASTE:      store certificate … console, store cert_key … console,
#               store stap certificate, store certificate rsa_securid console
#   MENU:       store ssl_configuration (cipher toggle)
#   LONG-RUN:   fileserver (blocks until duration expires)
_INTERACTIVE_CMDS = re.compile(
    r"^\s*("
    r"diag|iptraf"
    r"|change_cli_password"
    r"|store\s+user\s+password"
    r"|store\s+alerter\s+smtp\s+authentication\s+password"
    r"|store\s+certificate\s+.*\bconsole\b"
    r"|store\s+cert_key\s+.*\bconsole\b"
    r"|store\s+stap\s+certificate"
    r"|store\s+certificate\s+rsa_securid\s+console"
    r"|store\s+ssl_configuration"
    r"|configure_archive"
    r"|configure_export"
    r"|configure_purge"
    r"|configure_results_archive"
    r"|configure_cold_storage"
    r"|configure_cold_storage_data_streaming"
    r"|backup\s+system"
    r"|restore\s+backup"
    r"|import\s+file"
    r"|fileserver"
    r")\b",
    re.IGNORECASE,
)


class GDPCLIClient:
    """SSH client for the Guard CLI (cli@host:2222)."""

    def __init__(self, config: GDPConfig) -> None:
        self._config = config
        self._available: bool | None = None

    @property
    def configured(self) -> bool:
        return bool(self._config.cli_pass)

    async def execute(
        self,
        command: str,
        confirm_destructive: bool = False,
        timeout: int = 60,
    ) -> str:
        """Execute a Guard CLI command over SSH.

        Args:
            command: The CLI command (e.g. "show system hostname").
            confirm_destructive: Must be True for destructive commands.
            timeout: Total timeout in seconds (banner + command).

        Returns:
            Command output as a string.
        """
        if not self.configured:
            return (
                "Guard CLI is not configured. Set GDP_CLI_PASS in your environment. "
                "Optional: GDP_CLI_HOST (defaults to GDP_HOST), "
                "GDP_CLI_PORT (defaults to 2222), GDP_CLI_USER (defaults to cli)."
            )

        command = command.strip()
        if not command:
            return "No command provided."

        if _INTERACTIVE_CMDS.match(command):
            return (
                f"⚠️ '{command}' requires interactive input (password prompt, "
                f"paste dialog, wizard, or TUI menu) and cannot be automated "
                f"over SSH. Run it manually via: ssh cli@<host> -p 2222"
            )

        if _DESTRUCTIVE_PATTERNS.search(command) and not confirm_destructive:
            return (
                f"⚠️ BLOCKED: '{command}' appears destructive.\n"
                f"This command may modify system state. "
                f"To proceed, call gdp_guard_cli with confirm_destructive=True.\n"
                f"Ask the user for confirmation first."
            )

        return await asyncio.to_thread(
            self._ssh_exec, command, timeout
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_until_prompt(chan: paramiko.Channel, timeout: float) -> str:
        """Read from *chan* until the Guard CLI prompt or *timeout*."""
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                chunk = chan.recv(4096)
                if not chunk:
                    break
                buf += chunk
                text = buf.decode("utf-8", errors="replace")
                # Strip ANSI escapes before checking — the CLI often appends
                # control sequences (e.g. \x1b[K) after the prompt, which
                # breaks the $ anchor in _PROMPT_RE.
                clean_text = _ANSI_RE.sub("", text)
                if _PROMPT_RE.search(clean_text):
                    break
            except Exception:          # socket.timeout
                time.sleep(0.3)
        return buf.decode("utf-8", errors="replace")

    @staticmethod
    def _clean(raw: str, command: str) -> str:
        """Strip ANSI codes, the echoed command, and the trailing prompt."""
        text = _ANSI_RE.sub("", raw).replace("\r", "")
        # Remove the echoed command line
        lines = text.split("\n")
        cleaned: list[str] = []
        for line in lines:
            stripped = line.strip()
            if stripped == command.strip():
                continue
            # Remove trailing prompt line
            if _PROMPT_RE.match(stripped):
                continue
            cleaned.append(line)
        # Trim leading/trailing blank lines
        result = "\n".join(cleaned).strip()
        return result or "(no output)"

    def _ssh_exec(self, command: str, timeout: int) -> str:
        """Open an interactive Guard CLI shell, send *command*, return output."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        host = self._config.cli_host
        port = self._config.cli_port
        user = self._config.cli_user
        password = self._config.cli_pass

        try:
            logger.info("SSH %s@%s:%d — %s", user, host, port, command)
            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=15,
                look_for_keys=False,
                allow_agent=False,
            )

            chan = client.invoke_shell(width=200, height=50)
            chan.settimeout(3)

            # Wait for the CLI banner + prompt (can take 10-15 s)
            banner_timeout = min(timeout * 0.5, 30)
            banner = self._read_until_prompt(chan, banner_timeout)
            logger.debug("CLI banner: %s", banner[:200])

            # Send the command
            chan.send(command + "\n")

            # Read the command output until the next prompt
            cmd_timeout = max(timeout - banner_timeout, 15)
            raw = self._read_until_prompt(chan, cmd_timeout)

            chan.close()
            return self._clean(raw, command)

        except paramiko.AuthenticationException:
            return (
                f"SSH authentication failed for {user}@{host}:{port}. "
                f"Check GDP_CLI_USER and GDP_CLI_PASS."
            )
        except paramiko.SSHException as e:
            return f"SSH error connecting to {host}:{port}: {e}"
        except OSError as e:
            return f"Cannot reach {host}:{port}: {e}"
        finally:
            client.close()
