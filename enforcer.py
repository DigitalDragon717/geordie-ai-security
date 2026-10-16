"""Geordie AI – Safe, verified enforcement with elevation detection."""
import subprocess
import logging
import platform
from typing import Tuple

logger = logging.getLogger("geordie.enforcer")

class Enforcer:
    @staticmethod
    def is_windows() -> bool:
        return platform.system().lower() == "windows"

    @staticmethod
    def block_ip(ip: str, dry_run: bool = True) -> Tuple[bool, str, bool]:
        """
        Returns: (success, message, needs_admin)
        needs_admin=True when the failure was caused by missing elevation.
        """
        if not Enforcer.is_windows():
            return False, "Firewall actions are only supported on Windows", False

        # Clean IP for rule name
        safe_ip = ip.split()[0].replace(".", "_")
        rule_name = f"Geordie_Block_{safe_ip}"

        if dry_run:
            return True, f"[DRY-RUN] Would create verified rule '{rule_name}' blocking {ip}", False

        create_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block",
            f"remoteip={ip.split()[0]}", "enable=yes"
        ]

        try:
            result = subprocess.run(create_cmd, capture_output=True, text=True, timeout=15)

            if result.returncode != 0:
                err = (result.stderr or result.stdout or "").lower()
                needs_admin = any(x in err for x in ["access is denied", "requires elevation", "administrator", "privilege"])
                return False, f"Failed: {result.stderr.strip() or result.stdout.strip()}", needs_admin

            # Verify the rule actually exists
            verify = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
                capture_output=True, text=True, timeout=10
            )
            if verify.returncode == 0 and rule_name in verify.stdout:
                return True, f"Rule '{rule_name}' created and verified successfully", False
            return False, "Rule reported success but verification failed", False

        except subprocess.TimeoutExpired:
            return False, "netsh timed out", False
        except Exception as e:
            logger.exception("block_ip error")
            return False, str(e), False