import subprocess
import psutil
import logging

class AutonomousEnforcer:
    """Executes real-time, hands-free system isolation without human intervention."""
    
    @staticmethod
    def block_ip_firewall(ip_address: str) -> bool:
        """Applies a real Windows Firewall rule to block malicious traffic."""
        try:
            cmd = f'netsh advfirewall firewall add rule name="Geordie_Block_{ip_address}" dir=in action=block remoteip={ip_address}'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
            return True
        except Exception as e:
            logging.error(f"Failed to block IP {ip_address}: {e}")
            return False

    @staticmethod
    def terminate_malicious_process(process_name: str) -> bool:
        """Scans running processes and terminates matching attack vectors."""
        terminated = False
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    psutil.Process(proc.info['pid']).kill()
                    terminated = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return terminated