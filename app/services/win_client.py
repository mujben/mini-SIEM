import subprocess

class WinClient:
    """
    Wrapper for subprocess to run PowerShell locally.
    """
    def __init__(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def run_ps(self, cmd):
        """Executes a PowerShell command and returns the output."""
        full_cmd = ["powershell", "-Command", cmd]
        
        try:
            # encoding='oem' or 'cp852' for Polish Windows
            result = subprocess.run(
                full_cmd, 
                capture_output=True, 
                text=True, 
                encoding='oem' 
            )
            if result.returncode != 0:
                raise Exception(f"PS Error: {result.stderr.strip()}")
            
            return result.stdout.strip()
        except Exception as e:
            raise e

    def get_logs_json(self, log_name, limit=10):
        """Special method to get logs as JSON"""
        ps_cmd = f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} | Select-Object TimeCreated, Id, Message | ConvertTo-Json"
        return self.run_ps(ps_cmd)