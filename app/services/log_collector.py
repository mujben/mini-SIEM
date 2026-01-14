import re
import json
from datetime import datetime

# needed for logs from failed ssh logins
import win32evtlog
import win32evtlogutil

class LogCollector:
    """
    Pobiera i normalizuje logi z różnych systemów (Linux/Windows).
    """

    # --- KONFIGURACJA LINUX (REGEX) ---
    # Linux w journalctl zwraca treść błędu jako tekst w polu MESSAGE.
    # Musimy użyć Regex, aby wyciągnąć IP i Usera.
    LINUX_PATTERNS = {
        'failed_password': re.compile(r"Failed password for (?:invalid user )?([\w.-]+) from ([\d.]+)"),
        'invalid_user': re.compile(r"Invalid user ([\w.-]+) from ([\d.]+)"),
        'sudo': re.compile(r"sudo:\s+([a-zA-Z0-9._-]+)\s*:"),
    }

    # =========================================================================
    # METODA 1: LINUX (SSH + Journalctl + Regex)
    # =========================================================================
    @staticmethod
    def get_linux_logs(ssh_client, last_fetch_time=None):
        logs = []
        
        # Budowanie komendy: pobierz JSON z journalctl
        cmd = "sudo journalctl -u ssh -o json --no-pager"
        
        if last_fetch_time:
            since_str = last_fetch_time.strftime("%Y-%m-%d %H:%M:%S")
            cmd += f' --since "{since_str}"'
        else:
            cmd += ' --since "7 days ago"' # Domyślny zasięg na start

        print(f"DEBUG [Linux]: Executing {cmd}")
        
        try:
            stdout, stderr = ssh_client.run(cmd)
            
            if not stdout:
                return []

            for line in stdout.splitlines():
                if not line.strip(): continue
                try:
                    # Parsowanie JSON z journald
                    entry = json.loads(line)
                    message = entry.get('MESSAGE', '')
                    
                    # Konwersja czasu (mikrosekundy -> datetime)
                    ts_micro = int(entry.get('__REALTIME_TIMESTAMP', 0))
                    timestamp = datetime.fromtimestamp(ts_micro / 1_000_000)

                    # Analiza treści (Logika Regex)
                    parsed = LogCollector._parse_linux_message(message, timestamp)
                    if parsed:
                        logs.append(parsed)

                except json.JSONDecodeError:
                    continue

        except Exception as e:
            print(f"Error collecting Linux logs: {e}")
            # Nie rzucamy wyjątku, żeby błąd jednego hosta nie zatrzymał procesu dla innych
            return []

        return logs

    @staticmethod
    def _parse_linux_message(message, timestamp):
        # Helper do sprawdzania Regexów
        
        # 1. Failed Password
        match = LogCollector.LINUX_PATTERNS['failed_password'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'FAILED_LOGIN',
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message
            }
        
        # 2. Invalid User
        match = LogCollector.LINUX_PATTERNS['invalid_user'].search(message)
        if match:
            return {
                'timestamp': timestamp,
                'alert_type': 'INVALID_USER',
                'source_ip': match.group(2),
                'user': match.group(1),
                'message': message,
                'raw_log': message
            }

        # 3. Sudo
        match = LogCollector.LINUX_PATTERNS['sudo'].search(message)
        if match:
             return {
                'timestamp': timestamp,
                'alert_type': 'SUDO_USAGE',
                'source_ip': 'LOCAL',
                'user': match.group(1),
                'message': message,
                'raw_log': message
            }
        return None

 # =========================================================================
    # METODA 2: WINDOWS (PowerShell + XML Parsing)
    # =========================================================================
    @staticmethod
    def get_windows_logs(win_client, last_fetch_time=None):
        logs = []
        
        # Budujemy filtr dla PowerShell
        # Jeśli mamy last_fetch_time, pobieramy logi nowsze niż ta data.
        # Jeśli nie (pierwsze uruchomienie), pobieramy 20 ostatnich.
        
        if last_fetch_time:
            # Formatowanie daty dla PowerShell: 'yyyy-MM-dd HH:mm:ss'
            ts_str = last_fetch_time.strftime('%Y-%m-%d %H:%M:%S')
            # StartTime musi być rzutowane na [datetime]
            filter_script = f"@{{LogName='Security'; Id=4625; StartTime=[datetime]'{ts_str}'}}"
            params = "" # Pobierz wszystko od tej daty
        else:
            filter_script = "@{LogName='Security'; Id=4625}"
            params = "-MaxEvents 20" # Domyślny limit na start

        # Komenda PowerShell:
        # 1. Get-WinEvent z filtrem
        # 2. ToXml() -> pozwala wyciągnąć IpAddress niezależnie od języka OS
        # 3. Parsowanie XML i budowanie obiektu JSON
        
        ps_security = (
            f"try{{"
            f"Get-WinEvent -FilterHashtable {filter_script} {params} -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "   $xml = [xml]$_.ToXml(); "
            "   $data = @{}; "
            "   $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }; "
            "   [PSCustomObject]@{ "
            "       Timestamp = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
            "       IpAddress = $data['IpAddress']; "
            "       User = $data['TargetUserName']; "
            "       EventId = $_.Id "
            "   } "
            "} | ConvertTo-Json -Compress"
            f"}} catch {{ }}"
        )
        
        # collecting OpenSSH logs
        ps_ssh = (
            f"try {{"
            f"Get-WinEvent -FilterHashtable @{{LogName='OpenSSH/Operational'; StartTime=[datetime]'{ts_str}'}} -ErrorAction SilentlyContinue | "
            "ForEach-Object { "
            "   if ($_.Message -match 'Failed password for (?:invalid user )?(.+) from ([\\d\\.]+)') { "
            "       [PSCustomObject]@{ "
            "           Timestamp = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'); "
            "           IpAddress = $matches[2]; "
            "           User = $matches[1]; "
            "           Type = 'SSH_WINDOWS_LOGIN' "
            "       } "
            "   } "
            "} | ConvertTo-Json -Compress"
            f"}} catch {{ }}"
        )

        print(f"DEBUG [Windows]: Executing PS commands for (Security, OpenSSH)") 
        for ps_cmd in [ps_security, ps_ssh]:
            try:
                stdout = win_client.run_ps(ps_cmd)
                
                if not stdout:
                    continue # Brak logów lub błąd PS

                try:
                    data = json.loads(stdout)
                except json.JSONDecodeError:
                    print("WinLog Error: Invalid JSON output from PowerShell")
                    continue

                # PowerShell zwraca dict (gdy 1 wynik) lub list (gdy wiele). Ujednolicamy.
                entries = [data] if isinstance(data, dict) else data

                for entry in entries:
                    # Czyste dane ze struktury XML
                    ip = entry.get('IpAddress', 'LOCAL_CONSOLE')
                    if not ip or ip == '-' or ip == '::1': ip = 'LOCAL_CONSOLE'
                    user = entry.get('User', 'UNKNOWN')
                    ts_str = entry.get('Timestamp')

                    alert_type = entry.get('Type', 'WIN_FAILED_LOGIN')                

                    # Konwersja daty (String -> Datetime)
                    try:
                        timestamp = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    except (ValueError, TypeError):
                        timestamp = datetime.now()

                    # Dodajemy do listy w formacie ujednoliconym z Linuxem
                    logs.append({
                        'timestamp': timestamp,
                        'alert_type': alert_type,
                        'source_ip': ip,
                        'user': user,
                        'message': f"{alert_type} for user: {user}",
                        'raw_log': json.dumps(entry)
                    })
                print(f"DEBUG [Windows]: Collected {len(logs)} logs.")
            except Exception as e:
                print(f"Error collecting Windows logs: {e}")
                return []
        return logs