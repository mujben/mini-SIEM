import pandas as pd
from datetime import datetime, timezone, timedelta
from app.extensions import db
from app.models import Alert, IPRegistry, Host
from app.services.data_manager import DataManager

class LogAnalyzer:

    @staticmethod
    def analyze_parquet(filename, host_id):
        # 1. Wczytanie danych
        df = DataManager.load_logs(filename)
        
        if df.empty:
            return 0 
            
        if 'alert_type' not in df.columns or 'source_ip' not in df.columns:
            return 0

        # 2. Filtrowanie: Interesują nas tylko ataki
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN', 'SSH_WINDOWS_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]
        
        if threats.empty:
            return 0

        alerts_created = 0
        
        # 3. Iteracja po zagrożeniach
        for index, row in threats.iterrows():
            ip = row['source_ip']
            user = row.get('user', 'unknown')
            
            # Ignorujemy lokalne
            if ip in ['LOCAL_CONSOLE', '-']:
                continue
            
            # 0. sprawdzenie czy taki sam alert już istnieje
            log_timestamp = row['timestamp']
            existing_alert = Alert.query.filter_by(
                host_id=host_id,
                source_ip=ip,
                alert_type=row['alert_type'],
                timestamp=log_timestamp
            ).first()
            if existing_alert:
                continue

            # 1. Sprawdź, czy IP jest w rejestrze
            ip_record = IPRegistry.query.filter_by(ip_address=ip).first()
            
            if not ip_record:
                # 2. Jeśli nie ma - dodaj jako UNKNOWN
                ip_record = IPRegistry(ip_address=ip, status='UNKNOWN')
                db.session.add(ip_record)
            else:
                # 3. Jeśli jest - zaktualizuj czas
                ip_record.last_seen = datetime.now(timezone.utc)

            # Zadanie dodatkowe 6.1 Cross-Host Correlation
            cross_host_attack = False
            if ip_record.status == 'UNKNOWN':
                ten_min_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
                other_hosts_attacked = Alert.query.filter(
                    Alert.source_ip == ip,
                    Alert.host_id != host_id,
                    Alert.timestamp > ten_min_ago
                ).count()

                if other_hosts_attacked > 0:
                    ip_record.status = 'BANNED'
                    cross_host_attack = True
                    db.session.commit()

            if ip_record.status == 'BANNED' and cross_host_attack:
                severity = 'CRITICAL'
                msg_prefix = "[CROSS-HOST ATTACK DETECTED]"
            elif ip_record.status == 'BANNED':
                severity = 'CRITICAL'
                msg_prefix = "[BANNED IP DETECTED!] "                
            else:  
                severity = 'WARNING'
                msg_prefix = ""

            if ip_record.status == 'TRUSTED':
                continue
            
            # 5. Stwórz Alert
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=f"{msg_prefix}{row.get('message', 'Suspicious activity')}",
                timestamp=log_timestamp
            )
            
            db.session.add(new_alert)
            alerts_created += 1

        db.session.commit()
        return alerts_created
