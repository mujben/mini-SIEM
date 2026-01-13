import pandas as pd
from datetime import datetime, timezone
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
        attack_pattern = ['FAILED_LOGIN', 'INVALID_USER', 'WIN_FAILED_LOGIN']
        threats = df[df['alert_type'].isin(attack_pattern)]
        
        if threats.empty:
            return 0

        alerts_created = 0
        
        # 3. Iteracja po zagrożeniach
        for index, row in threats.iterrows():
            ip = row['source_ip']
            user = row.get('user', 'unknown')
            
            # Ignorujemy lokalne
            if ip in ['LOCAL', 'LOCAL_CONSOLE', '127.0.0.1', '::1', '-']:
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

            # 4. Ustal poziom alertu
            severity = 'WARNING'
            msg_prefix = ""

            if ip_record.status == 'BANNED':
                severity = 'CRITICAL'
                msg_prefix = "[BANNED IP DETECTED!] "
            elif ip_record.status == 'TRUSTED':
                continue
            
            # 5. Stwórz Alert
            new_alert = Alert(
                host_id=host_id,
                alert_type=row['alert_type'],
                source_ip=ip,
                severity=severity,
                message=f"{msg_prefix}{row.get('message', 'Suspicious activity')}",
                timestamp=datetime.now(timezone.utc)
            )
            
            db.session.add(new_alert)
            alerts_created += 1

        db.session.commit()
        return alerts_created
