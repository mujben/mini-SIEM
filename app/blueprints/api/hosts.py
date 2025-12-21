#import time
from flask import Blueprint, jsonify, request, current_app
from datetime import timezone, datetime
#import os

from app.models import Host, LogSource, LogArchive, Alert, IPRegistry
from app.services.remote_client import RemoteClient
from app.services.win_client import WinClient
from app.services.log_collector import LogCollector
from app.services.data_manager import DataManager
from app.services.log_analyzer import LogAnalyzer
from app.extensions import db


api_bp = Blueprint("api_hosts", __name__)

@api_bp.route("/hosts", methods=["GET"])
def get_hosts():
    hosts = Host.query.all()
    return jsonify([h.to_dict() for h in hosts])

@api_bp.route("/hosts", methods=["POST"])
def add_host() -> tuple:
    data = request.get_json()
    
    if not data:
        return jsonify({"error": "Brak danych"}), 400
    
    if Host.query.filter_by(ip_address=data.get("ip_address")).first():
        return jsonify({"error": "IP musi być unikalne"}), 409
    
    new_host = Host(hostname=data.get("hostname"), ip_address=data.get("ip_address"), os_type=data.get("os_type"))
    db.session.add(new_host)
    db.session.commit()
    
    return jsonify(new_host.to_dict()), 201

@api_bp.route("/hosts/<int:host_id>", methods=["DELETE"])
def delete_host(host_id) -> tuple:
    host = Host.query.get_or_404(host_id)
    db.session.delete(host)
    db.session.commit()
    
    return jsonify({"message": "Usunięto hosta"}), 200

@api_bp.route("/hosts/<int:host_id>", methods=["PUT"])
def update_host(host_id) -> tuple:
    host = Host.query.get_or_404(host_id)
    data = request.get_json()
    if "hostname" in data: host.hostname = data["hostname"]
    if "ip_address" in data: host.ip_address = data["ip_address"]
    if "os_type" in data: host.os_type = data["os_type"]
    db.session.commit()
    
    return jsonify(host.to_dict()), 200

@api_bp.route("/hosts/<int:host_id>/ssh-info", methods=["GET"])
def get_ssh_info(host_id) -> tuple:
    host = Host.query.get_or_404(host_id)
    ssh_user = current_app.config.get("SSH_DEFAULT_USER", "vagrant")
    ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 2222)
    ssh_key = current_app.config.get("SSH_KEY_FILE")
    
    try:
        with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port, key_file=ssh_key) as remote:
            ram_info, _ = remote.run("free -m | grep Mem | awk '{print $7}'")
            disk_percentage, _ = remote.run("df -h | grep '/$' | awk '{print $5}'")
            if not disk_percentage: disk_percentage, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $5}'")
            disk_total, _ = remote.run("df -h | grep '/$' | awk '{print $2}'")
            if not disk_total: disk_total, _ = remote.run("df -h | grep '/dev/sda1' | awk '{print $2}'")
            cpu_load, _ = remote.run("uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1")
            uptime_str, _ = remote.run("cat /proc/uptime | awk '{print $1}'")
            uptime_formatted = "N/A"
            try:
                uptime_seconds = float(uptime_str)
                hrs = int(uptime_seconds // 3600)
                mis = int((uptime_seconds % 3600) // 60)
                uptime_formatted = f"{hrs}h {mis}m"
            except:
                pass
            return jsonify({
                "free_ram_mb": ram_info.strip(),
                "disk_info": disk_percentage.strip(),
                "disk_total": disk_total.strip(),
                "cpu_load": cpu_load.strip(),
                "uptime_hours": uptime_formatted
            }), 200
    except Exception as e:
        return jsonify({"error": f"Błąd połączenia SSH: {str(e)}"}), 500
    
@api_bp.route("/hosts/<int:host_id>/windows-info", methods=["GET"])
def get_windows_info(host_id):
    import psutil
    host = Host.query.get_or_404(host_id)
    if "windows" not in str(host.os_type).lower(): return jsonify({"error": "Wrong OS"}), 400
    
    try:
        mem = psutil.virtual_memory()
        free_ram_mb = str(round(mem.available / (1024 * 1024)))
        cpu_load = f"{psutil.cpu_percent(interval=0.1)}%"
        try:
            usage = psutil.disk_usage("C:\\")
            disk_percentage = f"{usage.percent}%"
            disk_total = f"{round(usage.total / (1024**3), 1)}GB"
        except:
            disk_percentage, disk_total = "N/A", "?"
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        uptime_seconds = (datetime.now() - boot_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return jsonify({
            "free_ram_mb": free_ram_mb, "disk_info": disk_percentage,
            "disk_total": disk_total, "cpu_load": cpu_load, "uptime_hours": f"{hours}h {minutes}m"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@api_bp.route("/hosts/<int:host_id>/logs", methods=["POST"])
def fetch_logs(host_id):
    host = Host.query.get_or_404(host_id)
    
    # Download or create LogSource
    log_source = LogSource.query.filter_by(host_id=host.id).first()
    if not log_source:
        log_source = LogSource(host_id=host.id, log_type='security', last_fetch=None)
        db.session.add(log_source)
        db.session.commit()
    
    # TODO: ZADANIE 2 - INTEGRACJA POBIERANIA LOGÓW
    # Ten endpoint obecnie nic nie robi. Twoim zadaniem jest jego uzupełnienie.
    # Wzoruj się na plikach 'test_real_ssh_logs.py' oraz 'test_windows_logs.py'.
    # 1. Sprawdź host.os_type (LINUX vs WINDOWS).
    os_type = host.os_type.lower()
    logs_data = []
    # 2. Użyj odpowiedniego klienta (RemoteClient lub WinClient).
    # 3. Wywołaj LogCollector.get_linux_logs (lub windows) aby pobrać listę zdarzeń.
    # 4. WAŻNE: Zapisz pobrane logi do pliku Parquet używając DataManager.save_logs_to_parquet().
    #    Metoda ta zwróci nazwę pliku (filename).
    try:
        if "windows" in os_type.lower():
            win_client = WinClient(host=host.ip_address)
            logs_data = LogCollector.get_windows_logs(win_client, log_source.last_fetch)

        elif "linux" in os_type.lower():
            ssh_user = current_app.config.get("SSH_DEFAULT_USER", "vagrant")
            ssh_port = current_app.config.get("SSH_DEFAULT_PORT", 2222)
            ssh_key = current_app.config.get("SSH_KEY_FILE")
            
            with RemoteClient(host=host.ip_address, user=ssh_user, port=ssh_port, key_file=ssh_key) as remote:
                logs_data = LogCollector.get_linux_logs(remote)
        else:
            return jsonify({"error": "Unsupported OS type"}), 400
        
        if not logs_data:
            return jsonify({"message": "No logs fetched", "alerts": 0}), 200
        filename = DataManager.save_logs_to_parquet(logs_data, host.id)
        # 5. Zaktualizuj log_source.last_fetch na bieżący czas.
        log_source.last_fetch = datetime.now(timezone.utc)
        # 6. Dodaj wpis do LogArchive (historia pobrań).
        log_archive = LogArchive(host_id=host.id, timestamp=datetime.now(timezone.utc), filename=filename, record_count=len(logs_data))
        db.session.add(log_archive)
        # KROKI DO WYKONANIA:
        # 7. Wywołaj LogAnalyzer.analyze_parquet(filename, host.id) aby wykryć zagrożenia.
        alerts_count = LogAnalyzer.analyze_parquet(filename, host.id)
        db.session.commit()

        return jsonify({
            "message": "Logs fetched successfully",
            "count": len(logs_data),
            "alerts": alerts_count,
            "filename": filename
        }), 200
    except Exception as e:
        db.session.rollback()
        print(f"Error fetching logs for host {host.id}")
        return jsonify({"error": str(e)}), 500

@api_bp.route("/ips", methods=["GET"])
def get_ips():
    ips = IPRegistry.query.order_by(IPRegistry.last_seen.desc()).all()
    results = [{
        "id": ip.id,
        "ip_address": ip.ip_address,
        "status": ip.status,
        "last_seen": ip.last_seen.isoformat() if ip.last_seen else None
    } for ip in ips]
    
    return jsonify(results), 200


@api_bp.route("/ips", methods=["POST"])
def add_ip():
    data = request.get_json()
    if not data or "ip_address" not in data:
        return jsonify({"error": "Brak adresu IP"}), 400
    
    # Check if IP already exists
    if IPRegistry.query.filter_by(ip_address=data["ip_address"]).first():
        return jsonify({"error": "IP już istnieje w rejestrze"}), 409

    new_ip = IPRegistry(
        ip_address=data["ip_address"],
        status=data.get("status", "unknown"),
        last_seen=datetime.now(timezone.utc)
    )
    db.session.add(new_ip)
    db.session.commit()
    
    return jsonify({"message": "Dodano IP", "id": new_ip.id}), 201

@api_bp.route("/ips/<int:ip_id>", methods=["PUT"])
def update_ip(ip_id):
    ip_reg = IPRegistry.query.get_or_404(ip_id)
    data = request.get_json()
    
    if "status" in data:
        ip_reg.status = data["status"]
    
    ip_reg.last_seen = datetime.now(timezone.utc)
    
    db.session.commit()
    
    return jsonify({"message": "Zaktualizowano status IP"}), 200

@api_bp.route("/ips/<int:ip_id>", methods=["DELETE"])
def delete_ip(ip_id):
    ip_reg = IPRegistry.query.get_or_404(ip_id)
    db.session.delete(ip_reg)
    db.session.commit()

    return jsonify({"message": "Usunięto wpis IP"}), 200

@api_bp.route("/alerts", methods=["GET"])
def get_recent_alerts():
    # Return 20 most recent alerts
    alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(20).all()
    return jsonify([a.to_dict() for a in alerts])
