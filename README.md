# 🛡️ Mini-SIEM System (Security Information & Event Management)

System monitorowania bezpieczeństwa infrastruktury IT, zaprojektowany do gromadzenia logów, wykrywania incydentów w czasie rzeczywistym oraz zarządzania bazą Threat Intelligence.

## 🚀 Kluczowe Funkcjonalności

1.  **Dashboard Monitoringu:**
    * Podgląd statusu hostów (Windows/Linux) w czasie rzeczywistym.
    * Tabela alertów bezpieczeństwa z priorytetami (CRITICAL/WARNING).
2.  **Log Collector (ETL):**
    * Pobieranie logów przez SSH (Linux) i PowerShell (Windows).
    * Inteligentne pobieranie przyrostowe (tylko nowe logi).
3.  **Forensics & Retention:**
    * Składowanie surowych logów w formacie **Parquet** (dowody cyfrowe).
4.  **Threat Intelligence Engine:**
    * Automatyczna korelacja adresów IP z wewnętrzną bazą reputacji.
    * Wykrywanie prób logowania z zablokowanych (BANNED) adresów IP.
5.  **Panel Administracyjny:**
    * Zarządzanie hostami i bazą reputacji IP.

## 🛠️ Architektura

Projekt oparty o architekturę Klient-Serwer:
* **Backend:** Python 3.x, Flask, SQLAlchemy, Pandas (analiza danych).
* **Frontend:** Vanilla JS (ES6 Modules), Bootstrap 5.
* **Baza Danych:** SQLite (metadata), Pliki Parquet (surowe logi).

## ⚙️ Instalacja i Uruchomienie

1.  **Klonowanie i środowisko:**
    ```bash
    git clone https://github.com/mujben/mini-SIEM.git
    cd Cyber-lab8-Starter
    python -m venv venv
    # Windows: venv\Scripts\activate | Linux: source venv/bin/activate
    ```

2.  **Instalacja zależności:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Konfiguracja:**
    * Stwórz plik `.env` na podstawie `.env.example`.
    * Upewnij się, że masz klucze SSH (jeśli monitorujesz Linuxa).

4.  **Uruchomienie:**
    ```bash
    flask shell
    >>> db.create_all()
    >>> exit()
    flask run
    ```
    Aplikacja dostępna pod adresem: `http://127.0.0.1:5000`

## 👥 Autorzy

* ** Mikołaj Mitoń (Platform Engineer):** Security Hardening, Uwierzytelnianie, Panel Admina (Hosty), Frontend Configuration.
* ** Zuzanna Kosek (Security Engineer):** Logika SIEM (Analyzer), Obsługa Logów (ETL), API Alertów i Threat Intel, Integracja Dashboardu.

## 🧠 Jak to działa? (Log Flow)

1.  **Trigger:** Użytkownik klika "Logi" na Dashboardzie.
2.  **Collection:** `LogCollector` łączy się zdalnie z maszyną i pobiera 'Failed Logins'.
3.  **Preservation:** Surowe dane są zapisywane do pliku `.parquet` w folderze `storage/`.
4.  **Analysis:** `LogAnalyzer` otwiera plik, wyciąga adresy IP i sprawdza je w tabeli `IPRegistry`.
5.  **Alerting:** Jeśli IP jest nieznane lub zbanowane, system tworzy wpis w tabeli `Alerts`, który natychmiast pojawia się na Dashboardzie.
