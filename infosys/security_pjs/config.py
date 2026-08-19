import os

FAILED_LOGIN_SUSPICIOUS = int(os.getenv("SECURITY_FAILED_LOGIN_SUSPICIOUS", "5"))
FAILED_LOGIN_CRITICAL = int(os.getenv("SECURITY_FAILED_LOGIN_CRITICAL", "15"))
FAILED_LOGIN_WINDOW_MINUTES = int(os.getenv("SECURITY_FAILED_LOGIN_WINDOW_MINUTES", "15"))
DOWNLOAD_THRESHOLD = int(os.getenv("SECURITY_DOWNLOAD_THRESHOLD", "50"))
DOWNLOAD_WINDOW_MINUTES = int(os.getenv("SECURITY_DOWNLOAD_WINDOW_MINUTES", "30"))
WORKDAY_START = int(os.getenv("SECURITY_WORKDAY_START", "9"))
WORKDAY_END = int(os.getenv("SECURITY_WORKDAY_END", "18"))
ALERT_DEDUP_MINUTES = int(os.getenv("SECURITY_ALERT_DEDUP_MINUTES", "30"))
MAX_API_BYTES = int(os.getenv("SECURITY_API_MAX_BYTES", "65536"))

def runtime_settings(connection):
    """Read analyst-approved local settings without changing safe environment defaults."""
    values={"failed_login_suspicious":FAILED_LOGIN_SUSPICIOUS,"failed_login_critical":FAILED_LOGIN_CRITICAL,"failed_login_window_minutes":FAILED_LOGIN_WINDOW_MINUTES,"download_threshold":DOWNLOAD_THRESHOLD,"download_window_minutes":DOWNLOAD_WINDOW_MINUTES,"workday_start":WORKDAY_START,"workday_end":WORKDAY_END}
    try:
        rows=connection.execute("SELECT setting_key,setting_value FROM security_settings").fetchall()
        for row in rows:
            if row[0] in values and str(row[1]).isdigit():values[row[0]]=int(row[1])
    except Exception:pass
    return values
