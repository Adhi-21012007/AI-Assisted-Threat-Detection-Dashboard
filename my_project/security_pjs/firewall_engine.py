from datetime import datetime, timedelta
from .alert_manager import recent_events
from .rules import evaluate
from . import config

class FirewallEngine:
    """Rule-based prototype security engine; it is not a production network firewall."""
    def inspect(self, connection, event):
        now=datetime.fromisoformat(event["timestamp"]); employee=event.get("employee_id")
        if not employee:return []
        # The processor persists the current event before inspection, so this
        # query includes it exactly once.
        settings=config.runtime_settings(connection)
        recent=recent_events(connection,employee,now-timedelta(minutes=max(settings['failed_login_window_minutes'],settings['download_window_minutes'])))
        history=recent_events(connection,employee,now-timedelta(days=30))
        return evaluate(event,recent,history,settings)
