import os

# Ensure BASE_DIR is imported or defined if you're using it
from django.conf import settings

LOG_FILE_PATH = os.path.join(settings.BASE_DIR, 'actions.log')

def parse_logs():
    """
    Read the log file and filter for important log entries.
    """
    important_logs = []
    if os.path.exists(LOG_FILE_PATH):
        with open(LOG_FILE_PATH, 'r') as log_file:
            for line in log_file:
                # Filter logs for specific levels or keywords
                if any(keyword in line for keyword in ["WARNING", "ERROR", "failed", "invalid", "expired"]):
                    important_logs.append(line.strip())
    return important_logs
