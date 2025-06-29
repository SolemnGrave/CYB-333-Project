import pandas as pd
import re
from datetime import datetime
import time
import os
import json # For saving/loading state
import logging # For logging the analyzer's own operations
import yaml # For loading alert rules from YAML
import smtplib # For sending email notifications
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Dict, Any, Union, Tuple

# Configuration Constants
LOG_FILE_PATH: str = 'sample_logs/example_log.txt'
STATE_FILE_PATH: str = 'analyzer_state.json' # File to save last read position and inode
ALERT_RULES_FILE: str = 'rules.yaml' # New: Path to external alert rules file
# Adjusted LOG_PATTERN to remove brackets around log level, based on your output
LOG_PATTERN: re.Pattern = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(INFO|DEBUG|ERROR|WARNING|CRITICAL|ALERT|UNKNOWN)\s+(.*)")
TIMESTAMP_FORMAT: str = '%Y-%m-%d %H:%M:%S'

# Check interval in seconds
CHECK_INTERVAL_SECONDS: int = 5

# Historical log retention duration in seconds
MAX_HISTORY_DURATION_SECONDS: int = 3600 # 1 hour

# Email notification settings
# In testing, I was unable to simulate email sending, due to security reasons, so this is disabled by default.
SEND_EMAILS: bool = True # Set to False to disable email sending
SMTP_SERVER: str = 'smtp.gmail.com' # Your SMTP server
SMTP_PORT: int = 587 
SMTP_USERNAME: str = 'your_sender_email@example.com' # Sender's email address
SMTP_PASSWORD: str = 'your_email_password' # Sender's email password
ALERT_RECIPIENTS: List[str] = ['security_ops@example.com', 'admin@example.com'] # List of recipient emails
EMAIL_SUBJECT_PREFIX: str = '[Log Analyzer Alert]' # Prefix for email subject lines

# Severity order for prioritization
LEVEL_ORDER: pd.CategoricalDtype = pd.CategoricalDtype(
    ['CRITICAL', 'ALERT', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'UNKNOWN'],
    ordered=True
)

# Analyzer's own logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("analyzer.log"), # Log to file
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

# Management functions
def save_state(file_path: str, last_position: int, inode: int) -> None:
    """Saves the last read file position and inode to a JSON file."""
    state_data = {'last_position': last_position, 'inode': inode}
    try:
        with open(file_path, 'w') as f:
            json.dump(state_data, f)
        logger.info(f"Analyzer state saved: position={last_position}, inode={inode}")
    except IOError as e:
        logger.error(f"Failed to save analyzer state to {file_path}: {e}")

def load_state(file_path: str) -> Tuple[int, int]:
    """Loads the last read file position and inode from a JSON file."""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as f:
                state_data = json.load(f)
                last_position = state_data.get('last_position', 0)
                inode = state_data.get('inode', 0)
                logger.info(f"Analyzer state loaded: position={last_position}, inode={inode}")
                return last_position, inode
        except (IOError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load analyzer state from {file_path}: {e}. Starting from scratch.")
    logger.info("No existing analyzer state found. Starting from scratch.")
    return 0, 0 # Default to start

# Load alert rules from external YAML file
def load_alert_rules(file_path: str) -> List[Dict[str, Union[str, List[str], int]]]:
    """Loads alert rules from a YAML file."""
    if not os.path.exists(file_path):
        logger.error(f"Alert rules file not found: {file_path}. No custom rules will be loaded.")
        return []
    try:
        with open(file_path, 'r') as f:
            rules = yaml.safe_load(f)
            if 'alert_rules' in rules and isinstance(rules['alert_rules'], list):
                logger.info(f"Successfully loaded {len(rules['alert_rules'])} alert rules from {file_path}.")
                return rules['alert_rules']
            else:
                logger.error(f"Invalid format in {file_path}. Expected 'alert_rules' as a list.")
                return []
    except yaml.YAMLError as e:
        logger.error(f"Error parsing alert rules file {file_path}: {e}. No custom rules will be loaded.")
        return []
    except Exception as e:
        logger.exception(f"An unexpected error occurred loading alert rules from {file_path}: {e}")
        return []


# Load reading function
def read_new_log_entries(file_path: str, last_position: int, last_inode: int) -> Tuple[pd.DataFrame, int, int]:
    """
    Reads new log entries from the file starting from last_position.
    Tracks file inode to detect rotations.
    Returns a DataFrame of new entries, the current file position, and the current inode.
    """
    parsed_data: List[Dict[str, Any]] = []
    current_position: int = last_position
    current_inode: int = last_inode

    try:
        if not os.path.exists(file_path):
            logger.warning(f"Log file not found at '{file_path}'. Waiting for it to appear.")
            return pd.DataFrame(), last_position, last_inode

        file_stat = os.stat(file_path)
        new_inode = file_stat.st_ino
        current_file_size = file_stat.st_size

        if new_inode != last_inode:
            if last_inode != 0:
                logger.info(f"Log file '{file_path}' inode changed (old: {last_inode}, new: {new_inode}). Assuming rotation/new file. Resetting read position.")
            current_position = 0
            current_inode = new_inode
        elif current_file_size < last_position:
            logger.info(f"Log file '{file_path}' size ({current_file_size} bytes) is smaller than last read position ({last_position} bytes). Assuming truncation/rotation. Resetting read position.")
            current_position = 0
            current_inode = new_inode

        with open(file_path, 'r') as file:
            file.seek(current_position)
            for line in file:
                match = LOG_PATTERN.match(line)
                if match:
                    timestamp_str, level, message = match.groups()
                    try:
                        timestamp_obj = datetime.strptime(timestamp_str, TIMESTAMP_FORMAT)
                        parsed_data.append({
                            'timestamp': timestamp_obj,
                            'level': level,
                            'message': message.strip(),
                            'original_log': line.strip()
                        })
                    except ValueError:
                        parsed_data.append({
                            'timestamp': None,
                            'level': 'UNKNOWN',
                            'message': line.strip(),
                            'original_log': line.strip()
                        })
                else:
                    parsed_data.append({
                        'timestamp': None,
                        'level': 'UNKNOWN',
                        'message': line.strip(),
                        'original_log': line.strip()
                    })
            current_position = file.tell()

    except FileNotFoundError:
        logger.error(f"Log file not found at '{file_path}' during read attempt.")
        return pd.DataFrame(), last_position, last_inode
    except Exception as e:
        logger.exception(f"An unexpected error occurred while reading the log file: {e}")
        return pd.DataFrame(), last_position, last_inode

    df = pd.DataFrame(parsed_data)
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    return df, current_position, current_inode


def evaluate_alert_rules(df_new_logs: pd.DataFrame, all_processed_logs: pd.DataFrame,
                         alert_rules: List[Dict[str, Union[str, List[str], int]]]) -> pd.DataFrame:
    """
    Evaluates defined alert rules on a combination of new logs and a historical window
    of all processed logs to detect threshold-based alerts.
    Returns a DataFrame of triggered alerts with an 'alert_type' column.
    """
    if df_new_logs.empty:
        return pd.DataFrame()

    triggered_alerts: List[Dict[str, Any]] = []

    clean_all_processed_logs = all_processed_logs[all_processed_logs['timestamp'].notna()]
    clean_new_logs = df_new_logs[df_new_logs['timestamp'].notna()]

    if clean_all_processed_logs.empty:
        combined_logs_for_analysis = clean_new_logs.copy()
    else:
        combined_logs_for_analysis = pd.concat([clean_all_processed_logs, clean_new_logs]).drop_duplicates(subset=['original_log'])
        combined_logs_for_analysis = combined_logs_for_analysis.sort_values(by='timestamp').reset_index(drop=True)

    if combined_logs_for_analysis.empty:
        return pd.DataFrame()

    for rule in alert_rules:
        rule_name = rule.get('name', 'Unnamed Rule')
        rule_levels = rule.get('levels', [])
        rule_keywords = rule.get('keywords', [])
        threshold_count = rule.get('threshold_count', 1)
        time_window_seconds = rule.get('time_window_seconds', 0)

        level_condition = pd.Series([False] * len(combined_logs_for_analysis))
        if rule_levels:
            level_condition = combined_logs_for_analysis['level'].isin(rule_levels)

        keyword_condition = pd.Series([False] * len(combined_logs_for_analysis))
        if rule_keywords:
            pattern = '|'.join([re.escape(k) for k in rule_keywords])
            keyword_condition = combined_logs_for_analysis['message'].str.contains(pattern, case=False, na=False)

        rule_matches = combined_logs_for_analysis[level_condition | keyword_condition].copy()

        if rule_matches.empty:
            continue

        relevant_new_logs_for_rule = df_new_logs[
            (df_new_logs['original_log'].isin(rule_matches['original_log'])) &
            (df_new_logs['timestamp'].notna())
        ].copy()


        if time_window_seconds > 0:
            for _, new_log_row in relevant_new_logs_for_rule.iterrows():
                window_start = new_log_row['timestamp'] - pd.to_timedelta(time_window_seconds, unit='s')
                relevant_matches_in_window = rule_matches[
                    (rule_matches['timestamp'] >= window_start) &
                    (rule_matches['timestamp'] <= new_log_row['timestamp'])
                ]

                if len(relevant_matches_in_window) >= threshold_count:
                    alert_entry = new_log_row.to_dict()
                    alert_entry['alert_type'] = rule_name
                    triggered_alerts.append(alert_entry)
        else:
            for _, match_row in relevant_new_logs_for_rule.iterrows():
                if len(match_row) >= threshold_count:
                    alert_entry = match_row.to_dict()
                    alert_entry['alert_type'] = rule_name
                    triggered_alerts.append(alert_entry)

    if triggered_alerts:
        df_triggered = pd.DataFrame(triggered_alerts)
        df_triggered = df_triggered.drop_duplicates(subset=['original_log', 'alert_type'])
        return df_triggered
    else:
        return pd.DataFrame()

def prioritize_alerts(df_alerts: pd.DataFrame) -> pd.DataFrame:
    """
    Prioritizes alerts based on defined severity order and timestamp.
    """
    if df_alerts.empty:
        return pd.DataFrame()

    df_alerts['level'] = df_alerts['level'].astype(LEVEL_ORDER)
    prioritized_df = df_alerts.sort_values(by=['timestamp', 'level'], ascending=[False, False])
    return prioritized_df

# Alert summary and notification for emails
def send_alert_email(subject: str, body: str, recipients: List[str]) -> None:
    """
    Sends an email notification.
    """
    if not SEND_EMAILS:
        logger.info("Email sending is disabled. (SEND_EMAILS=False)")
        return
    if not all([SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD, ALERT_RECIPIENTS]):
        logger.error("Email settings are incomplete. Cannot send email.")
        return
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USERNAME
        msg['To'] = ', '.join(recipients)
        msg['Subject'] = f"{EMAIL_SUBJECT_PREFIX} {subject}"

        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls() # Secure the connection
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_USERNAME, recipients, msg.as_string())
        logger.info(f"Alert email sent to: {', '.join(recipients)} with subject: {msg['Subject']}")
    except smtplib.SMTPAuthenticationError:
        logger.error("SMTP Authentication Error: Failed to login to the SMTP server. Check username/password.")
        logger.error("Email sending skipped due to authentication error.")
    except Exception as e:
        logger.error(f"Failed to send alert email: {e}")
        logger.exception("Email sending error details:")

def generate_alert_summary(df_prioritized_alerts: pd.DataFrame) -> None:
    """
    Generates and prints a summary of triggered alerts.
    This is where external notification integrations would go.
    """
    if df_prioritized_alerts.empty:
        logger.info("No new alerts detected.")
        return

    logger.critical(f"\n--- NEW ALERTS TRIGGERED! ({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")
    alert_counts = df_prioritized_alerts['alert_type'].value_counts()
    logger.critical("Alerts by Type:")
    logger.critical(alert_counts.to_string())

    logger.critical("\nDetails of New Prioritized Alerts (Newest first, then by level):")
    for index, row in df_prioritized_alerts.iterrows():
        ts_str = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['timestamp']) else "N/A"
        logger.critical(f"  [{ts_str}] {row['level']} - {row['alert_type']}: {row['message']}")
    logger.critical("---------------------------------------------------\n")

    # Send email notification
    email_subject = f"Urget: {len(df_prioritized_alerts)} New Alerts Detected"
    email_body = f"Analyzer has detected new alerts at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}.\n\n"
    email_body += "Alerts by Type:\n"
    email_body += alert_counts.to_string() + "\n\n"
    email_body += "Details of New Prioritized Alerts: (Newest first, then by level):\n"

    for index, row in df_prioritized_alerts.iterrows():
        ts_str = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S') if pd.notna(row['timestamp']) else "N/A"
        email_body += f"  [{ts_str}] {row['level']} - {row['alert_type']}: {row['message']}\n"
    email_body += "\n--- End of Alert Summary ---\n"

    # Sending email
    send_alert_email(email_subject, email_body, ALERT_RECIPIENTS)



# Execution loop
if __name__ == "__main__":
    logger.info("--- Starting Continuous Log Monitoring for Security Operations ---")
    logger.info(f"Monitoring log file: {LOG_FILE_PATH}")
    logger.info(f"Checking for new logs every {CHECK_INTERVAL_SECONDS} seconds.")

    # Load initial state
    last_read_position, last_inode = load_state(STATE_FILE_PATH)
    # Load alert rules
    ALERT_RULES = load_alert_rules(ALERT_RULES_FILE)
    if not ALERT_RULES:
        logger.error("No alert rules loaded. The analyzer will not detect any alerts.")

    # Initialize historical logs DataFrame
    all_processed_logs: pd.DataFrame = pd.DataFrame(columns=['timestamp', 'level', 'message', 'original_log'])

    try:
        while True:
            new_logs_df, current_read_position, current_inode = read_new_log_entries(
                LOG_FILE_PATH, last_read_position, last_inode
            )

            last_read_position = current_read_position
            last_inode = current_inode
            save_state(STATE_FILE_PATH, last_read_position, last_inode)

            if not new_logs_df.empty:
                logger.info(f"Detected {len(new_logs_df)} new log entries.")

                all_processed_logs = pd.concat([all_processed_logs, new_logs_df]).drop_duplicates(subset=['original_log'])
                all_processed_logs = all_processed_logs.sort_values(by='timestamp', ascending=True).reset_index(drop=True)

                if not all_processed_logs.empty and pd.notna(all_processed_logs['timestamp']).any():
                    max_valid_timestamp = all_processed_logs['timestamp'].max()
                    cut_off_time = max_valid_timestamp - pd.to_timedelta(MAX_HISTORY_DURATION_SECONDS, unit='s')
                    all_processed_logs = all_processed_logs[all_processed_logs['timestamp'] >= cut_off_time].copy()
                    logger.debug(f"Trimmed historical logs. Current count: {len(all_processed_logs)}")

                # Evaluate alert rules, as long as there are rules loaded
                if ALERT_RULES:
                    df_triggered_alerts = evaluate_alert_rules(new_logs_df, all_processed_logs, ALERT_RULES)
                    df_prioritized_alerts = prioritize_alerts(df_triggered_alerts)
                    generate_alert_summary(df_prioritized_alerts)
                else:
                    logger.warning("No alert rules are active. Skipping alert evaluation.")
            else:
                logger.info("No new log entries detected. Waiting...")

            time.sleep(CHECK_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        logger.info("\n--- Log monitoring stopped by user. ---")
        save_state(STATE_FILE_PATH, last_read_position, last_inode)
    except Exception as e:
        logger.exception(f"\n--- An unhandled error occurred, stopping monitoring: {e} ---")
        save_state(STATE_FILE_PATH, last_read_position, last_inode)

    logger.info("--- Log Analysis Session Ended ---")