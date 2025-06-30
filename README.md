# CYB-333-Project

---

## Dependencies and Prerequisites

- To run the Log Analyzer, you will need to have Python installed (current version) and the associated libraries we have listed.

- Ensure to update pip via ‘python -m install –upgrade pip’

- Then install the pandas and pyyaml via ‘pip install pandas pyyaml’

- We use pandas for the data and analysis for our DataFrames to structure, filter, parse, and process our logs.

- 'datetime' for the log entry timestamps for conversion to do filtering, management, and analysis.

- 'os' to interact with the filesystem.

- 'json' is used for reading the last position of the logs, in case of an abrupt shutdown. We don't want to have to go through all of the archived logs, so this basically creates a saved position to work off of.

- 'logging' is so we can monitor the state of our analyzer and its operations.

- 'yaml' this is what we will be using to adjust rules without having the alter the main code.

- 'smtplib' as we are using email alerts for this example, we require this in order for that feature to function.

- 'email.mime.text' and 'email.mim.multipart' an additional aspect of the previous 'smtplib', allowing us to format the notification email text.

- 'typing' not absolutely necessary, but makes the readability better.

## Config

This section outlines the Log Analyzer behavior and can be adjusted through the constrants set at the top of 'log_analyzer.py'.

* **`LOG_FILE_PATH`**:
    * **Default:** `'sample_logs/example_log.txt'`
    * This string sets the path to the log files to be analyzed. *You need to change this to point to your actual log file, wherever it may be located.*

* **`STATE_FILE_PATH`**:
    * **Default:** `'analyzer_state.json'`
    *  Pathing for JSON file. As mentioned above, in case of a stoppage or restart, this will allow the analyzer to essentially create a saved state for its read position. This file will be automatically created/updated via the script.

* **`ALERT_RULES_FILE`**:
    * **Default:** `'rules.yaml'`
    * Pathing to YAML file for custom alert definition. This file is vital in defining the alerts for the logs. An example `rules.yaml` will be provided.

* **`LOG_PATTERN`**:
    * This is the expression pattern used to parse each line of your log file. It's designed to extract the `timestamp`, `level` (e.g., INFO, ERROR), and `message` from each log entry.
    * **Default Pattern:** `r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+(INFO|DEBUG|ERROR|WARNING|CRITICAL|ALERT|UNKNOWN)\s+(.*)"`
    * You will need to ensure that you alter the default pattern to match your specific log file format.

* **`TIMESTAMP_FORMAT`**:
    * **Default:** `'%Y-%m-%d %H:%M:%S'`
    * Format of the timestamp in your log file. This must match the format expected by Python's `datetime.strptime()` function in order to ensure proper parsing.

* **`CHECK_INTERVAL_SECONDS`**:
    * **Default:** `5`
    * The interval at which the analyzer will check the log file for new entries (defined in seconds). You can lower this value to get more 'real-time' activity, but that will also increase the resources used.

* **`MAX_HISTORY_DURATION_SECONDS`**:
    * **Default:** `3600` (1 hour)
    * Retention time for historical logs (defined in seconds).Used for rules that depend on frequency of events over time. Additionally, this helps to purge older logs to mitigate excess resource consumption.

## Email Notification Settings

    * Alright, this is how we will be getting the 'HELP' calls. I had some issues on my end that prevented me from fully testing this, email and permission issues, but all testing, apart from the execution of an email, were good to go.

    **`SEND_EMAILS`**:
        * **Default:** `True`
        * Flip this to `False` For if you don't want the email notifications, or need to adjust setting for testing.
    **`SMTP_SERVER`**:
        * **Example:** `'smtp.gmail.com'`
        * Your mail server. Obviously change accordingly.
    **`SMTP_PORT`**:
        * **Example:** `587`
        * Standard port for SMTP.
    **`SMTP_USERNAME`**:
        * **Example:** `'your_sender_email@example.com'`
        * The email address doing the sending.
        * **SECURITY HEADS UP:** Don't put your real credentials into a public repo...
    **`SMTP_PASSWORD`**:
        * **Example:** `'your_email_password'`
        * The password for that sender email.
        * **SERIOUSLY:** Again...public repo...don't put your real credentials...
    **`ALERT_RECIPIENTS`**:
        * **Example:** `['security_ops@example.com', 'admin@example.com']`
        * This is who needs to know the alert.
    **`EMAIL_SUBJECT_PREFIX`**:
        * **Default:** `'[Log Analyzer Alert]'`
        * Set a standard alert subject line.

* **`LEVEL_ORDER`**:
    * **Default:** `['CRITICAL', 'ALERT', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'UNKNOWN']`
    * List of the priority levels for the alerts, starting left to right from highest to lowest.

## Core Functionality and Monitoring
    * This is we implement our JSON to keep the persistent state tracking.
* **'def save_state'**
    * **logger.info** This is where our script is going to be saving the read position.

* **'def load_state'**
    * **logger.info** This is where our script will load the previously known read position.

    * This functions as the Analyzer's memory and keep tabs on progress through the utilization of unique file identifiers with 'inode'.

## Alert Rule

    * This is where we will be setting and injecting our specific rule logic for the system to follow. You define the rules in the rules.yaml file and then the script pulls those rules, parsing them, and then loads them.

## Reading Function

    * We next have to use the 'read_new_log_entries' function for our script to actually read the logs in order for us to keep the analyzer up-to-date. Basically, it reads, ingests the contents of the logs, and parses them with our log pattern.

## Alert Evaluation

    * Now that the script can read the new logs and stay up-to-date and be parsed through the pattern, we have to use the 'evaluate_alert_rules' and runs it against our pre-defined rules in our 'rules.yaml' file.

## Alert Priority

    * Now that we have generated an alert from the previous function, we have to set the priority through our 'prioritze_alerts' and then sort through the severity with our set 'LEVEL_ORDER'.

## Notification (Email)

    * The next section is where we take the alert that is found (if there is one), and this specific part is where the dispatching of the email alert occurs through 'send_alert_email'.

## Alert Output

    * Now that we are primed to send the email, and this section generates the summary of the alert with 'generate_alert_summary' that will then go back to 'send_alert_email' to be sent out.

## Execution and Automation

    * The final section, the 'if __name__ == "__main__": block, is the conductor of this whole script. First, the initialization through loading the last known state through 'analyzer_state.json', puts it though our 'rules.yaml' definitions. After, it will go through its checklist:
            - Reading the new logs.
            - Updating and saving position.
            - Processing new logs.
            - Running our 'evaluate_alert_rules'.
            - Prioritizes alerts.
            - Generates the summary, sending them out.
    * This look creates our 'real-time' automation.