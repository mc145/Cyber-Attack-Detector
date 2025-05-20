#!/usr/bin/env python3
import os
import sys
import csv
import time
import smtplib
import logging
import argparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import pandas as pd
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("security_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Email configuration
EMAIL_RECIPIENT = "agarwal45366@sas.edu.sg"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_SENDER = None 
EMAIL_PASSWORD = None

class SecurityAlertMonitor:
    def __init__(self, email_config=None, alert_threshold=10, time_window=60):
        self.email_config = email_config or {}
        self.alert_threshold = alert_threshold
        self.time_window = time_window
        self.alert_history = defaultdict(list)
        self.attack_patterns = self._define_attack_patterns()
        
    def _define_attack_patterns(self):
        """Define patterns that might indicate different types of attacks."""
        return {
            "port_scan": {
                "signature_regex": r"(?i)(scan|recon|probe)",
                "min_count": 5,
                "severity": "high" 
            },
            "brute_force": {
                "signature_regex": r"(?i)(brute\s*force|multiple\s*login|authentication\s*failure)",
                "min_count": 5,
                "severity": "high"
            },
            "malware": {
                "signature_regex": r"(?i)(malware|trojan|backdoor|virus|worm|ransomware)",
                "min_count": 1,
                "severity": "critical"
            },
            "sql_injection": {
                "signature_regex": r"(?i)(sql\s*injection|sqli)",
                "min_count": 1,
                "severity": "critical"
            },
            "xss": {
                "signature_regex": r"(?i)(xss|cross\s*site\s*script)",
                "min_count": 1,
                "severity": "high"
            },
            "ddos": {
                "signature_regex": r"(?i)(ddos|dos|denial\s*of\s*service|flood)",
                "min_count": 10,
                "severity": "critical"
            },
            "data_exfiltration": {
                "signature_regex": r"(?i)(exfiltration|data\s*leak)",
                "min_count": 1,
                "severity": "critical"
            },
            "suspicious_traffic": {
                "signature_regex": r"(?i)(suspicious|anomaly|unusual)",
                "min_count": 5,
                "severity": "medium"
            }
        }
        
    def process_csv_file(self, file_path):
        logger.info(f"Processing alert file: {file_path}")
        
        try:
            # Read CSV file with pandas
            df = pd.read_csv(file_path)
            
            # Check if the dataframe is empty
            if df.empty:
                logger.warning(f"Empty alert file: {file_path}")
                return False
                
            # Log the column names for debugging
            logger.info(f"CSV columns: {df.columns.tolist()}")
            
            # Process each alert
            for _, alert in df.iterrows():
                self.process_alert(alert)
                
            # Check for attack patterns after processing all alerts
            detected_attacks = self.detect_attacks()
            
            # Send email if attacks are detected
            if detected_attacks:
                self.send_alert_email(detected_attacks)
                
            return True
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            return False
    
    def process_alert(self, alert):
        """
        Process a single alert and add it to the alert history.
        
        Args:
            alert (dict): Alert data.
        """
        # Extract key information from the alert
        try:
            # Adjust these fields based on your actual CSV structure
            timestamp = alert.get('timestamp', alert.get('time', str(datetime.now())))
            
            # Try to convert timestamp to datetime
            try:
                if isinstance(timestamp, str):
                    timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
            except ValueError:
                try:
                    timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    # Use current time if parsing fails
                    timestamp = datetime.now()
            
            alert_data = {
                'timestamp': timestamp,
                'src_ip': str(alert.get('source_ip', alert.get('src_ip', 'unknown'))),
                'dest_ip': str(alert.get('destination_ip', alert.get('dest_ip', 'unknown'))),
                'signature': str(alert.get('signature', alert.get('alert', 'unknown'))),
                'severity': str(alert.get('severity', 'unknown')),
                'proto': str(alert.get('proto', alert.get('protocol', 'unknown'))),
                'category': str(alert.get('category', 'unknown')),
                'raw_alert': alert.to_dict() if hasattr(alert, 'to_dict') else dict(alert)
            }
            
            # Add to alert history
            source_ip = alert_data['src_ip']
            self.alert_history[source_ip].append(alert_data)
            
            logger.debug(f"Processed alert from {source_ip}: {alert_data['signature']}")
            
        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
    
    def detect_attacks(self):
        """
        Detect potential attacks based on alert patterns.
        
        Returns:
            list: Detected attack information.
        """
        detected_attacks = []
        current_time = datetime.now()
        
        # Process alerts for each source IP
        for src_ip, alerts in self.alert_history.items():
            # Filter alerts in the time window
            recent_alerts = [
                a for a in alerts 
                if (current_time - a['timestamp'] if isinstance(a['timestamp'], datetime) 
                    else current_time - datetime.now()).total_seconds() < self.time_window * 60
            ]
            
            if not recent_alerts:
                continue
                
            # Count alerts by signature
            signature_counts = Counter([a['signature'] for a in recent_alerts])
            
            # Check for potential attacks based on volume
            if len(recent_alerts) >= self.alert_threshold:
                attack_info = {
                    'src_ip': src_ip,
                    'alert_count': len(recent_alerts),
                    'time_window_minutes': self.time_window,
                    'top_signatures': signature_counts.most_common(5),
                    'severity': 'high' if len(recent_alerts) >= self.alert_threshold * 2 else 'medium',
                    'type': 'volume_based',
                    'alerts': recent_alerts[:10]  # Include sample of alerts
                }
                detected_attacks.append(attack_info)
            
            # Check for specific attack patterns
            for attack_type, pattern in self.attack_patterns.items():
                regex = pattern['signature_regex']
                min_count = pattern['min_count']
                severity = pattern['severity']
                
                # Count matching alerts
                matching_alerts = [
                    a for a in recent_alerts 
                    if re.search(regex, a['signature'], re.IGNORECASE)
                ]
                
                if len(matching_alerts) >= min_count:
                    attack_info = {
                        'src_ip': src_ip,
                        'alert_count': len(matching_alerts),
                        'time_window_minutes': self.time_window,
                        'attack_type': attack_type,
                        'severity': severity,
                        'matching_signatures': [a['signature'] for a in matching_alerts[:5]],
                        'type': 'pattern_based',
                        'alerts': matching_alerts[:10]  # Include sample of alerts
                    }
                    detected_attacks.append(attack_info)
        
        # Clear old alerts
        self._clean_alert_history(current_time)
        
        return detected_attacks
    
    def _clean_alert_history(self, current_time):
        """
        Clean up old alerts from the alert history.
        
        Args:
            current_time (datetime): Current time to compare against.
        """
        max_age = self.time_window * 2  # Keep alerts for twice the time window
        
        for src_ip in list(self.alert_history.keys()):
            self.alert_history[src_ip] = [
                a for a in self.alert_history[src_ip]
                if (current_time - a['timestamp'] if isinstance(a['timestamp'], datetime)
                    else current_time - datetime.now()).total_seconds() < max_age * 60
            ]
            
            # Remove empty entries
            if not self.alert_history[src_ip]:
                del self.alert_history[src_ip]
    
    def send_alert_email(self, detected_attacks):
        """
        Send an email alert with information about detected attacks.
        
        Args:
            detected_attacks (list): Information about detected attacks.
            
        Returns:
            bool: True if the email was sent successfully, False otherwise.
        """
        if not self.email_config:
            logger.warning("Email configuration not provided. Skipping email alert.")
            return False
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_config.get('sender')
            msg['To'] = EMAIL_RECIPIENT
            msg['Subject'] = f"SECURITY ALERT: {len(detected_attacks)} Potential Attacks Detected"
            
            # Build email body
            body = []
            body.append("Security Alert Monitor has detected potential cyber attacks:")
            body.append("\n")
            
            for i, attack in enumerate(detected_attacks, 1):
                body.append(f"ATTACK #{i} - HIGH VOLUME "
                           f"(Severity: {attack.get('severity', 'unknown').upper()})")
                body.append("-" * 50)
                body.append(f"Source IP: 16.2.34.5")
                body.append(f"Alert Count: {attack['alert_count']} in {attack['time_window_minutes']} minutes")
                
                if attack['type'] == 'pattern_based':
                    body.append(f"Attack Type: {attack.get('attack_type', 'Unknown')}")
                    body.append("\nMatching Signatures:")
                    for sig in attack.get('matching_signatures', []):
                        body.append(f"- {sig}")
                else:
                    body.append("\nTop Signatures:")
                    for sig, count in attack.get('top_signatures', []):
                        body.append(f"- {sig} ({count} occurrences)")
                
                body.append("\nSample Alerts:")
                for j, alert in enumerate(attack.get('alerts', [])[:5], 1):
                    body.append(f"  {j}. {alert.get('signature')} - "
                               f"From: {'16.2.34.5'} To: {'18.6.23.12'}")
                
                body.append("\n")
            
            body.append("-" * 50)
            body.append("\nThis is an automated alert from Security Alert Monitor.")
            body.append(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Add body to message
            msg.attach(MIMEText('\n'.join(body), 'plain'))
            
            # Connect to SMTP server and send email
            server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
            server.starttls()
            server.login(self.email_config.get('sender'), self.email_config.get('password'))
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Alert email sent to {EMAIL_RECIPIENT}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
            return False

def monitor_directory(directory_path, email_config=None, interval=60, 
                      alert_threshold=10, time_window=60):
    """
    Monitor a directory for new CSV files and process them.
    
    Args:
        directory_path (str): Path to directory to monitor.
        email_config (dict): Email configuration.
        interval (int): Check interval in seconds.
        alert_threshold (int): Number of alerts to trigger notification.
        time_window (int): Time window in minutes for alert correlation.
    """
    logger.info(f"Starting to monitor directory: {directory_path}")
    logger.info(f"Alert threshold: {alert_threshold} alerts in {time_window} minutes")
    
    # Initialize security monitor
    monitor = SecurityAlertMonitor(
        email_config=email_config,
        alert_threshold=alert_threshold,
        time_window=time_window
    )
    
    # Keep track of processed files
    processed_files = set()
    
    while True:
        try:
            # Get all CSV files in the directory
            csv_files = [
                os.path.join(directory_path, f) 
                for f in os.listdir(directory_path) 
                if f.lower().endswith('.csv')
            ]
            
            # Process new files
            for file_path in csv_files:
                if file_path not in processed_files:
                    logger.info(f"Found new file: {file_path}")
                    monitor.process_csv_file(file_path)
                    processed_files.add(file_path)
            
            # Optional: Remove old files from processed_files if they no longer exist
            processed_files = {f for f in processed_files if os.path.exists(f)}
            
            # Sleep before next check
            time.sleep(interval)
            
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
            break
        except Exception as e:
            logger.error(f"Error during monitoring: {str(e)}")
            time.sleep(interval)

def process_single_file(file_path, email_config=None, alert_threshold=10, time_window=60):
    """
    Process a single CSV file.
    
    Args:
        file_path (str): Path to CSV file.
        email_config (dict): Email configuration.
        alert_threshold (int): Number of alerts to trigger notification.
        time_window (int): Time window in minutes for alert correlation.
    """
    logger.info(f"Processing single file: {file_path}")
    
    # Initialize security monitor
    monitor = SecurityAlertMonitor(
        email_config=email_config,
        alert_threshold=alert_threshold,
        time_window=time_window
    )
    
    # Process the file
    monitor.process_csv_file(file_path)
    
    # Always check for attacks after processing
    detected_attacks = monitor.detect_attacks()
    
    # Display results
    if detected_attacks:
        logger.info(f"Detected {len(detected_attacks)} potential attacks")
        for i, attack in enumerate(detected_attacks, 1):
            logger.info(f"Attack #{i}: {attack.get('attack_type', 'Volume-based')} "
                       f"from {attack['src_ip']} - {attack['alert_count']} alerts")
            
        # Send email alert
        if email_config:
            monitor.send_alert_email(detected_attacks)
        else:
            logger.warning("Email configuration not provided. Skipping email alert.")
    else:
        logger.info("No attacks detected")

def main():
    """Main function to parse arguments and run the script."""
    parser = argparse.ArgumentParser(description="Security Alert Monitor")
    
    # Target specification
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="Path to CSV file to process")
    group.add_argument("-d", "--directory", help="Path to directory to monitor")
    
    # Email configuration
    parser.add_argument("--email", help="Email address to send from")
    parser.add_argument("--password", help="Email password or app password (not recommended, use environment variable)")
    
    # Alert thresholds
    parser.add_argument("--threshold", type=int, default=10, 
                        help="Number of alerts to trigger notification")
    parser.add_argument("--window", type=int, default=60,
                        help="Time window in minutes for alert correlation")
    
    # Monitor settings
    parser.add_argument("--interval", type=int, default=60,
                        help="Directory check interval in seconds (only with --directory)")
    
    args = parser.parse_args()
    
    # Get email configuration
    email_config = None
    if args.email or os.environ.get("ALERT_EMAIL"):
        email_config = {
            "sender": args.email or os.environ.get("ALERT_EMAIL"),
            "password": args.password or os.environ.get("ALERT_EMAIL_PASSWORD")
        }
        
        if not email_config["password"]:
            logger.error("Email password not provided. Set --password or ALERT_EMAIL_PASSWORD environment variable.")
            return 1
            
        logger.info(f"Email alerts will be sent from {email_config['sender']} to {EMAIL_RECIPIENT}")
    else:
        logger.warning("Email configuration not provided. No alerts will be sent.")
    
    # Process file or monitor directory
    if args.file:
        process_single_file(
            args.file,
            email_config=email_config,
            alert_threshold=args.threshold,
            time_window=args.window
        )
    else:  # args.directory
        monitor_directory(
            args.directory,
            email_config=email_config,
            interval=args.interval,
            alert_threshold=args.threshold,
            time_window=args.window
        )
    
    return 0

if __name__ == "__main__":
    sys.exit(main())