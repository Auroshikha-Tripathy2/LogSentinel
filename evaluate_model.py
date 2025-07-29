import requests
import json
import time
from typing import List, Dict, Any, Tuple
import random
import os
import sys
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
# Add the parent directory to the path to import main and hdfs_parser
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the hdfs_parser to get the processed HDFS data
# Make sure hdfs_parser.py is updated with the latest code provided previously
from hdfs_parser import process_structured_hdfs_dataset, HDFS_LOG_FILE, ANOMALY_LABELS_FILE, PARSED_HDFS_DATA_CACHE

# Import evaluation metrics from scikit-learn
from sklearn.metrics import precision_score, recall_score, f1_score, roc_curve, auc, classification_report # Added classification_report
from sklearn.model_selection import train_test_split # Import for stratified splitting
import matplotlib.pyplot as plt
import numpy as np

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Configuration ---
FASTAPI_BASE_URL = "http://localhost:8001" 

# --- Evaluation Parameters ---
TRAINING_RATIO = 0.7 # Percentage of data for training
BATCH_SIZE = 100 # Batch size for sending logs to FastAPI (adjust based on memory/network)

# This threshold should ideally be consistent with main.py's prediction logic.
# If main.py returns 1 - similarity, then higher values are anomalous.
# Default global anomaly threshold in main.py is 0.8.
PREDICTION_THRESHOLD = 0.8 

def load_and_split_data(log_file: str, training_ratio: float) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Loads parsed HDFS data and splits it into training and testing sets.
    Performs a stratified split to ensure both normal and anomalous logs
    are present in the test set if they exist in the full dataset.
    Forces re-parsing initially to ensure fresh data.
    """
    logger.info("Loading and splitting HDFS dataset...")
    
    # Use the hdfs_parser to get the data. Force re-parse for the first time
    # to ensure we get the correctly labeled data.
    # This is the crucial change: force_reparse=True
    all_parsed_logs = process_structured_hdfs_dataset(
        log_file, PARSED_HDFS_DATA_CACHE, ANOMALY_LABELS_FILE, force_reparse=True 
    )

    if not all_parsed_logs:
        logger.error("No parsed logs available to split.")
        return [], []

    # Separate data into features (log entries) and labels (is_anomalous_true)
    # Convert bool to int (0/1) for scikit-learn compatibility
    X = np.array(all_parsed_logs)
    y = np.array([int(log.get('is_anomalous_true', False)) for log in all_parsed_logs])

    # Check if there are enough samples and at least two classes for splitting
    if len(X) < 2:
        logger.warning("Not enough log entries to perform a split. Need at least 2 entries.")
        return [], []

    unique_classes = np.unique(y)
    if len(unique_classes) < 2:
        logger.warning(f"Only one class ({unique_classes[0]}) present in the true labels after parsing. Cannot perform stratified split or proper ROC evaluation.")
        logger.warning("Ensure your anomaly_label.csv contains 'Anomaly' labels and those block_ids are present in HDFS.log.")
        return [], all_parsed_logs # Return all data as testing (or [] if you prefer it to exit)

    # Perform stratified split
    X_train_idx, X_test_idx, y_train, y_test = train_test_split(
        np.arange(len(X)), # Use indices for splitting
        y,
        test_size=(1 - training_ratio),
        stratify=y, # This is the key change!
        random_state=42 # For reproducibility
    )

    training_set = [all_parsed_logs[i] for i in X_train_idx]
    testing_set = [all_parsed_logs[i] for i in X_test_idx]

    logger.info(f"Split data: Training set size = {len(training_set)}, Testing set size = {len(testing_set)}")
    
    # Verify anomaly distribution in test set
    test_anomalies = sum(1 for log in testing_set if log.get('is_anomalous_true', False))
    logger.info(f"Anomalous logs in training set: {sum(1 for log in training_set if log.get('is_anomalous_true', False))}")
    logger.info(f"Anomalous logs in testing set: {test_anomalies}")

    if test_anomalies == 0:
        logger.warning("Warning: No true anomalous logs found in the testing set after splitting. ROC curve cannot be plotted.")

    return training_set, testing_set


def train_model(training_logs: List[Dict[str, Any]]):
    """
    Sends normal logs from the training set to the FastAPI backend
    for model training (semantic profiling).
    Only logs with 'is_anomalous_true' as False are sent for training.
    """
    logger.info(f"Sending {len(training_logs)} training logs to FastAPI for profiling...")
    normal_training_logs = [
        log for log in training_logs if not log.get('is_anomalous_true', False)
    ]
    logger.info(f"Using {len(normal_training_logs)} logs for training (only 'Normal' logs).")

    if not normal_training_logs:
        logger.warning("No normal logs available for training. Skipping model training.")
        return

    # Extract only necessary fields for the API
    logs_to_send = [
        {
            "entity_id": log.get('block_id') or "global", # Use block_id as entity_id, or "global"
            "timestamp": log['timestamp'],
            "log_content": log['message']
        }
        for log in normal_training_logs
    ]

    try:
        # Send logs in batches
        for i in range(0, len(logs_to_send), BATCH_SIZE):
            batch = logs_to_send[i:i + BATCH_SIZE]
            response = requests.post(f"{FASTAPI_BASE_URL}/profile/learn", json=batch)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            if (i // BATCH_SIZE + 1) % 10 == 0:
                 logger.info(f"  Sent {i + len(batch)} training logs.")
        logger.info("Model training (profiling) complete.")
    except requests.exceptions.ConnectionError:
        logger.error(f"Failed to connect to FastAPI at {FASTAPI_BASE_URL}. Is the server running?")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending training logs to FastAPI: {e}")
        logger.error(f"Response content: {response.text if 'response' in locals() else 'N/A'}")
        sys.exit(1)


def evaluate_model_performance(testing_logs: List[Dict[str, Any]]) -> Tuple[List[int], List[float]]:
    """
    Sends testing logs to the FastAPI backend for anomaly detection and
    collects true labels and predicted anomaly scores.
    """
    logger.info(f"Sending {len(testing_logs)} testing logs to FastAPI for anomaly detection...")
    true_labels = []
    predicted_scores = []

    if not testing_logs:
        logger.warning("No testing logs to evaluate.")
        return [], []

    # Send logs in batches for detection
    logs_to_send = [
        {
            "entity_id": log.get('block_id') or "global", # Use block_id or "global" for detection
            "timestamp": log['timestamp'],
            "log_content": log['message']
        }
        for log in testing_logs
    ]

    try:
        for i in range(0, len(logs_to_send), BATCH_SIZE):
            batch = logs_to_send[i:i + BATCH_SIZE]
            response = requests.post(f"{FASTAPI_BASE_URL}/detect/batch", json=batch) # Using /detect/batch
            response.raise_for_status()
            results = response.json()
            
            for j, result in enumerate(results):
                # Ensure the order matches
                original_log = testing_logs[i + j]
                true_labels.append(int(original_log.get('is_anomalous_true', False)))
                predicted_scores.append(result['anomaly_score'])
            
            if (i // BATCH_SIZE + 1) % 10 == 0:
                 logger.info(f"  Processed {i + len(batch)} testing logs.")

        logger.info("Anomaly detection on testing logs complete.")
    except requests.exceptions.ConnectionError:
        logger.error(f"Failed to connect to FastAPI at {FASTAPI_BASE_URL}. Is the server running?")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        logger.error(f"Error sending testing logs to FastAPI: {e}")
        logger.error(f"Response content: {response.text if 'response' in locals() else 'N/A'}")
        sys.exit(1)
    
    return true_labels, predicted_scores

def plot_roc_curve(true_labels: List[int], predicted_scores: List[float], title_prefix: str = ""):
    """Plots the ROC curve."""
    if not true_labels or not predicted_scores:
        logger.warning("No data to plot ROC curve.")
        return

    y_true = np.array(true_labels)
    y_scores = np.array(predicted_scores)

    unique_classes = np.unique(y_true)
    if len(unique_classes) < 2:
        logger.error(f"Could not plot ROC curve: Only one class present in y_true ({unique_classes}). ROC AUC score is undefined.")
        return

    try:
        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'{title_prefix} Receiver Operating Characteristic (ROC) Curve')
        plt.legend(loc="lower right")
        plt.grid(True)
        plt.show()
    except ValueError as e:
        logger.error(f"Could not plot ROC curve: {e}. This might happen if there's only one class present in true_labels or an issue with scores.")


if __name__ == "__main__":
    logger.info("Starting HDFS Anomaly Detection Evaluation...")

    # Step 1: Load and split the HDFS dataset
    training_set, testing_set = load_and_split_data(HDFS_LOG_FILE, TRAINING_RATIO)

    if not training_set or not testing_set:
        logger.error("Insufficient data for training or testing. Exiting.")
        sys.exit(1)

    # Step 2: Train the model (send normal logs for profiling)
    train_model(training_set)

    logger.info("Waiting 5 seconds for profiles to settle...")
    time.sleep(5) 

    # Step 3: Evaluate the model (send test logs for anomaly detection)
    true_labels, predicted_scores = evaluate_model_performance(testing_set)

    if not true_labels:
        logger.error("No true labels or predicted scores obtained for evaluation. Exiting.")
        sys.exit(1)

    true_labels_np = np.array(true_labels)
    predicted_scores_np = np.array(predicted_scores)

    num_true_anomalies_in_test = np.sum(true_labels_np == 1)
    num_true_normals_in_test = np.sum(true_labels_np == 0)

    logger.info(f"\n--- Evaluation Summary ---")
    logger.info(f"Total testing logs: {len(testing_set)}")
    logger.info(f"True Anomalies in testing set: {num_true_anomalies_in_test}")
    logger.info(f"True Normals in testing set: {num_true_normals_in_test}")

    if num_true_anomalies_in_test == 0:
        logger.warning("Cannot calculate ROC AUC, Precision, Recall, F1-score as there are no TRUE anomalies in the testing set.")
        logger.warning("This means the stratified split didn't put any true anomalies into the test set, or your parser still isn't marking them.")
        logger.warning("Please re-run hdfs_parser.py and ensure it reports >0 true anomalous logs, then check the split in evaluate_model.py logs.")
    else:
        if len(np.unique(predicted_scores_np)) < 2:
            logger.warning("Predicted scores are all the same value. Cannot calculate meaningful metrics.")
        else:
            plot_roc_curve(true_labels, predicted_scores, title_prefix="HDFS Anomaly Detection")

            PREDICTION_THRESHOLD = 0.8 
            predicted_labels_binary = (predicted_scores_np > PREDICTION_THRESHOLD).astype(int)

            logger.info(f"Using prediction threshold: {PREDICTION_THRESHOLD}")
            logger.info(f"Predicted Anomalies: {np.sum(predicted_labels_binary == 1)}")
            logger.info(f"Predicted Normals: {np.sum(predicted_labels_binary == 0)}")

            precision = precision_score(true_labels_np, predicted_labels_binary, zero_division=0)
            recall = recall_score(true_labels_np, predicted_labels_binary, zero_division=0)
            f1 = f1_score(true_labels_np, predicted_labels_binary, zero_division=0)

            logger.info(f"Precision: {precision:.4f}")
            logger.info(f"Recall: {recall:.4f}")
            logger.info(f"F1-Score: {f1:.4f}")

            logger.info("\nClassification Report:")
            logger.info(classification_report(true_labels_np, predicted_labels_binary, target_names=['Normal', 'Anomaly'], zero_division=0))