import re
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional
import os
import json
import logging

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- File Paths Configuration ---
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Define your HDFS log file path
HDFS_LOG_FILE = os.path.join(SCRIPT_DIR, "HDFS.log")

# Define possible anomaly labels file names
POSSIBLE_ANOMALY_LABELS_FILES = [
    "anomaly_label.csv",
    "anomaly_labels.csv" # For flexibility
]
# --- IMPORTANT FIX: Determine ANOMALY_LABELS_FILE at module load time ---
ANOMALY_LABELS_FILE = None 
for fname in POSSIBLE_ANOMALY_LABELS_FILES:
    full_path = os.path.join(SCRIPT_DIR, fname)
    if os.path.exists(full_path):
        ANOMALY_LABELS_FILE = full_path
        logger.info(f"Found anomaly labels file: {ANOMALY_LABELS_FILE}")
        break

if ANOMALY_LABELS_FILE is None:
    logger.warning(f"No anomaly labels file found among {POSSIBLE_ANOMALY_LABELS_FILES} in '{SCRIPT_DIR}'. Logs will not be marked as truly anomalous.")
# --- END IMPORTANT FIX ---

# Define an optional file to cache parsed logs as JSON
PARSED_HDFS_DATA_CACHE = os.path.join(SCRIPT_DIR, "parsed_hdfs_logs.json")

# --- Log Line Parsing Pattern ---
LOG_PATTERN = re.compile(
    r'^(?P<year>\d{2})(?P<month>\d{2})(?P<day>\d{2})\s+' # Year, Month, Day (e.g., 081109)
    r'(?P<time>\d{6})\s+'                                # Time (HHMMSS, e.g., 203615)
    r'(?P<line_id>\d+)\s+'                               # Line ID
    r'(?P<level>[A-Z]+)\s+'                              # Log Level (INFO, WARN, ERROR, etc.)
    r'(?P<component>[a-zA-Z0-9.$]+):\s+'                 # Component (e.g., dfs.DataNode$PacketResponder)
    r'(?P<message>.*)$'                                  # The rest is the message
)

def parse_hdfs_log_line(line: str) -> Optional[Dict[str, Any]]:
    """
    Parses a single HDFS log line into a dictionary of extracted fields.
    Extracts year, month, day, time, line ID, level, component, and message.
    Also attempts to extract a 'block_id' if present in the message.
    """
    match = LOG_PATTERN.match(line)
    if not match:
        # logger.debug(f"Skipping unmatchable line: {line.strip()}") # Uncomment for detailed debugging
        return None
    
    data = match.groupdict()
    
    # Try to extract block ID from the message
    block_id_match = re.search(r'(blk_-?\d+)', data['message'])
    data['block_id'] = block_id_match.group(1) if block_id_match else None
    
    # Construct a full timestamp (assuming logs are from 20xx and year is 2 digits)
    try:
        full_year_str = f"20{data['year']}"
        date_time_str = f"{full_year_str}-{data['month']}-{data['day']} {data['time']}"
        data['timestamp'] = datetime.strptime(date_time_str, "%Y-%m-%d %H%M%S").isoformat()
    except ValueError as e:
        logger.warning(f"Could not parse timestamp for line: {line.strip()}. Error: {e}")
        data['timestamp'] = None # Could not parse timestamp
        
    return data


def load_anomaly_labels(file_path: str) -> Dict[str, str]:
    """
    Loads anomaly labels from a CSV file.
    Expected format: BlockId,Label (e.g., blk_1234,Anomaly or blk_5678,Normal)
    """
    labels = {}
    if not file_path:
        logger.warning("No anomaly labels file path provided. Returning empty labels.")
        return labels

    try:
        # Using a raw string for sep to avoid SyntaxWarning
        df = pd.read_csv(file_path, sep=r'\s*,\s*', header=0, engine='python', skipinitialspace=True)
        if 'BlockId' in df.columns and 'Label' in df.columns:
            for index, row in df.iterrows():
                # Ensure stripping whitespace from BlockId and Label
                labels[str(row['BlockId']).strip()] = str(row['Label']).strip() 
            logger.info(f"Loaded {len(labels)} anomaly labels from {file_path}")
            anomaly_count_in_csv = sum(1 for label in labels.values() if label == 'Anomaly')
            logger.info(f"  (From CSV) Total 'Anomaly' labels found: {anomaly_count_in_csv}")
            # --- DIAGNOSTIC PRINT: Sample Anomaly Block IDs from CSV ---
            logger.debug(f"  Sample Anomaly Block IDs from CSV: {[k for k,v in labels.items() if v == 'Anomaly'][:5]}")
            # --- END DIAGNOSTIC PRINT ---
        else:
            logger.warning(f"Warning: '{file_path}' does not contain expected 'BlockId' and 'Label' columns. Columns found: {df.columns.tolist()}")
    except FileNotFoundError:
        logger.error(f"Error: Anomaly labels file '{file_path}' not found.")
    except pd.errors.EmptyDataError:
        logger.warning(f"Warning: Anomaly labels file '{file_path}' is empty.")
    except Exception as e:
        logger.exception(f"An error occurred while loading anomaly labels from {file_path}: {e}")
    return labels

def process_raw_hdfs_dataset(log_file_path: str, anomaly_labels_file: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Reads and parses the raw HDFS log file line by line.
    If anomaly_labels_file is provided, it will load labels and mark logs as anomalous.
    """
    logger.info(f"Parsing raw HDFS log file: {log_file_path}")
    parsed_logs: List[Dict[str, Any]] = []
    anomaly_labels: Dict[str, str] = {}

    if anomaly_labels_file: # Only load if a path is provided
        anomaly_labels = load_anomaly_labels(anomaly_labels_file)
    else:
        logger.warning("No anomaly labels file provided for parsing. All logs will be labeled 'Normal' (is_anomalous_true=False).")
    
    parsed_count = 0
    anomalous_true_count = 0
    block_id_missing_count = 0

    try:
        with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if (i + 1) % 100000 == 0:
                    logger.info(f"  Processed {i+1} lines...")
                
                parsed_data = parse_hdfs_log_line(line)
                if parsed_data:
                    parsed_count += 1
                    
                    if parsed_data['block_id']:
                        # --- DIAGNOSTIC PRINT: Check block_id and lookup ---
                        if i < 100 or (i % 500 == 0 and i > 0): # Print for first 100 and then every 500
                            logger.debug(f"Line {i+1}: Extracted Block ID: '{parsed_data['block_id']}'")
                            label_from_csv = anomaly_labels.get(parsed_data['block_id'], 'NOT_FOUND')
                            logger.debug(f"  Lookup in anomaly_labels: '{label_from_csv}'")
                            if label_from_csv == 'NOT_FOUND':
                                logger.debug(f"  Block ID '{parsed_data['block_id']}' not found in anomaly_label.csv")
                            elif label_from_csv == 'Normal':
                                logger.debug(f"  Block ID '{parsed_data['block_id']}' found as 'Normal'")
                            elif label_from_csv == 'Anomaly':
                                logger.debug(f"  Block ID '{parsed_data['block_id']}' found as 'Anomaly'")
                        # --- END DIAGNOSTIC PRINT ---

                        label = anomaly_labels.get(parsed_data['block_id'], 'Normal')
                        parsed_data['is_anomalous_true'] = (label == 'Anomaly')
                        if label == 'Anomaly':
                            anomalous_true_count += 1
                    else:
                        block_id_missing_count += 1
                        parsed_data['is_anomalous_true'] = False
                        
                    parsed_logs.append(parsed_data)
        
        logger.info(f"Finished parsing. Total lines processed: {i+1}")
        logger.info(f"Total successfully parsed log entries: {parsed_count}")
        logger.info(f"Log entries with missing Block ID (auto-labeled 'Normal'): {block_id_missing_count}")
        logger.info(f"Total entries marked as TRUE anomalous (based on block_id and {os.path.basename(anomaly_labels_file or 'N/A')}): {anomalous_true_count}")

    except FileNotFoundError:
        logger.error(f"Error: Raw log file '{log_file_path}' not found. Please ensure it exists.")
    except Exception as e:
        logger.exception(f"An error occurred during log file processing: {e}") # Use exception for full traceback
    
    return parsed_logs

def process_structured_hdfs_dataset(
    log_file_path: str,
    output_json_path: Optional[str] = None,
    anomaly_labels_file: Optional[str] = None,
    force_reparse: bool = False # <-- NEW ARGUMENT
) -> List[Dict[str, Any]]:
    """
    Wrapper function to process the HDFS dataset.
    If output_json_path exists, it tries to load from there first, unless force_reparse is True.
    Otherwise, it parses the raw logs and saves to JSON (if output_json_path is provided).
    """
    if not force_reparse and output_json_path and os.path.exists(output_json_path): # <-- Check force_reparse
        logger.info(f"Loading parsed HDFS data from {output_json_path}")
        try:
            with open(output_json_path, 'r', encoding='utf-8') as f:
                parsed_data = json.load(f)
            
            loaded_anomalies = sum(1 for entry in parsed_data if entry.get('is_anomalous_true'))
            logger.info(f"  (From JSON Cache) Total entries marked as TRUE anomalous: {loaded_anomalies}")
            return parsed_data
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON from cache '{output_json_path}': {e}. Re-parsing raw logs.")
        except Exception as e:
            logger.error(f"An error occurred loading JSON cache '{output_json_path}': {e}. Re-parsing raw logs.")

    # If not found, invalid, no output path, or force_reparse is True, process raw logs
    logger.info("Forcing re-parse of raw HDFS log file (cache either not found, invalid, or force_reparse=True).") # <-- Added log
    parsed_data = process_raw_hdfs_dataset(log_file_path, anomaly_labels_file)

    if output_json_path and parsed_data:
        logger.info(f"Saving parsed HDFS data to {output_json_path}")
        try:
            with open(output_json_path, 'w', encoding='utf-8') as f:
                json.dump(parsed_data, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving parsed HDFS data to {output_json_path}: {e}")
            
    return parsed_data

if __name__ == "__main__":
    try:
        logger.info("Starting HDFS Log Parsing process...")

        # Check if the raw HDFS log file exists
        if not os.path.exists(HDFS_LOG_FILE):
            raise FileNotFoundError(f"Raw log file '{HDFS_LOG_FILE}' not found. Please ensure it is in the '{SCRIPT_DIR}' directory.")
        
        # ANOMALY_LABELS_FILE is now determined above, at module level.
        # So we just need to check if it was found.
        if ANOMALY_LABELS_FILE is None:
            logger.warning(f"No anomaly labels file found among {POSSIBLE_ANOMALY_LABELS_FILES} in '{SCRIPT_DIR}'. Logs will not be marked as truly anomalous.")
        
        # Process the HDFS dataset - force reparse for initial run
        # Added force_reparse=True here for direct execution to ensure it always parses.
        hdfs_data = process_structured_hdfs_dataset(HDFS_LOG_FILE, PARSED_HDFS_DATA_CACHE, ANOMALY_LABELS_FILE, force_reparse=True)
        
        if hdfs_data:
            logger.info(f"Final result: Successfully obtained {len(hdfs_data)} log entries.")
            true_anomalies_final = sum(1 for entry in hdfs_data if entry.get('is_anomalous_true'))
            logger.info(f"Final count of TRUE anomalous entries: {true_anomalies_final}")

            if true_anomalies_final == 0 and ANOMALY_LABELS_FILE:
                logger.warning("Despite having an anomaly labels file, 0 logs were marked as true anomalous.")
                logger.warning("  Possible reasons: Mismatch between log block IDs and anomaly_label.csv block IDs, or no 'Anomaly' labels in your CSV.")
                logger.warning("  Please verify the 'BlockId' column in anomaly_label.csv against 'blk_XXXX' patterns in HDFS.log.")
        else:
            logger.error("No log entries were processed. Check log file format, path, and parsing logic.")

    except FileNotFoundError as e:
        logger.critical(f"Fatal Error: {e}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")