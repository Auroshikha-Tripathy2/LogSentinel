import json
import pandas as pd

# Load the parsed JSON data
with open('parsed_hdfs_logs.json', 'r') as f:
    data = json.load(f)

# Load the original CSV labels
df = pd.read_csv('anomaly_label.csv')

# Create a dictionary for quick lookup
df_dict = dict(zip(df['BlockId'], df['Label']))

# Count true anomalies in JSON
json_anomalies = sum(1 for log in data if log['is_anomalous_true'])
json_normals = len(data) - json_anomalies

print("=== PARSED HDFS JSON ANALYSIS ===")
print(f"Total logs in JSON: {len(data)}")
print(f"True anomalies in JSON: {json_anomalies}")
print(f"Normal logs in JSON: {json_normals}")
print(f"Anomaly percentage in JSON: {json_anomalies/len(data)*100:.2f}%")

print("\n=== ORIGINAL CSV ANALYSIS ===")
csv_anomalies = len(df[df['Label'] == 'Anomaly'])
csv_normals = len(df[df['Label'] == 'Normal'])
print(f"Total rows in CSV: {len(df)}")
print(f"Anomalies in CSV: {csv_anomalies}")
print(f"Normals in CSV: {csv_normals}")
print(f"Anomaly percentage in CSV: {csv_anomalies/len(df)*100:.2f}%")

print("\n=== VERIFICATION ===")
correct_labels = 0
total_checked = 0
mismatches = []

for log in data:
    if log['block_id'] in df_dict:
        total_checked += 1
        csv_label = df_dict[log['block_id']]
        json_label = log['is_anomalous_true']
        
        # Check if labels match
        if (csv_label == 'Anomaly' and json_label == True) or (csv_label == 'Normal' and json_label == False):
            correct_labels += 1
        else:
            mismatches.append({
                'block_id': log['block_id'],
                'csv_label': csv_label,
                'json_label': json_label
            })

print(f"Total logs checked: {total_checked}")
print(f"Correctly labeled: {correct_labels}")
print(f"Accuracy: {correct_labels/total_checked*100:.2f}%")
print(f"Mismatches found: {len(mismatches)}")

if mismatches:
    print("\nFirst 5 mismatches:")
    for i, mismatch in enumerate(mismatches[:5]):
        print(f"  {i+1}. Block {mismatch['block_id']}: CSV={mismatch['csv_label']}, JSON={mismatch['json_label']}") 