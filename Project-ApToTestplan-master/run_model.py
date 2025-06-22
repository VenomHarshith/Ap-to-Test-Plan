import json
import os
import subprocess

# Paths
current_dir = os.path.dirname(os.path.abspath(__file__))
last_tag_json = os.path.join(current_dir, "last_efr_tag.json")
efr_json = "/auto/violet/cron_efr_data_for_aptoTest_plan/leatest_efr_details.json"

# Load current efr_tag
with open(efr_json) as f:
    data = json.load(f)
current_tag = data.get("efr_tag")

# Load last seen efr_tag from JSON (if exists)
last_tag = None
if os.path.exists(last_tag_json):
    with open(last_tag_json) as f:
        last_tag_data = json.load(f)
        last_tag = last_tag_data.get("efr_tag")

# If tag changed, run your model and update the record
if current_tag != last_tag:
    print(f"efr_tag changed: {last_tag} -> {current_tag}. Running model...")
    # Replace the next line with your actual model run command
    subprocess.run(["python", os.path.join(current_dir, "code_1.py")])
    # Update the tag record in JSON
    with open(last_tag_json, "w") as f:
        json.dump({"efr_tag": current_tag}, f)
else:
    print("efr_tag unchanged. No action taken.")