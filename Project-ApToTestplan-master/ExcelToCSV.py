import os
import pandas as pd

# Define the source and destination directories
source_dir = "Excels"
destination_dir = "CSVs"

# Create the destination directory if it doesn't exist
os.makedirs(destination_dir, exist_ok=True)

# Traverse the source directory
for root, dirs, files in os.walk(source_dir):
    for file in files:
        if file.endswith(".xlsx"):
            # Construct full file path
            file_path = os.path.join(root, file)

            # Read the Excel file
            df = pd.read_excel(file_path, engine='openpyxl')

            # Determine the relative path to maintain folder structure
            relative_path = os.path.relpath(root, source_dir)
            target_folder = os.path.join(destination_dir, relative_path)

            # Create the target folder if it doesn't exist
            os.makedirs(target_folder, exist_ok=True)

            # Construct the CSV file path
            csv_file_name = os.path.splitext(file)[0] + ".csv"
            csv_file_path = os.path.join(target_folder, csv_file_name)

            # Save the DataFrame as a CSV file
            df.to_csv(csv_file_path, index=False)

print("✅ All Excel files have been converted to CSV and saved in the 'CSVs' directory.")

