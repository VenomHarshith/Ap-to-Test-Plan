import ast
import os
import re
import json
import hashlib
import ast
import hashlib
import requests
import xlsxwriter
import pandas as pd

# Ollama configuration
OLLAMA_URL = "http://acoe-ind-lnx:11434/api/generate"
MODEL = "llama3.1"


# Functions
def format_test_name(name):
    """Formats test function names into human-readable titles."""
    return name.replace("test_", "").replace("_", " ").capitalize()

def format_verification_line(method_name):
    """Cleans up verification method names for display."""
    cleaned = method_name.lower().replace("verify_", "").replace("check_", "").replace("test_", "").strip()
    return f"{cleaned.replace('_', ' ').capitalize()} verification is performed."

def excel_title(filename):
    base = os.path.splitext(filename)[0]
    parts = base.split('_')
    formatted = [part.capitalize() if part.islower() else part for part in parts]
    return " ".join(formatted) + " Test Plan"

def remove_pronouns(text):
    """Removes personal pronouns like 'I', 'we', 'you' from the text."""
    pronouns = r"\b(I|we|you|he|she|it|they|me|him|her|us|them|my|your|our|his|hers|its|their)\b"
    return re.sub(pronouns, "", text, flags=re.IGNORECASE).strip()

def extract_triggers_from_docstring(docstring):
    """Extracts the 'Triggers' section from the docstring and returns a structured sentence."""
    if not docstring:
        return ""

    lines = docstring.splitlines()
    trigger_lines = []
    capture_triggers = False

    for line in lines:
        stripped = line.strip()

        # Match variations like "Triggers:", "TRIGGERS:", "triggers" while allowing extra spaces
        if re.match(r"^\s*triggers\s*:", stripped, re.IGNORECASE):
            # Capture inline content after 'Triggers:'
            inline_trigger = stripped.split(":", 1)[1].strip()
            if inline_trigger.lower() == "none":
                return "This test has no specific triggers."
            if inline_trigger:
                trigger_lines.append(inline_trigger)
            capture_triggers = True
            continue

        if capture_triggers:
            # Stop capturing when another section starts (empty line or another heading)
            if not stripped or re.match(r"^\s*\w+.*:$", stripped):
                break  
            if stripped.lower() == "none":
                return "This test has no specific triggers."
            trigger_lines.append(stripped)

    return "This test is triggered by " + ", ".join(trigger_lines) + "." if trigger_lines else "This test has no specific triggers."

def extract_verification_from_docstring(docstring, file_path):
    """Extracts verification steps from docstrings and formats them as '... verification is performed at ...'."""
    if not docstring:
        return []

    verification_lines = []
    lines = docstring.splitlines()
    capture = False
    exclude_verification = "bundle" in file_path.lower()  # Check if the file is related to 'bundle'

    for line in lines:
        stripped = line.strip()
        if stripped.lower().startswith("verification:"):
            capture = True
            continue

        if capture:
            if stripped.startswith("-"):
                point = stripped.lstrip("-").strip()
                if not point or exclude_verification:
                    continue

                # Remove 'verify', 'verification', or similar words from the start
                cleaned = re.sub(r"^(verify|verification)\s*", "", point, flags=re.IGNORECASE)
                # Remove 'is performed' if present
                cleaned = re.sub(r"\bis performed\b", "", cleaned, flags=re.IGNORECASE).strip()
                # Format as required
                verification_lines.append(f"{cleaned} verification is performed.")
            elif stripped == "" or stripped.endswith(":"):
                break

    return verification_lines


def extract_parametrize_info(node):
    """Extracts parameterization details from test functions."""
    parametrize_info = []
    for decorator in node.decorator_list:
        if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
            if (decorator.func.attr == "parametrize"
                and isinstance(decorator.func.value, ast.Attribute)
                and decorator.func.value.attr == "mark"
                and isinstance(decorator.func.value.value, ast.Name)
                and decorator.func.value.value.id == "pytest"):

                if len(decorator.args) >= 2:
                    param_name_node = decorator.args[0]
                    param_values_node = decorator.args[1]

                    if isinstance(param_name_node, ast.Str):
                        param_name = param_name_node.s
                    elif isinstance(param_name_node, ast.Constant):
                        param_name = param_name_node.value
                    else:
                        continue

                    if isinstance(param_values_node, (ast.List, ast.Tuple)):
                        values = []
                        for elt in param_values_node.elts:
                            if isinstance(elt, ast.Str):
                                values.append(elt.s)
                            elif isinstance(elt, ast.Constant):
                                values.append(elt.value)
                            elif isinstance(elt, ast.Name):
                                values.append(elt.id)
                            else:
                                values.append(ast.unparse(elt))
                        parametrize_info.append((param_name, values))
                    else:
                        parametrize_info.append((param_name, ast.unparse(param_values_node)))

    return parametrize_info


def enhance_docstring(docstring):
    """Extracts everything before 'Verification:' and removes pronouns."""
    if not docstring or not docstring.strip():
        return ""

    doc_lines = docstring.splitlines()
    filtered_lines = []
    for line in doc_lines:
        if line.strip().lower().startswith("verification:"):
            break  # Stop at "Verification:"
        filtered_lines.append(line.strip())

    extracted_text = " ".join(filtered_lines).strip()

    # Remove pronouns from extracted text
    extracted_text = remove_pronouns(extracted_text)

    if not extracted_text:
        return docstring.strip()

    payload = {
        "model": MODEL,
        "prompt": (
            "Rewrite the following text into a single, natural-sounding paragraph. "
            "If there is a line starting with 'This test is triggered by', rewrite that line in proper English and place it at the end."
            "Do not include any introductory phrases like 'Here is a rewritten version' or 'This is a rewritten version' or 'Here is a rewritten version of the text in a single, natural-sounding paragraph:'."
            "Avoid headings, bullet points, personal pronouns, or any mention of rewriting. "
            "Just return the clean, rewritten paragraph and the rewritten trigger sentence as described:\n"
            f"{extracted_text}"
        ),
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        return response.json().get("response", "").strip()
    except Exception as e:
        print(f"⚠️ Error enhancing docstring: {e}")
        return extracted_text

def get_base_id_from_file(file_path):
    filename = os.path.basename(file_path)
    if filename.startswith("bundlemrg_ap_l2"):
        return "BundleApBaseL2"
    return filename.split("_")[0].capitalize() + "ApBase"

def annotate_parents(tree):
    """Annotates AST nodes with parent references."""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node


# Function to extract pass/fail criteria
def extract_pass_fail_criteria(node, source_code, file_path):
    """Extracts pass/fail criteria from test functions."""
    criteria_lines = []
    test_device_names = set()
    loop_vars = set()
    base_id = get_base_id_from_file(file_path)

    # Identify assigned variables
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Assign):
            for target in child.targets:
                if isinstance(target, ast.Name):
                    test_device_names.add(target.id)

    # Identify loop variables
    for child in ast.walk(node):
        if isinstance(child, ast.For):
            iter_node = child.iter
            if isinstance(iter_node, ast.Name) and iter_node.id in test_device_names:
                if isinstance(child.target, ast.Name):
                    loop_vars.add(child.target.id)

    # Extract method calls for verifications
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
            method_name = child.func.attr
            base = child.func.value

            base_chain = []
            current = base
            while isinstance(current, ast.Attribute):
                base_chain.insert(0, current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                base_chain.insert(0, current.id)

            if base_chain and base_chain[0] == "ApData" and method_name.startswith("verify_"):
                readable = method_name.replace("verify_", "").replace("_", " ").strip()
                if readable:
                    criteria_lines.append(f"{readable.capitalize()} verification is performed.")
                continue

            if not (
                "check" in method_name.lower()
                or "verify" in method_name.lower()
                or method_name.lower().startswith("test_")
            ):
                continue

            original_base = base
            while isinstance(base, ast.Attribute):
                if isinstance(base.value, ast.Name) and base.value.id == "self" and base.attr in {"basic_test", "test"}:
                    criteria_lines.append(format_verification_line(method_name))
                    break
                base = base.value

            if isinstance(base, ast.Name) and base.id == "self":
                criteria_lines.append(format_verification_line(method_name))
            elif isinstance(base, ast.Name):
                base_id = base.id
                if base_id == base.id or base_id in test_device_names or base_id in loop_vars:
                    criteria_lines.append(format_verification_line(method_name))

    # Extract verifications from docstring
    docstring = ast.get_docstring(node)
    doc_verifications = extract_verification_from_docstring(docstring, file_path)
    criteria_lines.extend(doc_verifications)

    # Ensure unique criteria
    seen = set()
    unique_criteria = []
    for line in criteria_lines:
        if (
            line
            and isinstance(line, str)
            and line.strip().lower() != "verification is performed."
            and line not in seen
        ):
            seen.add(line)
            unique_criteria.append(line)

    if not unique_criteria:
        return "Test case is passed if all verifications are successful."

    unique_criteria.append("Test case is passed if above verifications are successful.")
    return "\n".join(unique_criteria)


def generate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except PermissionError as e:
        print(f"⚠️ Skipping file '{file_path}' due to permission error: {e}")
        return None
def generate_sha256_from_string(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def load_hash_records(json_file):
    if os.path.exists(json_file):
        with open(json_file, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def save_hash_records(json_file, records):
    os.makedirs(os.path.dirname(json_file), exist_ok=True)
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(records, f, indent=4)

def append_test_case_to_json(json_file, file_name, test_case_name, procedure, criteria, test_hash):

    os.makedirs(os.path.dirname(json_file), exist_ok=True)

    try:
        if os.path.exists(json_file) and os.path.getsize(json_file) > 0:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}
    except json.JSONDecodeError:
        print("⚠️ Warning: JSON file is corrupted or empty. Reinitializing.")
        data = {}

    if file_name not in data or not isinstance(data[file_name], dict):
        data[file_name] = {"test_cases": []}

    test_cases = data[file_name]["test_cases"]

    # Find the index of the existing test case (if any)
    existing_index = next(
        (i for i, tc in enumerate(test_cases) if tc.get("Test Case Name") == test_case_name),
        None
    )

    # Remove the old test case if it exists
    test_cases = [tc for tc in test_cases if tc.get("Test Case Name") != test_case_name]

    # Create the updated test case
    new_test_case = {
        "Test Case Name": test_case_name,
        "Procedure": procedure,
        "Pass/Fail Criteria": criteria
    }

    # Insert at the original index or append if not found
    if existing_index is not None and existing_index <= len(test_cases):
        test_cases.insert(existing_index, new_test_case)
    else:
        test_cases.append(new_test_case)

    data[file_name]["test_cases"] = test_cases

    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def model_optimization(file_path):
    """Extracts and enhances only changed test cases from a Python test file."""
    hash_file = "./hash_records.json"
    json_file = "./test_case_details.json"
    file_name = os.path.basename(file_path)
    hash_value = generate_sha256(file_path)
    records = load_hash_records(hash_file)

    if file_name in records and records[file_name].get("file_hash") == hash_value:
        print("✅ File already processed. Skipping.")
        return
    else:
        print("🔁 File is new or changed. Processing.")
        if file_name not in records:
            records[file_name] = {
                "file_hash": hash_value,
                "test_cases": {}
            }
        else:
            records[file_name]["file_hash"] = hash_value

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                source_code = file.read()
        except PermissionError as e:
            print(f"⚠️ Skipping file '{file_path}' due to permission error: {e}")
            return
        
    # Fix indentation: replace all tabs with 4 spaces in memory
    source_code_fixed = source_code.replace('\t', '    ')

    try:
        tree = ast.parse(source_code_fixed)
    except SyntaxError as e:
        print(f"⚠️ Skipping file '{file_path}' due to syntax error: {e}")
        return

    annotate_parents(tree)

    test_nodes = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
    ]

    for node in test_nodes:
        test_source = ast.get_source_segment(source_code, node)
        test_hash = generate_sha256_from_string(test_source)

        previous_hash = records[file_name]["test_cases"].get(node.name)
        if previous_hash == test_hash:
            print(f"✅ Test case '{node.name}' unchanged. Skipping.")
            continue

        print(f"🔄 Updating test case: {node.name}")
        docstring = ast.get_docstring(node)
        triggers_sentence = extract_triggers_from_docstring(docstring)

        if triggers_sentence:
            docstring += "\n" + triggers_sentence

        procedure = enhance_docstring(docstring)
        pretty_name = format_test_name(node.name)
        criteria = extract_pass_fail_criteria(node, source_code, file_path)
        param_info = extract_parametrize_info(node)

        if param_info:
            param_lines = [
                "This test function is parameterized using pytest.mark.parametrize to automatically run all combinations of the following parameter values:"
            ]
            for name, values in param_info:
                if isinstance(values, list):
                    value_str = " and ".join(f'"{v}"' for v in values)
                else:
                    value_str = f'"{values}"'
                param_lines.append(f"{name}: {value_str}")
            procedure += "\n\n" + "\n".join(param_lines)

        records[file_name]["test_cases"][node.name] = test_hash
        append_test_case_to_json(json_file, file_name, pretty_name, procedure, criteria, test_hash)

        print(f"\nTest Case Name: {pretty_name}")
        print(f"Procedure:\n{procedure}")
        print(f"Pass/Fail Criteria:\n{criteria}")
        print("=" * 80)

    save_hash_records(hash_file, records)
        
                                    
def json_to_styled_excel(input_json, output_excel, target_filename):
    output_dir = os.path.dirname(output_excel)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    with open(input_json, 'r') as f:
        data = json.load(f)

    if target_filename not in data:
        print(f"⚠️ No test case data found for {target_filename}. Skipping Excel generation.")
        return

    workbook = xlsxwriter.Workbook(output_excel)

    title_format = workbook.add_format({
        'bold': True, 'font_color': 'white', 'font_size': 14, 'align': 'center',
        'valign': 'vcenter', 'border': 1, 'bg_color': "#2C61BC"
    })
    header_format = workbook.add_format({
        'bold': True, 'font_color': 'white', 'bg_color': "#153B82",
        'align': 'center', 'valign': 'vcenter', 'border': 1
    })
    body_format = workbook.add_format({
        'border': 1, 'align': 'left', 'valign': 'top', 'text_wrap': True
    })
    bold_format = workbook.add_format({
        'border': 1, 'bold': True, 'align': 'left', 'valign': 'top', 'text_wrap': True
    })
    sno_format = workbook.add_format({
        'border': 1, 'align': 'center', 'valign': 'top'
    })

    headers = ['S. No', 'Test Case Name', 'Procedure', 'Pass/Fail Criteria']

    content = data[target_filename]
    title = excel_title(target_filename)
    sheet_name = title[:31]
    worksheet = workbook.add_worksheet(sheet_name)

    test_cases = content.get('test_cases', [])
    if not test_cases:
        workbook.close()
        return

    df = pd.DataFrame(test_cases).rename(columns={
        'name': 'Test Case Name',
        'procedure': 'Procedure',
        'criteria': 'Pass/Fail Criteria'
    })
    df = df[['Test Case Name', 'Procedure', 'Pass/Fail Criteria']]
    df.insert(0, 'S. No', range(1, len(df) + 1))

    worksheet.merge_range(0, 0, 0, df.shape[1] - 1, title, title_format)

    for col, header in enumerate(headers):
        worksheet.write(1, col, header, header_format)

    for row_num, row_data in enumerate(df.itertuples(index=False, name=None), start=2):
        worksheet.write_number(row_num, 0, row_data[0], sno_format)
        worksheet.write(row_num, 1, row_data[1], bold_format)
        worksheet.write(row_num, 2, row_data[2], body_format)
        worksheet.write(row_num, 3, row_data[3], body_format)

    worksheet.set_column(0, 0, 6)
    worksheet.set_column(1, 1, 35)
    worksheet.set_column(2, 2, 65)
    worksheet.set_column(3, 3, 50)

    workbook.close()
    
def process_file(subdir, filename, root_directory, json_file, output_root):
    file_path = os.path.join(subdir, filename)
    model_optimization(file_path)

    base_name = os.path.splitext(filename)[0]
    excel_filename = f"{base_name}_testplan.xlsx"

    # Determine relative subfolder under root_directory
    relative_path = os.path.relpath(subdir, root_directory)
    output_subfolder = os.path.join(output_root, relative_path)

    if not os.path.exists(output_subfolder):
        os.makedirs(output_subfolder)

    excel_output = os.path.join(output_subfolder, excel_filename)
    json_to_styled_excel(json_file, excel_output, filename)

ap_codes_directory = "/auto/violet/cron_clone_iosxr_byefr_cyclometric_complexity_tool/test/ap"
json_file = "./test_case_details.json"
excel_output_dir = "Excels"

def process_all_ap_files(root_directory, json_file, output_root):
    if not os.path.exists(root_directory):
        print(f"❌ Directory '{root_directory}' not found.")
        return

    # Folders to search in (relative to root_directory)
    target_folders = [
        "bundlemgr",
        "bng",
        "mpls",
        "l2"
    ]

    # For each target folder, walk all subfolders and process .py files (excluding those with 'base' in the name and including only those with 'ap' in the name)
    for folder in target_folders:
        target_path = os.path.join(root_directory, folder)
        if not os.path.exists(target_path):
            continue
        for subdir, _, files in os.walk(target_path):
            for filename in files:
                lower_name = filename.lower()
                if (
                    filename.endswith(".py")
                    and "base" not in lower_name
                    and "ap" in lower_name
                ):
                    process_file(subdir, filename, root_directory, json_file, output_root)
                

process_all_ap_files(ap_codes_directory, json_file, excel_output_dir)
