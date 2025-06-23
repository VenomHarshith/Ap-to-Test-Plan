import streamlit as st
import os
import base64
import json
from datetime import datetime

# Page configuration
st.set_page_config(page_title="Test Plan for APs", layout="wide")

# Function to encode image to base64
def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        encoded = base64.b64encode(img_file.read()).decode()
    return encoded

# Load background image
bg_image = get_base64_image("CISCO_Img.png")

# Enhanced Custom CSS
st.markdown(
    f"""
    <style>
    header {{ visibility: hidden; }}
    footer {{ visibility: hidden; }}
    

    .block-container {{
        padding-top: 6rem;
        border: 1.5px solid #ccc;
        border-radius: 10px;
        padding: 2rem;
        margin-top: 2rem;
    }}

    .stApp {{
        background: url("data:image/png;base64,{bg_image}") no-repeat fixed;
        background-position: right 2vw top 1vw;  /* Changed from 2vw (left) to 98vw (right) */
        background-size: 10vw auto;
    }}

    .stFileUploader > div > div {{
        display: none;
    }}
    
    h1, h2, h3 {{
        color: #0e5aa7;
    }}
    
    .stButton>button {{
        background-color: #0e5aa7;
        color: white;
        border-radius: 4px;
        padding: 0.5rem 1rem;
        font-weight: 500;
    }}
    
    .stButton>button:hover {{
        background-color: #0c4d8c;
    }}

    .efr-dashboard {{
        padding: 1rem;
        border-radius: 8px;
        background: linear-gradient(135deg, #e6f2ff 0%, #d1e6ff 100%);
        margin-bottom: 1.5rem;
        border-left: 4px solid #007bff;
        box-shadow: 0 3px 8px rgba(0,0,0,0.1);
    }}

    .tag-info {{
        font-family: 'Courier New', monospace;
        padding: 0.4rem 0.6rem;
        background: #0066cc;
        color: white;
        border-radius: 4px;
        font-weight: bold;
    }}

    .info-box ul {{
        margin-top: 0;
        padding-left: 1.2em;
    }}
    
    .info-box li {{
        margin-bottom: 0.6em;
    }}

    .stat-card {{
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border-radius: 10px;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border-left: 4px solid #28a745;
        box-shadow: 0 4px 15px rgba(0,0,0,0.08);
        transition: all 0.3s ease;
    }}
    
    .stat-card:hover {{
        transform: translateY(-5px);
        box-shadow: 0 6px 18px rgba(0,0,0,0.12);
    }}

    .stat-value {{
        font-size: 2rem;
        font-weight: bold;
        color: #0066cc;
        margin: 0.5rem 0;
    }}

    .stat-label {{
        font-size: 1rem;
        color: #444;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }}
    
    .stat-desc {{
        color: #555;
        font-size: 0.9rem;
        margin-top: 0.5rem;
    }}
    
    .sidebar .block-container {{
        background-color: #f8f9fa;
    }}
    
    .download-section {{
        padding: 1rem;
        background-color: #f9f9f9;
        border-radius: 8px;
        margin-top: 1rem;
    }}
    
    .expander-header {{
        background-color: #f1f8ff;
        border-radius: 4px;
        padding: 0.5rem;
        border-left: 3px solid #0066cc;
        margin-bottom: 0.5rem;
    }}
    
    .footer {{
        text-align: center;
        color: #666;
        padding: 1rem;
        border-top: 1px solid #eee;
        margin-top: 2rem;
    }}
    
    .main-content-box {{
        background-color: white;
        border: 1.5px solid #e1e4e8;
        border-radius: 12px;
        padding: 2rem;
        margin: 0 2rem 2rem 2rem;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
    }}
    
    div[data-testid="stSelectbox"] > label {{
        font-size: 0.5rem !important;
        font-weight: 500;
    }}
    </style>
    """,
    unsafe_allow_html=True
)

# Add sidebar content
with st.sidebar:
    st.title("About This Page")
    
    st.markdown("### 📕 Overview")
    st.markdown("""
    This tool provides test plans generated from EFR code for different Automated Programs (APs).
    Select an AP from the main page to view and download its test plans.
    """)
    
    st.markdown("### 📋 Test Plan Contents")
    st.markdown("""
    <div class="info-box">
    The Test Plan provides a comprehensive overview of the testing strategy and includes:
    <ul>
        <li>🧾 <strong>Test Case Catalogue</strong>: A detailed list of all planned test cases.</li>
        <li>🧭 <strong>Execution Steps</strong>: Clear, step-by-step procedures to follow for each test.</li>
        <li>🎯 <strong>Input Parameters & Triggers</strong>: Required conditions, configurations, or inputs to initiate each test.</li>
        <li>✅ <strong>Pass/Fail Criteria</strong>: Explicit success/failure conditions for validating results.</li>
    </ul>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### 👨‍💻 How It Works")
    st.markdown("""
    1. The system monitors EFR code changes
    2. When changes are detected, test plans are auto-generated
    3. Test plans reflect the latest code structure and requirements
    4. Files are organized by AP and sub-AP for easy access
    """)
    
    # Add statistics to sidebar
    st.markdown("---")
    st.markdown("#### Statistics")
    
    excel_folder = "Excels"
    main_aps = ["bundlemgr", "bng", "l2", "mpls"]
    
    total_aps = len([ap for ap in main_aps if os.path.isdir(os.path.join(excel_folder, ap))])
    
    # Count total Excel files across all folders
    total_files = 0
    if os.path.exists(excel_folder):
        for root, _, files in os.walk(excel_folder):
            total_files += len([f for f in files if f.endswith('.xlsx')])
    
    st.metric(label="Total APs", value=total_aps)
    st.metric(label="Total Test Plans", value=total_files)
    
    # Contact information
    st.markdown("---")
    st.markdown("#### Contact")
    st.markdown("For questions or issues, please contact Cisco Support.")

# Main content
st.title("📋 Download Test Plan for APs")

# EFR Details Dashboard - Enhanced 
st.markdown("### 🔄 EFR Build Information")

# Load EFR details
efr_json = "/auto/violet/cron_efr_data_for_aptoTest_plan/leatest_efr_details.json"

try:
    with open(efr_json) as f:
        efr_data = json.load(f)
    
    # Extract just the tag and date
    current_tag = efr_data.get("efr_tag", "Unknown")
    author_date = efr_data.get("author_date", "Unknown")
    
    try:
        # Parse date string like "Wed Jun 18 01:33:03 2025 -0700"
        date_obj = datetime.strptime(author_date, "%a %b %d %H:%M:%S %Y %z")
        formatted_date = date_obj.strftime("%B %d, %Y at %I:%M %p")
    except:
        formatted_date = author_date  # Use original if parsing fails
    
    # Display enhanced dashboard
    st.markdown(
        f"""
        <div class="efr-dashboard">
        <h3 style="margin-top:0; color:#000000;">Current EFR Build</h3>
        <p style="font-size:1.2rem; color:#000000"><strong>🏷️ EFR Tag:</strong> <span class="tag-info">{current_tag}</span></p>
        <p style="font-size:1.2rem;color:#000000"><strong>🕒 Last Updated:</strong> {formatted_date}</p>
        </div>
        """,
        unsafe_allow_html=True
    )
    
except Exception as e:
    st.warning(f"⚠️ Could not load EFR details: {e}")

# Enhanced statistics dashboard 
col1, col2, col3 = st.columns(3)

# Last script execution
last_run_time = os.path.getmtime("last_efr_tag.json") if os.path.exists("last_efr_tag.json") else None
if last_run_time:
    last_run_date = datetime.fromtimestamp(last_run_time).strftime("%B %d, %Y at %I:%M %p")
    
    with col1:
        st.markdown(
            f"""
            <div class="stat-card">
            <div class="stat-label">Last Script Execution</div>
            <div class="stat-value">🕒</div>
            <div class="stat-desc">{last_run_date}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

with col2:
    excel_folder = "Excels"
    ap_count = len([f for f in os.listdir(excel_folder) if os.path.isdir(os.path.join(excel_folder, f))]) if os.path.exists(excel_folder) else 0
    
    st.markdown(
        f"""
        <div class="stat-card">
        <div class="stat-label">Total APs</div>
        <div class="stat-value">{ap_count}</div>
        <div class="stat-desc">Main Automated Programs</div>
        </div>
        """,
        unsafe_allow_html=True
    )

with col3:
    total_files = 0
    if os.path.exists(excel_folder):
        for root, _, files in os.walk(excel_folder):
            total_files += len([f for f in files if f.endswith('.xlsx')])
    
    st.markdown(
        f"""
        <div class="stat-card">
        <div class="stat-label">Total Test Plans</div>
        <div class="stat-value">{total_files}</div>
        <div class="stat-desc">Automated Excel Documents</div>
        </div>
        """,
        unsafe_allow_html=True
    )

# Horizontal separator
st.markdown("---")

# Load Excel files section - using columns for better width control
st.markdown("### 📊 Download Test Plans")

# Create a three-column layout with the middle column containing our content
left_spacer, center_content, right_spacer = st.columns([1, 6, 1])

# Use the middle column for all content
with center_content:
    excel_folder = "Excels"
    main_aps = ["bundlemgr", "bng", "l2", "mpls"]

    if not os.path.exists(excel_folder):
        st.error("❌ 'Excels' folder not found.")
    else:
        # Only show the four main APs if they exist
        available_main_aps = [ap for ap in main_aps if os.path.isdir(os.path.join(excel_folder, ap))]
        st.markdown("### 📋 Select Main AP")
        selected_main_ap = st.selectbox("", available_main_aps, label_visibility="collapsed")

        if selected_main_ap:
            st.subheader(f"📂 Test Plans for '{selected_main_ap}' (all sub-APs)")
            main_ap_path = os.path.join(excel_folder, selected_main_ap)

            # Walk through all subfolders and collect .xlsx files
            excel_files = []
            for root, dirs, files in os.walk(main_ap_path):
                for file in files:
                    if file.endswith(".xlsx"):
                        rel_dir = os.path.relpath(root, main_ap_path)
                        rel_file = os.path.join(rel_dir, file) if rel_dir != "." else file
                        excel_files.append((rel_file, os.path.join(root, file)))

            if not excel_files:
                st.info("ℹ️ No test plan files found in any sub-AP.")
            else:
                # Create a nicer container for the files
                for rel_file, file_path in sorted(excel_files):
                    with st.expander(f"📄 {rel_file}", expanded=False):
                        with open(file_path, "rb") as f:
                            file_data = f.read()
                        
                        # Create columns for file details and download button
                        file_col, download_col = st.columns([3, 1])
                        
                        # Show file details in left column
                        with file_col:
                            file_size = os.path.getsize(file_path) / 1024  # Size in KB
                            file_date = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime("%Y-%m-%d %H:%M")
                            st.markdown(f"**File Size:** {file_size:.1f} KB")
                            st.markdown(f"**Last Modified:** {file_date}")
                        
                        # Download button in right column
                        with download_col:
                            st.download_button(
                                label="⬇️ Download Testplan",
                                data=file_data,
                                file_name=os.path.basename(file_path),
                                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                                key=rel_file
                            )
# Footer section
st.markdown("---")
st.markdown(
    '<div class="footer">© 2025 Cisco Systems, Inc. | Generated Test Plans from EFR Code</div>', 
    unsafe_allow_html=True
)
