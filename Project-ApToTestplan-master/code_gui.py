import streamlit as st
import os
import base64

# Page configuration
st.set_page_config(page_title="Test Plan for APs", layout="centered")

# Function to encode image to base64
def get_base64_image(image_path):
    with open(image_path, "rb") as img_file:
        encoded = base64.b64encode(img_file.read()).decode()
    return encoded

# Load background image
bg_image = get_base64_image("CISCO_Img.png")

# Custom CSS
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
        background-position: 2vw 1vw;
        background-size: 10vw auto;
    }}

    .stFileUploader > div > div {{
        display: none;
    }}
    </style>
    """,
    unsafe_allow_html=True
)

# Title and AP selection
st.title("📋 Download Test Plan for APs")

# Info box
with st.expander("ℹ️ What does the Test Plan contain?", expanded=False):
    st.markdown("""
    The test plan includes:
    - List of all test cases
    - Step-by-step procedures for each test
    - Triggers and input parameters (if applicable)
    - Clearly defined pass/fail criteria
    """)

# Load Excel files from 'excels' folder
import os
import streamlit as st

excel_folder = "Excels"

if not os.path.exists(excel_folder):
    st.error("❌ 'Excels' folder not found.")
else:
    # Get all subdirectories (APs)
    ap_names = sorted([
        name for name in os.listdir(excel_folder)
        if os.path.isdir(os.path.join(excel_folder, name))
    ])

    selected_ap = st.selectbox("Select an AP", ap_names)

    if selected_ap:
        st.subheader(f"📂 Test Plans for '{selected_ap}'")

        ap_path = os.path.join(excel_folder, selected_ap)
        excel_files = [
            f for f in os.listdir(ap_path)
            if f.endswith(".xlsx")
        ]

        if not excel_files:
            st.info("ℹ️ No test plan files found in this AP.")
        else:
            for file_name in excel_files:
                with st.expander(f"📄 {file_name}", expanded=False):
                    file_path = os.path.join(ap_path, file_name)
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                    st.download_button(
                        label="⬇️ Download Testplan",
                        data=file_data,
                        file_name=file_name,
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
