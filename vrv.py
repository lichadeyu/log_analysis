import os
import re
import pandas as pd
import streamlit as st
import time
from io import BytesIO, StringIO

# Define the regex pattern to parse the log file entries
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>[^"]+)")?'
)

def process_log_file(log_file, suspicious_threshold=10):
    timer_start = time.time()
    rows = []
    for line in log_file:
        match = log_pattern.match(line)
        if match:
            row = [
                match.group("ip"),
                match.group("datetime"),
                match.group("method"),
                match.group("endpoint"),
                int(match.group("status")),
                int(match.group("size")),
                match.group("message") or ""
            ]
            rows.append(row)

    df = pd.DataFrame(rows, columns=["IP Address", "Datetime", "Method", "Endpoint", "Status", "Size", "Message"])
    ip_counts = df['IP Address'].value_counts()
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda item: (-item[1], item[0]))

    endpoint_counts = df['Endpoint'].value_counts()
    most_accessed_endpoint = endpoint_counts.index[0] if not endpoint_counts.empty else None
    most_accessed_count = int(endpoint_counts.iloc[0]) if not endpoint_counts.empty else 0

    failed_logins = df[(df['Status'] == 401) | (df['Message'].str.contains('Invalid credentials', na=False))]
    failed_login_counts = failed_logins['IP Address'].value_counts()
    suspicious_ips = failed_login_counts[failed_login_counts > suspicious_threshold]
    sorted_suspicious_ips = sorted(suspicious_ips.items(), key=lambda item: (-item[1], item[0]))

    timer_end = time.time()

    return {
        "requests_per_ip": sorted_ip_counts,
        "most_accessed_endpoint": {
            "endpoint": most_accessed_endpoint,
            "access_count": most_accessed_count
        },
        "suspicious_activity": sorted_suspicious_ips,
        "processing_time": round(timer_end - timer_start, 3),
        "number_of_rows": len(df)
    }

def generate_csv(analysis_results):
    ip_df = pd.DataFrame(analysis_results['requests_per_ip'], columns=['IP Address', 'Request Count'])
    endpoint_df = pd.DataFrame([{
        'Endpoint': analysis_results['most_accessed_endpoint']['endpoint'],
        'Access Count': analysis_results['most_accessed_endpoint']['access_count']
    }])
    suspicious_df = pd.DataFrame(analysis_results['suspicious_activity'], columns=['IP Address', 'Failed Login Count'])

    output = StringIO()
    ip_df.to_csv(output, index=False)
    output.write("\nMost Accessed Endpoint:\n")
    endpoint_df.to_csv(output, index=False)
    output.write("\nSuspicious Activity:\n")
    suspicious_df.to_csv(output, index=False)

    return output.getvalue()

# Streamlit UI
st.set_page_config(page_title="Log File Analyzer", layout="wide", page_icon="📊")

st.title("📊 Log File Analyzer")
st.markdown("Analyze your log files for **suspicious activities**, **access patterns**, and generate detailed **reports**.")

uploaded_file = st.file_uploader("📁 Upload your log file", type=["log"], help="Upload a .log file for analysis.")
threshold = st.number_input("🚨 Suspicious Activity Threshold (Failed Logins)", min_value=1, value=10, step=1)

if uploaded_file is not None:
    try:
        log_lines = uploaded_file.read().decode('utf-8').splitlines()
        with st.spinner("🔍 Analyzing log file..."):
            analysis_results = process_log_file(log_lines, suspicious_threshold=threshold)

        st.success("✅ Analysis Completed!")

        st.markdown("### 📈 Analysis Summary")
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Processing Time", f"{analysis_results['processing_time']} seconds")
            st.metric("Rows Processed", analysis_results['number_of_rows'])
        with col2:
            st.metric("Most Accessed Endpoint", analysis_results['most_accessed_endpoint']['endpoint'])
            st.metric("Access Count", analysis_results['most_accessed_endpoint']['access_count'])

        st.markdown("### 📋 Detailed Results")
        with st.expander("📌 Requests per IP Address"):
            st.table(pd.DataFrame(analysis_results['requests_per_ip'], columns=["IP Address", "Request Count"]))

        with st.expander("📌 Suspicious Activity"):
            st.table(pd.DataFrame(analysis_results['suspicious_activity'], columns=["IP Address", "Failed Login Count"]))

        csv_output = generate_csv(analysis_results)
        st.download_button(
            label="📥 Download Full Report as CSV",
            data=BytesIO(csv_output.encode('utf-8')),
            file_name="log_analysis_results.csv",
            mime="text/csv"
        )
    except Exception as e:
        st.error(f"❌ An error occurred: {e}")
