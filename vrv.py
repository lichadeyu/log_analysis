# Import necessary modules
import os  # Provides a way to interact with the operating system (not used in this script)
import re  # Regular expressions for pattern matching
import pandas as pd  # For data manipulation and analysis
import streamlit as st  # Streamlit for creating interactive web applications
import time  # For measuring processing time
from io import BytesIO, StringIO  # Utilities for handling in-memory file streams

# Define the regex pattern to parse log file entries
# This assumes a standard log file format with IP, datetime, HTTP method, endpoint, status, size, and optional message
log_pattern = re.compile(
    r'(?P<ip>\S+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\S+) (?P<endpoint>\S+) \S+" (?P<status>\d+) (?P<size>\d+)(?: "(?P<message>[^"]+)")?'
)

# Function to process the log file and extract analysis data
def process_log_file(log_file, suspicious_threshold=10):
    # Start a timer to measure processing time
    timer_start = time.time()
    
    rows = []  # List to store parsed log file entries
    
    # Process each line of the log file
    for line in log_file:
        # Match the line against the regex pattern
        match = log_pattern.match(line)
        if match:
            # Extract relevant fields and append to rows
            row = [
                match.group("ip"),          # IP address
                match.group("datetime"),    # Date and time
                match.group("method"),      # HTTP method (GET, POST, etc.)
                match.group("endpoint"),    # Accessed endpoint
                int(match.group("status")), # HTTP status code
                int(match.group("size")),   # Response size
                match.group("message") or ""  # Optional message
            ]
            rows.append(row)
    
    # Create a DataFrame from the parsed log entries
    df = pd.DataFrame(rows, columns=["IP Address", "Datetime", "Method", "Endpoint", "Status", "Size", "Message"])
    
    # Count requests per IP address
    ip_counts = df['IP Address'].value_counts()
    sorted_ip_counts = sorted(ip_counts.items(), key=lambda item: (-item[1], item[0]))  # Sort by count, then by IP
    
    # Find the most accessed endpoint and its count
    endpoint_counts = df['Endpoint'].value_counts()
    most_accessed_endpoint = endpoint_counts.index[0] if not endpoint_counts.empty else None
    most_accessed_count = int(endpoint_counts.iloc[0]) if not endpoint_counts.empty else 0
    
    # Identify failed login attempts (status 401 or messages containing "Invalid credentials")
    failed_logins = df[(df['Status'] == 401) | (df['Message'].str.contains('Invalid credentials', na=False))]
    failed_login_counts = failed_logins['IP Address'].value_counts()
    
    # Detect suspicious IPs based on the threshold for failed logins
    suspicious_ips = failed_login_counts[failed_login_counts > suspicious_threshold]
    sorted_suspicious_ips = sorted(suspicious_ips.items(), key=lambda item: (-item[1], item[0]))  # Sort by count, then by IP
    
    # End the timer
    timer_end = time.time()
    
    # Return analysis results as a dictionary
    return {
        "requests_per_ip": sorted_ip_counts,  # Requests per IP
        "most_accessed_endpoint": {          # Most accessed endpoint details
            "endpoint": most_accessed_endpoint,
            "access_count": most_accessed_count
        },
        "suspicious_activity": sorted_suspicious_ips,  # Suspicious activity details
        "processing_time": round(timer_end - timer_start, 3),  # Processing time in seconds
        "number_of_rows": len(df)  # Total rows (entries) processed
    }

# Function to generate a CSV file from analysis results
def generate_csv(analysis_results):
    # Create a DataFrame for IP address requests
    ip_df = pd.DataFrame(analysis_results['requests_per_ip'], columns=['IP Address', 'Request Count'])
    
    # Create a DataFrame for the most accessed endpoint
    endpoint_df = pd.DataFrame([{
        'Endpoint': analysis_results['most_accessed_endpoint']['endpoint'],
        'Access Count': analysis_results['most_accessed_endpoint']['access_count']
    }])
    
    # Create a DataFrame for suspicious activity
    suspicious_df = pd.DataFrame(analysis_results['suspicious_activity'], columns=['IP Address', 'Failed Login Count'])
    
    # Create an in-memory file stream to store the CSV data
    output = StringIO()
    
    # Write IP request data to the stream
    ip_df.to_csv(output, index=False)
    
    # Append the most accessed endpoint data
    output.write("\nMost Accessed Endpoint:\n")
    endpoint_df.to_csv(output, index=False)
    
    # Append suspicious activity data
    output.write("\nSuspicious Activity:\n")
    suspicious_df.to_csv(output, index=False)
    
    # Return the CSV data as a string
    return output.getvalue()

# Streamlit user interface setup
st.set_page_config(page_title="Log File Analyzer", layout="wide", page_icon="📊")

# Main title of the application
st.title("📊 Log File Analyzer")
st.markdown("Analyze your log files for **suspicious activities**, **access patterns**, and generate detailed **reports**.")

# File uploader to allow users to upload log files
uploaded_file = st.file_uploader("📁 Upload your log file", type=["log"], help="Upload a .log file for analysis.")

# Input for setting the threshold for suspicious activity (failed logins)
threshold = st.number_input("🚨 Suspicious Activity Threshold (Failed Logins)", min_value=1, value=10, step=1)

# Check if a file has been uploaded
if uploaded_file is not None:
    try:
        # Read and decode the uploaded log file
        log_lines = uploaded_file.read().decode('utf-8').splitlines()
        
        # Analyze the log file
        with st.spinner("🔍 Analyzing log file..."):  # Display a loading spinner during analysis
            analysis_results = process_log_file(log_lines, suspicious_threshold=threshold)
        
        st.success("✅ Analysis Completed!")  # Display a success message
        
        # Display analysis summary
        st.markdown("### 📈 Analysis Summary")
        col1, col2 = st.columns(2)  # Create two columns for metrics
        with col1:
            st.metric("Processing Time", f"{analysis_results['processing_time']} seconds")
            st.metric("Rows Processed", analysis_results['number_of_rows'])
        with col2:
            st.metric("Most Accessed Endpoint", analysis_results['most_accessed_endpoint']['endpoint'])
            st.metric("Access Count", analysis_results['most_accessed_endpoint']['access_count'])
        
        # Display detailed results in expandable sections
        st.markdown("### 📋 Detailed Results")
        with st.expander("📌 Requests per IP Address"):
            st.table(pd.DataFrame(analysis_results['requests_per_ip'], columns=["IP Address", "Request Count"]))
        with st.expander("📌 Suspicious Activity"):
            st.table(pd.DataFrame(analysis_results['suspicious_activity'], columns=["IP Address", "Failed Login Count"]))
        
        # Generate and provide a download button for the CSV report
        csv_output = generate_csv(analysis_results)
        st.download_button(
            label="📥 Download Full Report as CSV",
            data=BytesIO(csv_output.encode('utf-8')),
            file_name="log_analysis_results.csv",
            mime="text/csv"
        )
    except Exception as e:
        # Handle errors gracefully and display an error message
        st.error(f"❌ An error occurred: {e}")
