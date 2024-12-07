# Log File Analyzer

**Log File Analyzer** is a Streamlit web application designed to process log files, analyze access patterns, detect suspicious activities (e.g., failed login attempts), and generate detailed CSV reports.

---

## Features

- Parse standard log file formats for key information like IP address, endpoint, HTTP method, status code, and more.
- Analyze logs for:
  - **Requests per IP Address**
  - **Most Accessed Endpoint**
  - **Suspicious Activity** (e.g., failed login attempts exceeding a user-defined threshold)
- Display results interactively in a user-friendly interface.
- Export analysis results as a downloadable CSV file.
- Fast and efficient processing of large log files.

---

## Installation

1. Clone this repository or download the source files.

   
bash
   git clone https://github.com/your-username/log-file-analyzer.git
   cd log-file-analyzer

   Clone the repository:

bash
   Install the required dependencies:

bash
    pip install -r requirements.txt
    Run the application:

bash
    streamlit run app.py
    Open the app in your browser at: http://localhost:8501

## How to Use

1. Upload Your Log File: Drag and drop your .log file into the application.
2. Set Suspicious Threshold: Define the number of failed login attempts to flag suspicious IPs.
   
## Analyze Results:
Processing Time: Time taken to analyze the log file.
Most Accessed Endpoint: View the endpoint with the highest traffic.
Suspicious IPs: Detect and list IPs with suspicious activities.
Download Results: Export analysis as a CSV file.


## Use Cases
Server Security Monitoring: Detect unauthorized access attempts or brute-force attacks.

Traffic Analysis: Identify high-traffic endpoints and optimize performance.

Log Debugging: Investigate errors, failed requests, or anomalies in logs.

Compliance Reporting: Generate reports for internal documentation or compliance needs.

## Technologies Used
Streamlit: Interactive web application framework.
Pandas: Data manipulation and analysis.
Python: Core backend logic for parsing and analyzing logs.


## Contributions are welcome! To contribute:

Fork the repository.
Create a new branch for your feature or bug fix.
Submit a pull request.



