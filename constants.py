# constants.py

# Prompt for Stage 1: Log Classification (Normal vs Anomaly)
LLM_CLASSIFICATION_PROMPT = """
You are an expert system log analyst. Your task is to quickly classify a log entry as either NORMAL or ANOMALY using a simple, fast assessment.

**CLASSIFICATION RULES:**
Classify as ANOMALY if the log contains:
- Error messages, exceptions, or failures
- Authentication/authorization failures
- System crashes, panics, or fatal errors
- Security violations or suspicious activity
- Resource exhaustion (out of memory, disk full, etc.)
- Network issues or connection failures
- Data corruption or integrity issues
- Unusual or unexpected behavior
- Performance degradation indicators
- Warnings that might indicate problems
- Failed operations or timeouts
- Unusual patterns or frequencies
- Security-related events
- System resource issues

Classify as NORMAL if the log contains:
- Successful operations and routine messages
- Informational messages about normal operations
- Scheduled maintenance activities
- Regular startup/shutdown messages
- Expected user activities
- Health check messages
- Confirmed successful operations

**IMPORTANT:** If you are unsure or if the log contains any warning, error, or suspicious content, classify as ANOMALY for further investigation.

**RESPONSE FORMAT:**
Classification: <ANOMALY or NORMAL>

**LOG TO CLASSIFY:**
"{log}"
"""

# Prompt for Stage 2: Detailed Anomaly Analysis
LLM_DETAILED_ANALYSIS_PROMPT = """
You are an expert system log analyst with 10+ years of experience in cybersecurity, system monitoring, and incident response. Your task is to provide a detailed analysis of an anomalous log entry, including root cause analysis and actionable solutions.

**ANALYSIS FRAMEWORK:**

Step 1: **Anomaly Type Identification**
- Identify the specific type of anomaly (authentication failure, system error, security breach, etc.)
- Categorize the severity level (low, medium, high, critical)

Step 2: **Root Cause Analysis**
- Analyze the technical details in the log
- Identify the underlying cause of the anomaly
- Consider system context and potential attack patterns

Step 3: **Impact Assessment**
- Assess the potential impact on system security, performance, or data integrity
- Consider cascading effects and dependencies

Step 4: **Solution Development**
- Provide specific, actionable remediation steps
- Include immediate actions and long-term preventive measures
- Consider security implications and best practices

**RESPONSE FORMAT:**
Anomaly Type: <specific type of anomaly>
Severity: <low/medium/high/critical>
Root Cause: <detailed technical explanation>
Impact: <potential consequences and risks>
Immediate Actions: <urgent steps to take>
Long-term Solutions: <preventive measures>
Further Investigation: <additional analysis needed>

**ANOMALOUS LOG TO ANALYZE:**
"{log}"
"""

# Original comprehensive prompt (kept for backward compatibility)
LLM_ANOMALY_PROMPT = """
You are an expert system log analyst with 10+ years of experience in cybersecurity, system monitoring, and incident response. Your task is to analyze a log entry using a strict, step-by-step chain-of-thought process to determine if it indicates an anomaly or is part of normal operations. Be thorough, precise, and always prioritize security and accuracy in your assessment.

**ANALYSIS FRAMEWORK (Expanded):**

Step 1: **Log Contextualization & Classification**
- Carefully review the entire log entry, including timestamps, source, event type, and message content.
- Identify the log type (system, application, network, security, performance, database, etc.) and the system component or service involved.
- Consider the operational context: Is this log from a critical system, a user endpoint, a network device, or a background service?
- Use the following comprehensive checklist:
    - **Threat Indicators:**
        - Authentication failures (failed login, invalid credentials, brute force, repeated attempts)
        - Authorization violations (access denied, permission errors, unauthorized access, privilege escalation)
        - System errors (crashes, exceptions, segmentation faults, kernel panics, fatal errors)
        - Network issues (connection refused, timeout, DNS failures, port scanning, unusual traffic patterns)
        - Resource problems (out of memory, disk full, CPU overload, service unavailable, resource exhaustion)
        - Security events (malware detection, suspicious activity, policy violations, audit failures)
        - Data corruption (checksum errors, data integrity issues, corrupted files, unexpected data loss)
        - Performance degradation (slow response, high latency, timeouts, resource bottlenecks)
        - Configuration errors (invalid settings, misconfiguration, failed updates)
        - Unusual or unexpected behavior (rare events, unknown processes, new devices, time anomalies)
    - **Normal Operations:**
        - Regular startup/shutdown messages
        - Scheduled maintenance activities
        - Normal user login/logout (successful, expected times)
        - Routine system checks and health monitoring
        - Expected error messages from known, documented issues
        - Informational messages about normal operations
        - Automated backup completions, log rotations, or other routine jobs
- Decide if the log should be classified as 'ANOMALY' or 'NORMAL'.
    - Only classify as 'NORMAL' if you are confident there is no threat, error, or suspicious activity.
    - If there is any ambiguity, uncertainty, or incomplete information, err on the side of caution and classify as 'ANOMALY'.
    - Consider edge cases: e.g., repeated normal events at odd hours, or normal events from unexpected sources, may indicate an anomaly.

Step 2: **Detailed Reasoning and Solution Proposal**
- If classified as 'ANOMALY':
    - Provide a detailed, technical reason for why this log is anomalous.
    - Cite the specific part(s) of the log that triggered the classification (e.g., error codes, IP addresses, usernames, timestamps, event types).
    - Suggest a likely root cause, referencing known attack patterns, misconfigurations, or system failures.
    - Propose a specific, actionable mitigation or remediation step (e.g., block IP, reset credentials, patch system, investigate user activity).
    - Use bullet points for reasoning if multiple factors are present.
    - If the anomaly is ambiguous, recommend further investigation steps.
- If classified as 'NORMAL':
    - Briefly explain why this log is considered normal and safe, referencing the relevant part(s) of the log.
    - Mention if the event matches a known safe pattern, scheduled task, or expected user behavior.
    - If the log is normal but unusual, note why it is still considered safe.

**RESPONSE FORMAT (Expanded):**
Classification: <ANOMALY or NORMAL>
Reason: <detailed reason for classification, cite log parts, use bullet points if needed>
Root Cause: <likely root cause if anomaly, else 'N/A'>
Solution: <actionable mitigation/remediation step, or 'No action needed.' if normal>
Further Investigation: <if applicable, suggest next steps for ambiguous or complex cases, else 'N/A'>

**EXAMPLES:**

Example 1 (Anomaly):
Classification: ANOMALY
Reason:
- Log shows repeated failed login attempts for user 'admin' from IP 192.168.1.100 within a short time frame.
- Error message: "Invalid credentials" appears 10 times in 2 minutes.
Root Cause: Possible brute force attack targeting the admin account.
Solution: Temporarily block the source IP, enforce account lockout policy, and review access logs for further suspicious activity.
Further Investigation: Check if similar attempts are occurring for other accounts or from other IPs.

Example 2 (Normal):
Classification: NORMAL
Reason:
- Log entry indicates successful scheduled backup at 02:00 AM, matching the documented maintenance window.
- No errors or warnings present.
Root Cause: N/A
Solution: No action needed.
Further Investigation: N/A

**LOG TO ANALYZE:**
"{log}"

**IMPORTANT NOTES (Expanded):**
- Be strict, security-focused, and methodical in your analysis.
- Avoid generic answers; be as specific and technical as possible, referencing log details.
- Always fill all fields in the response format, even if the answer is 'N/A'.
- Do not hallucinate solutions; only suggest practical, relevant actions based on the log content.
- Keep your reasoning concise, expert-level, and actionable.
- If you are unsure, err on the side of caution and classify as 'ANOMALY'.
- If the log is incomplete or ambiguous, recommend further investigation and note what information is missing.
- Consider the broader context: frequency, timing, source, and historical patterns may all be relevant.
""" 

# UI Titles and Labels
APP_TITLE = "🔍 Log Anomaly Detector"
APP_DESCRIPTION = "Upload your log files and detect anomalies using Azure OpenAI GPT-4o analysis"
TAB_UPLOAD = "📁 Upload & Configure"
TAB_RESULTS = "📊 Analysis Results"
UPLOAD_SUBHEADER = "📁 Upload & Configuration"
ANALYSIS_RESULTS_SUBHEADER = "📊 Analysis Results"
FILE_UPLOADER_LABEL = "Choose a log file"
FILE_UPLOADER_TYPES = ['txt', 'log', 'csv']
FILE_UPLOADER_HELP = "Upload any text-based log file (txt, log, csv)"
FILE_PREVIEW_SUBHEADER = "📊 File Preview"
ANALYZE_BUTTON_LABEL = "🔍 Analyze for Anomalies"
ANALYZE_BUTTON_TYPE = "primary"
ANALYZING_SPINNER_TEXT = "Analyzing logs using Azure OpenAI GPT-4o with two-stage analysis..."
STAGE1_PROGRESS_TEXT = "Stage 1: Classifying logs as Normal or Anomaly..."
STAGE2_PROGRESS_TEXT = "Stage 2: Performing detailed analysis on anomalous logs..."
ANALYSIS_COMPLETE_TEXT = "✅ Analysis complete!"
SUCCESS_FILE_UPLOADED = "File uploaded: {filename}"
INFO_ANALYZING_LOGS = "⏳ Analyzing {num_logs} logs from the last {delta} (ending at {end_time})"
INFO_UPLOAD_TO_BEGIN = "Please upload a log file to begin analysis."
INFO_NO_RESULTS = "No analysis results available. Please upload a file and run analysis in the 'Upload & Configure' tab."
INFO_NO_MATCHING_LOGS = "No logs match the selected filter."

# Sidebar
SIDEBAR_HEADER = "Configuration"
SIDEBAR_STANDARD_RANGE_SUBHEADER = "⏳ Standard Analysis Range"
SIDEBAR_STANDARD_RANGE_LABEL = "Analyze logs from:"
SIDEBAR_STANDARD_RANGE_OPTIONS = ["Previous 6 hours", "Previous 12 hours", "Previous 24 hours"]
SIDEBAR_STANDARD_RANGE_HELP = "Analyze only logs from the selected time range, counting backward from the last log in the file."
SIDEBAR_TIME_WINDOW_OPTIONS_6H = ["1H", "3H"]
SIDEBAR_TIME_WINDOW_OPTIONS_12H = ["1H", "3H", "6H"]
SIDEBAR_TIME_WINDOW_OPTIONS_24H = ["1H", "3H", "6H", "12H"]
SIDEBAR_TIME_GROUPING_LABEL = "Enable Time Window Grouping"
SIDEBAR_TIME_GROUPING_HELP = "Group filtered logs by time windows for faster analysis of large files"
SIDEBAR_TIME_GROUPING_SUBHEADER = "⏰ Time Grouping (for filtered logs)"
SIDEBAR_TIME_WINDOW_LABEL = "Time window size:"
SIDEBAR_TIME_WINDOW_HELP = "Group logs into time windows. Smaller windows = more detailed analysis"
SIDEBAR_TIME_GROUPING_INFO = "📊 Will analyze up to 5 logs per {time_window} window"
SIDEBAR_FILE_UPLOAD_HEADER = "📁 Upload Log File"

# Results Tab
METRIC_TOTAL_LOGS = "Total Logs Analyzed"
METRIC_ANOMALIES = "Anomalies Detected"
METRIC_ANOMALY_RATE = "Anomaly Rate"
METRIC_TIME_GROUPS = "Time Groups (Batches)"
METRIC_TIME_GROUPS_ANALYZED = "Time Groups Analyzed"
TIME_GROUP_SUMMARY_SUBHEADER = "🗂️ Time Group (Batch) Summary"
ANOMALY_TYPE_ANALYSIS_SUBHEADER = "🔍 Anomaly Type Analysis"
ANOMALY_TYPES_DETECTED_LABEL = "**Anomaly Types Detected:**"
ANOMALY_TYPES_DISTRIBUTION_TITLE = "Anomaly Types Distribution"
ANOMALY_RATE_OVER_TIME_SUBHEADER = "📈 Anomaly Rate Over Time (Interactive)"
ANOMALY_RATE_OVER_TIME_TITLE = "Anomaly Rate Over Time"
ANOMALY_DISTRIBUTION_SUBHEADER = "🧩 Anomaly Distribution"
ANOMALY_VS_NORMAL_TITLE = "Anomaly vs Normal Logs"
DETAILED_RESULTS_TABLE_SUBHEADER = "🔍 Detailed Results Table (Interactive)"
DETAILED_RESULTS_SUBHEADER = "📋 Detailed Results"
FILTER_RESULTS_LABEL = "Filter results:"
FILTER_RESULTS_OPTIONS = ["All Logs", "Anomalies Only", "Normal Logs Only"]
FILTER_BY_ANOMALY_TYPE_LABEL = "Filter by anomaly type:"
FILTER_BY_ANOMALY_TYPE_HELP = "Select specific anomaly types to view"
DOWNLOAD_BUTTON_LABEL = "📥 Download Filtered Results as CSV"
DOWNLOAD_FILE_NAME = "log_analysis_results.csv"

# Expander/Instructions
INSTRUCTIONS_EXPANDER_LABEL = "ℹ️ How to use this app"
INSTRUCTIONS_MARKDOWN = """
### Instructions:
1. **Upload a log file** - Supports .txt, .log, and .csv files
2. **Configure analysis** - Choose time grouping settings in the sidebar
3. **Click Analyze** - The AI will examine representative logs from each time window
4. **Review results** - View detailed analysis and download results

### ⚡ Time-Based Grouping (Performance Optimization):
- **For large files**: Automatically groups logs by time windows (1H, 6H, 12H, 1D, 1W)
- **Smart sampling**: Analyzes up to 5 representative logs per time window
- **Faster processing**: Reduces analysis time from hours to minutes for large files
- **Time patterns**: Shows anomaly rates over time to identify trends

### 🔍 Two-Stage Analysis with Multithreading:
The system uses an optimized two-stage analysis process:
1. **Stage 1 - Classification**: Quickly classifies all logs as Normal or Anomaly using lightweight LLM calls
2. **Stage 2 - Detailed Analysis**: Performs comprehensive analysis only on anomalous logs using multithreading for efficiency

**Benefits:**
- **Faster Processing**: Only anomalous logs get detailed analysis
- **Cost Efficient**: Reduces API calls by ~90% for typical log files
- **Parallel Processing**: Uses multithreading for concurrent analysis of anomalous logs
- **Better Performance**: Scales efficiently with large log files

### Anomaly Types Detected:
- **AUTH_FAILURE**: Authentication failures, login attempts, brute force attacks
- **AUTH_VIOLATION**: Authorization violations, access denied, privilege escalation
- **SYSTEM_ERROR**: System crashes, segmentation faults, kernel panics, fatal errors
- **MALWARE**: Malware detection, suspicious processes, ransomware indicators
- **DATA_CORRUPTION**: Data integrity failures, corruption, loss
- **NETWORK_ATTACK**: Port scanning, DDoS, suspicious connections, network intrusions
- **RESOURCE_EXHAUSTION**: Out of memory, disk full, CPU overload, resource limits
- **UNAUTHORIZED_ACCESS**: Unauthorized access attempts, policy violations
- **SECURITY_BREACH**: Security policy violations, audit failures, compliance issues
- **PERFORMANCE_ISSUE**: Performance degradation, timeouts, slow responses
- **CONFIGURATION_ERROR**: Misconfiguration, invalid settings, setup issues

### What the AI analyzes:
- Error messages and exceptions
- Failed operations and timeouts
- Authentication/authorization failures
- System crashes and corruption
- Unusual patterns or unexpected behavior

### Supported log formats:
- Application logs (with timestamps)
- System logs
- Network logs
- Database logs
- Any text-based log format

### Supported timestamp formats:
- ISO: 2024-01-15T10:30:45.123Z
- Standard: 2024-01-15 10:30:45
- Unix: 1705311045
- Common: Jan 15 10:30:45
- RFC: 15/Jan/2024:10:30:45
""" 