import pandas as pd
import re
import openai
import streamlit as st
from datetime import datetime, timedelta
from config import get_azure_openai_config
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from constants import (
    LLM_CLASSIFICATION_PROMPT,
    LLM_DETAILED_ANALYSIS_PROMPT,
    LLM_ANOMALY_PROMPT,
)

# Azure OpenAI config (lazy loading to avoid import errors)
azure_config = None


def get_azure_config():
    """Get Azure config with lazy loading."""
    global azure_config
    if azure_config is None:
        try:
            azure_config = get_azure_openai_config()
        except ValueError as e:
            print(f"Warning: Azure OpenAI not configured: {e}")
            return None
    return azure_config


def extract_timestamp(log_line):
    """Extract timestamp from various log formats with comprehensive validation and fallback strategies."""

    if not log_line or not isinstance(log_line, str):
        return None

    # Comprehensive timestamp patterns with multiple fallback strategies
    patterns = [
        # ISO 8601 formats (most common)
        {
            "pattern": r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)",
            "name": "ISO_8601",
            "validator": lambda x: "T" in x and len(x) >= 19,
            "parser": lambda x: datetime.fromisoformat(
                x.replace("Z", "+00:00") if x.endswith("Z") else x
            ),
        },
        # Standard datetime formats with more flexibility
        {
            "pattern": r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)",
            "name": "STANDARD_DATETIME",
            "validator": lambda x: len(x) >= 19 and " " in x and x.count(".") <= 1,
            "parser": lambda x: (
                datetime.strptime(x, "%Y-%m-%d %H:%M:%S.%f")
                if "." in x
                else datetime.strptime(x, "%Y-%m-%d %H:%M:%S")
            ),
        },
        # Unix timestamps (with validation)
        {
            "pattern": r"(\b\d{10,13}\b)",
            "name": "UNIX_TIMESTAMP",
            "validator": lambda x: len(x) in [10, 13] and x.isdigit(),
            "parser": lambda x: datetime.fromtimestamp(
                int(x) / 1000 if len(x) == 13 else int(x)
            ),
        },
        # Common log formats with year detection
        {
            "pattern": r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            "name": "COMMON_LOG",
            "validator": lambda x: len(x.split()) == 3 and ":" in x,
            "parser": lambda x: _parse_common_log_format(x),
        },
        # RFC format
        {
            "pattern": r"(\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2})",
            "name": "RFC_FORMAT",
            "validator": lambda x: "/" in x and ":" in x and len(x.split("/")) == 3,
            "parser": lambda x: datetime.strptime(x, "%d/%b/%Y:%H:%M:%S"),
        },
        # Windows Event Log format
        {
            "pattern": r"(\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?::\d{2})?)",
            "name": "WINDOWS_LOG",
            "validator": lambda x: len(x.split()) == 2 and "/" in x,
            "parser": lambda x: datetime.strptime(x, "%m/%d/%Y %H:%M:%S"),
        },
        # Syslog format with proper year handling
        {
            "pattern": r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})",
            "name": "SYSLOG",
            "validator": lambda x: len(x.split()) == 4 and ":" in x,
            "parser": lambda x: datetime.strptime(x, "%b %d %H:%M:%S %Y"),
        },
        # Additional formats for better coverage
        # MM/DD/YYYY HH:MM:SS format
        {
            "pattern": r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})",
            "name": "MMDDYYYY",
            "validator": lambda x: len(x.split()) == 2 and x.count("/") == 2,
            "parser": lambda x: datetime.strptime(x, "%m/%d/%Y %H:%M:%S"),
        },
        # YYYY-MM-DD HH:MM:SS format (without microseconds)
        {
            "pattern": r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
            "name": "YYYYMMDD",
            "validator": lambda x: len(x) == 19 and x.count("-") == 2,
            "parser": lambda x: datetime.strptime(x, "%Y-%m-%d %H:%M:%S"),
        },
        # DD-MM-YYYY HH:MM:SS format
        {
            "pattern": r"(\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2})",
            "name": "DDMMYYYY",
            "validator": lambda x: len(x) == 19 and x.count("-") == 2,
            "parser": lambda x: datetime.strptime(x, "%d-%m-%Y %H:%M:%S"),
        },
        # RFC 3339 format variations
        {
            "pattern": r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)",
            "name": "RFC3339",
            "validator": lambda x: "T" in x and len(x) >= 19,
            "parser": lambda x: datetime.fromisoformat(
                x.replace("Z", "+00:00") if x.endswith("Z") else x
            ),
        },
    ]

    # Try each pattern
    for pattern_info in patterns:
        match = re.search(pattern_info["pattern"], log_line)
        if match:
            timestamp_str = match.group(1).strip()

            # Validate the extracted timestamp
            if not pattern_info["validator"](timestamp_str):
                continue

            try:
                # Use the parser function for each pattern
                result = pattern_info["parser"](timestamp_str)

                # Additional validation for reasonable date ranges
                if result:
                    current_year = datetime.now().year
                    # Accept dates from 1990 to current year + 5
                    if 1990 <= result.year <= current_year + 5:
                        return result

            except (ValueError, TypeError, OSError) as e:
                # Continue to next pattern if this one fails
                continue

    # If no pattern matches, try fallback strategies
    return _fallback_timestamp_extraction(log_line)


def _parse_common_log_format(timestamp_str):
    """Parse common log format with intelligent year detection."""
    try:
        # Extract month, day, and time
        parts = timestamp_str.split()
        if len(parts) != 3:
            return None

        month, day, time = parts

        # Parse the time component
        time_parts = time.split(":")
        if len(time_parts) != 3:
            return None

        hour, minute, second = map(int, time_parts)

        # Convert month name to number
        month_map = {
            "Jan": 1,
            "Feb": 2,
            "Mar": 3,
            "Apr": 4,
            "May": 5,
            "Jun": 6,
            "Jul": 7,
            "Aug": 8,
            "Sep": 9,
            "Oct": 10,
            "Nov": 11,
            "Dec": 12,
        }

        if month not in month_map:
            return None

        month_num = month_map[month]
        day_num = int(day)

        # Intelligent year detection
        current_year = datetime.now().year
        current_month = datetime.now().month

        # If the month is in the future relative to current month, use previous year
        # If the month is in the past relative to current month, use current year
        if month_num > current_month:
            year = current_year - 1
        else:
            year = current_year

        return datetime(year, month_num, day_num, hour, minute, second)

    except (ValueError, TypeError):
        return None


def _fallback_timestamp_extraction(log_line):
    """Fallback timestamp extraction using multiple strategies."""

    # Strategy 1: Look for any 4-digit year followed by time
    year_pattern = (
        r"(\d{4})[-\s/](\d{1,2})[-\s/](\d{1,2})[T\s](\d{1,2}):(\d{2}):(\d{2})"
    )
    match = re.search(year_pattern, log_line)
    if match:
        try:
            year, month, day, hour, minute, second = map(int, match.groups())
            if 1990 <= year <= datetime.now().year + 5:
                return datetime(year, month, day, hour, minute, second)
        except (ValueError, TypeError):
            pass

    # Strategy 2: Look for Unix timestamp anywhere in the line
    unix_pattern = r"\b(\d{10,13})\b"
    match = re.search(unix_pattern, log_line)
    if match:
        try:
            ts = int(match.group(1))
            if len(match.group(1)) == 13:
                ts = ts / 1000
            if 946684800 <= ts <= 1893456000:  # 2000-2030 range
                return datetime.fromtimestamp(ts)
        except (ValueError, TypeError):
            pass

    # Strategy 3: Look for time pattern with current year assumption
    time_pattern = r"(\d{1,2}):(\d{2}):(\d{2})"
    match = re.search(time_pattern, log_line)
    if match:
        try:
            hour, minute, second = map(int, match.groups())
            if 0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59:
                # Use current date with the found time
                now = datetime.now()
                return datetime(now.year, now.month, now.day, hour, minute, second)
        except (ValueError, TypeError):
            pass

    return None


def validate_timestamp_range(timestamp):
    """Validate if timestamp is within reasonable range."""
    if not timestamp:
        return False

    current_year = datetime.now().year
    # Accept dates from 1990 to current year + 5
    return 1990 <= timestamp.year <= current_year + 5


def group_logs_by_time(df, time_window="1H", total_range_hours=24):
    # Extract timestamps and filter out invalid entries
    df["timestamp"] = df["Log"].apply(extract_timestamp)

    # Remove rows with invalid timestamps
    df = df.dropna(subset=["timestamp"])

    if df.empty:
        st.warning(
            "No valid timestamps found in logs. Using current time for analysis."
        )
        df["timestamp"] = datetime.now()

    df = df.sort_values("timestamp").reset_index(drop=True)
    last_log_ts = df["timestamp"].max()
    if time_window.endswith("H"):
        window_hours = int(time_window.replace("H", ""))
        aligned_last = last_log_ts.replace(minute=0, second=0, microsecond=0)
        aligned_last = aligned_last - timedelta(hours=aligned_last.hour % window_hours)
    elif time_window == "1D":
        window_hours = 24
        aligned_last = last_log_ts.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_window == "1W":
        window_hours = 24 * 7
        aligned_last = last_log_ts - timedelta(days=last_log_ts.weekday())
        aligned_last = aligned_last.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        window_hours = 1
        aligned_last = last_log_ts.replace(minute=0, second=0, microsecond=0)
    expected_batches = total_range_hours // window_hours
    last_window_end = aligned_last + timedelta(hours=window_hours)
    first_window_start = last_window_end - timedelta(
        hours=expected_batches * window_hours
    )
    group_starts = [
        first_window_start + timedelta(hours=i * window_hours)
        for i in range(expected_batches)
    ]
    df["time_group"] = pd.NaT
    for start in group_starts:
        end = start + timedelta(hours=window_hours)
        mask = (df["timestamp"] >= start) & (df["timestamp"] < end)
        df.loc[mask, "time_group"] = start
    # Use two-stage analysis with threading
    logs_list = df["Log"].tolist()
    analysis_results = two_stage_analysis_with_threading(logs_list, max_workers=5)

    # Apply results to DataFrame
    for i, result in enumerate(analysis_results):
        if i < len(df):
            df.loc[i, "Anomaly"] = result["anomaly"]
            df.loc[i, "AnomalyType"] = result["anomaly_type"]
            df.loc[i, "Reason"] = result["reason"]
            df.loc[i, "Solution"] = result["solution"]
            df.loc[i, "Status"] = "Anomaly" if result["anomaly"] == 1 else "Normal"
            # Add new fields from detailed analysis
            df.loc[i, "Severity"] = result.get("severity", "N/A")
            df.loc[i, "Impact"] = result.get("impact", "N/A")
            df.loc[i, "ImmediateActions"] = result.get("immediate_actions", "N/A")
            df.loc[i, "LongTermSolutions"] = result.get("long_term_solutions", "N/A")
            df.loc[i, "FurtherInvestigation"] = result.get(
                "further_investigation", "N/A"
            )
    grouped_logs = []
    for start in group_starts:
        group_df = df[df["time_group"] == start]
        if len(group_df) <= 5:
            samples = group_df
        else:
            samples = group_df.sample(min(5, len(group_df)), random_state=42)
        grouped_logs.append(
            {
                "time_group": start,
                "total_logs": len(group_df),
                "sample_logs": samples,
                "sample_size": len(samples),
            }
        )
    return grouped_logs, df


def parse_log_file(uploaded_file):
    """Parse log file with advanced timestamp detection and validation."""
    import re

    try:
        content = uploaded_file.read().decode("utf-8")

        # Handle different line endings
        content = content.replace("\r\n", "\n").replace("\r", "\n")

        # Split into lines and filter out empty lines
        lines = [line.strip() for line in content.split("\n") if line.strip()]

        if not lines:
            st.error("No valid log entries found in the file.")
            return None

        # Advanced log entry detection with multiple strategies
        log_entries = []

        # TODO: Move this to constants or config
        # Strategy 1: Look for lines with timestamps
        timestamp_patterns = [
            # ISO 8601 formats
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?",
            # Standard datetime formats
            r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?",
            # Unix timestamps (with word boundaries)
            r"\b\d{10,13}\b",
            # Common log formats
            r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
            # RFC format
            r"\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}",
            # Windows Event Log format
            r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}(?::\d{2})?",
            # Syslog format
            r"[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}",
            # Additional formats
            r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}",
            r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}",
            r"\d{2}-\d{2}-\d{4}\s+\d{2}:\d{2}:\d{2}",
        ]

        combined_pattern = "|".join(f"({p})" for p in timestamp_patterns)

        # Strategy 1: Lines with timestamps
        timestamp_lines = []
        non_timestamp_lines = []

        for line in lines:
            if re.search(combined_pattern, line):
                timestamp_lines.append(line)
            else:
                non_timestamp_lines.append(line)

        # FIXME: Why nested function?
        # Strategy 2: Group consecutive lines that might be multi-line log entries
        def group_multiline_logs(lines):
            """Group lines that might be part of the same log entry."""
            grouped = []
            current_group = []

            for line in lines:
                # If line starts with timestamp, start new group
                if re.search(combined_pattern, line):
                    if current_group:
                        grouped.append("\n".join(current_group))
                    current_group = [line]
                else:
                    # If line doesn't start with timestamp, it might be continuation
                    if current_group:
                        current_group.append(line)
                    else:
                        # Standalone line without timestamp
                        grouped.append(line)

            # Add the last group
            if current_group:
                grouped.append("\n".join(current_group))

            return grouped

        # Process timestamp lines
        timestamp_entries = group_multiline_logs(timestamp_lines)

        # Process non-timestamp lines (might be continuation or standalone)
        non_timestamp_entries = group_multiline_logs(non_timestamp_lines)

        # Combine all entries
        all_entries = timestamp_entries + non_timestamp_entries

        # Filter out empty entries and very short entries (likely not logs)
        log_entries = [
            entry for entry in all_entries if entry and len(entry.strip()) > 5
        ]

        if not log_entries:
            st.error("No valid log entries found after parsing.")
            return None

        # Create DataFrame
        df = pd.DataFrame({"Log": log_entries})

        # Add timestamp column for validation
        df["ExtractedTimestamp"] = df["Log"].apply(extract_timestamp)

        # Show parsing statistics
        total_lines = len(lines)
        valid_entries = len(log_entries)
        timestamp_entries = df["ExtractedTimestamp"].notna().sum()

        st.success(f"📊 Parsing Results:")
        st.info(f"   • Total lines: {total_lines}")
        st.info(f"   • Valid log entries: {valid_entries}")
        st.info(f"   • Entries with timestamps: {timestamp_entries}")
        st.info(
            f"   • Timestamp success rate: {timestamp_entries/valid_entries*100:.1f}%"
        )

        # Remove the temporary timestamp column
        df = df.drop("ExtractedTimestamp", axis=1)

        return df

    except UnicodeDecodeError:
        st.error("Error: File encoding not supported. Please use UTF-8 encoded files.")
        return None
    except Exception as e:
        st.error(f"Error parsing log file: {str(e)}")
        return None


def azure_llm_anomaly_check(log):
    from constants import LLM_ANOMALY_PROMPT

    try:
        # Get Azure config with lazy loading
        config = get_azure_config()
        if config is None:
            raise ValueError("Azure OpenAI not configured")

        # Use full chain-of-thought prompt
        full_prompt = LLM_ANOMALY_PROMPT.replace("{log}", log)

        # Create OpenAI client with Azure configuration
        client = openai.AzureOpenAI(
            azure_endpoint=config["endpoint"],
            api_key=config["api_key"],
            api_version=config["api_version"],
        )

        response = client.chat.completions.create(
            model=config["deployment_name"],
            messages=[{"role": "user", "content": full_prompt}],
            temperature=0.1,
            max_tokens=512,
            top_p=0.9,
        )

        content = response.choices[0].message.content.strip()

        # Helper function to extract each field
        def extract_field(field):
            match = re.search(
                rf"{field}:[ \t]*(.+?)(?=\n[A-Z ]+?:|\Z)",
                content,
                re.DOTALL | re.IGNORECASE,
            )
            return match.group(1).strip() if match else ""

        classification = extract_field("Classification").upper()
        reason = extract_field("Reason")
        root_cause = extract_field("Root Cause")
        solution = extract_field("Solution")
        further_investigation = extract_field("Further Investigation")

        return {
            "anomaly": 1 if "ANOMALY" in classification else 0,
            "anomaly_type": "LLM_ANOMALY" if "ANOMALY" in classification else "NORMAL",
            "reason": reason or "No reason provided.",
            "solution": solution or "No solution provided.",
            "detailed_analysis": content,
            "root_cause": root_cause or "N/A",
            "further_investigation": further_investigation or "N/A",
        }

    except Exception as e:
        # Fallback detection via keywords
        keywords = [
            "error",
            "fail",
            "denied",
            "unauthorized",
            "crash",
            "panic",
            "corrupt",
        ]
        for kw in keywords:
            if kw in log.lower():
                return {
                    "anomaly": 1,
                    "anomaly_type": "SIMPLE_ANOMALY",
                    "reason": f"Keyword '{kw}' found in log (fallback).",
                    "solution": "Review the log entry for details.",
                    "detailed_analysis": f"Simple keyword match: {kw}",
                    "root_cause": "N/A",
                    "further_investigation": "N/A",
                }

        return {
            "anomaly": 0,
            "anomaly_type": "NORMAL",
            "reason": "No anomaly keywords found (fallback).",
            "solution": "No action needed.",
            "detailed_analysis": "Normal log.",
            "root_cause": "N/A",
            "further_investigation": "N/A",
        }


def analyze_logs(
    df, time_window="1H", use_time_grouping=True, standard_range="Previous 24 hours"
):
    print("Analyzing logs with time window:", time_window)
    if standard_range == "Previous 6 hours":
        total_range_hours = 6
    elif standard_range == "Previous 12 hours":
        total_range_hours = 12
    else:
        total_range_hours = 24
    if use_time_grouping and len(df) > 20:
        grouped_logs, df_with_timestamps = group_logs_by_time(
            df, time_window, total_range_hours
        )
        return grouped_logs, df_with_timestamps
    else:
        sample_df = df.copy()
        # Use two-stage analysis with threading
        logs_list = sample_df["Log"].tolist()
        analysis_results = two_stage_analysis_with_threading(logs_list, max_workers=5)

        # Apply results to DataFrame
        for i, result in enumerate(analysis_results):
            if i < len(sample_df):
                sample_df.loc[i, "Anomaly"] = result["anomaly"]
                sample_df.loc[i, "AnomalyType"] = result["anomaly_type"]
                sample_df.loc[i, "Reason"] = result["reason"]
                sample_df.loc[i, "Solution"] = result["solution"]
                sample_df.loc[i, "Status"] = (
                    "Anomaly" if result["anomaly"] == 1 else "Normal"
                )
                # Add new fields from detailed analysis
                sample_df.loc[i, "Severity"] = result.get("severity", "N/A")
                sample_df.loc[i, "Impact"] = result.get("impact", "N/A")
                sample_df.loc[i, "ImmediateActions"] = result.get(
                    "immediate_actions", "N/A"
                )
                sample_df.loc[i, "LongTermSolutions"] = result.get(
                    "long_term_solutions", "N/A"
                )
                sample_df.loc[i, "FurtherInvestigation"] = result.get(
                    "further_investigation", "N/A"
                )
        return sample_df


def split_logs_by_hour(df):
    """
    Splits the logs DataFrame into a dictionary of DataFrames, keyed by hour.
    Keeps the timestamp column in each group for reference.
    """
    df = df.copy()
    df["timestamp"] = df["Log"].apply(extract_timestamp)

    # Remove rows with invalid timestamps
    df = df.dropna(subset=["timestamp"])

    if df.empty:
        st.warning("No valid timestamps found in logs. Cannot split by hour.")
        return {}

    df["hour"] = df["timestamp"].dt.floor("h")
    groups = {hour: group.drop(columns=["hour"]) for hour, group in df.groupby("hour")}
    return groups


def validate_timestamp_patterns():
    """Test function to validate timestamp patterns with various log formats."""
    test_cases = [
        # ISO 8601 formats
        "2024-01-15T10:30:45.123Z",
        "2024-01-15T10:30:45+05:30",
        "2024-01-15T10:30:45",
        # Standard datetime formats
        "2024-01-15 10:30:45.123",
        "2024-01-15 10:30:45",
        # Unix timestamps
        "1705311045",  # 10 digits
        "1705311045123",  # 13 digits
        # Common log formats
        "Jan 15 10:30:45",
        "Dec 25 23:59:59",
        # RFC format
        "15/Jan/2024:10:30:45",
        "25/Dec/2023:23:59:59",
        # Windows Event Log format
        "01/15/2024 10:30:45",
        "12/25/2023 23:59:59",
        # Syslog format
        "Jan 15 10:30:45 2024",
        "Dec 25 23:59:59 2023",
        # Invalid cases (should return None)
        "123456789",  # Too short for Unix timestamp
        "1234567890123456",  # Too long
        "invalid-timestamp",
        "2024-13-45T25:70:80",  # Invalid datetime
    ]

    results = []
    for test_case in test_cases:
        result = extract_timestamp(test_case)
        results.append(
            {"input": test_case, "output": result, "valid": result is not None}
        )

    return results


def get_timestamp_statistics(df):
    """Analyze timestamp extraction statistics for debugging."""
    if df is None or df.empty:
        return {}

    # Extract timestamps
    timestamps = df["Log"].apply(extract_timestamp)

    # Calculate statistics
    valid_count = timestamps.notna().sum()
    total_count = len(timestamps)
    invalid_count = total_count - valid_count

    # Get unique timestamp formats
    format_counts = {}
    for ts in timestamps.dropna():
        if isinstance(ts, datetime):
            format_counts["datetime"] = format_counts.get("datetime", 0) + 1

    return {
        "total_logs": total_count,
        "valid_timestamps": valid_count,
        "invalid_timestamps": invalid_count,
        "success_rate": (valid_count / total_count * 100) if total_count > 0 else 0,
        "format_distribution": format_counts,
    }


def stage1_classification(log):
    """Stage 1: Quick classification of log as NORMAL or ANOMALY."""
    try:
        config = get_azure_config()
        if config is None:
            raise ValueError("Azure OpenAI not configured")

        prompt = LLM_CLASSIFICATION_PROMPT.replace("{log}", log)

        # Create OpenAI client with Azure configuration
        client = openai.AzureOpenAI(
            azure_endpoint=config["endpoint"],
            api_key=config["api_key"],
            api_version=config["api_version"],
        )

        response = client.chat.completions.create(
            model=config["deployment_name"],
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=100,
            top_p=0.9,
        )

        content = response.choices[0].message.content.strip()

        # Extract classification
        classification_match = re.search(
            r"Classification:\s*(ANOMALY|NORMAL)", content, re.IGNORECASE
        )
        if classification_match:
            classification = classification_match.group(1).upper()
            return {
                "is_anomaly": classification == "ANOMALY",
                "classification": classification,
                "log": log,
            }
        else:
            # Fallback: check for anomaly keywords
            anomaly_keywords = [
                "error",
                "fail",
                "denied",
                "unauthorized",
                "crash",
                "panic",
                "corrupt",
            ]
            is_anomaly = any(keyword in log.lower() for keyword in anomaly_keywords)
            return {
                "is_anomaly": is_anomaly,
                "classification": "ANOMALY" if is_anomaly else "NORMAL",
                "log": log,
            }

    except Exception as e:
        # Fallback classification
        anomaly_keywords = [
            "error",
            "fail",
            "denied",
            "unauthorized",
            "crash",
            "panic",
            "corrupt",
        ]
        is_anomaly = any(keyword in log.lower() for keyword in anomaly_keywords)
        return {
            "is_anomaly": is_anomaly,
            "classification": "ANOMALY" if is_anomaly else "NORMAL",
            "log": log,
        }


def stage2_detailed_analysis(log):
    """Stage 2: Detailed analysis of anomalous log with root cause and solution."""
    try:
        config = get_azure_config()
        if config is None:
            raise ValueError("Azure OpenAI not configured")

        prompt = LLM_DETAILED_ANALYSIS_PROMPT.replace("{log}", log)

        # Create OpenAI client with Azure configuration
        client = openai.AzureOpenAI(
            azure_endpoint=config["endpoint"],
            api_key=config["api_key"],
            api_version=config["api_version"],
        )

        response = client.chat.completions.create(
            model=config["deployment_name"],
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
            max_tokens=512,
            top_p=0.9,
        )

        content = response.choices[0].message.content.strip()

        # Extract detailed analysis fields
        def extract_field(field_name):
            pattern = rf"{field_name}:\s*(.+?)(?=\n[A-Z][a-z\s]+:|\Z)"
            match = re.search(pattern, content, re.DOTALL | re.IGNORECASE)
            return match.group(1).strip() if match else "N/A"

        return {
            "anomaly_type": extract_field("Anomaly Type"),
            "severity": extract_field("Severity"),
            "root_cause": extract_field("Root Cause"),
            "impact": extract_field("Impact"),
            "immediate_actions": extract_field("Immediate Actions"),
            "long_term_solutions": extract_field("Long-term Solutions"),
            "further_investigation": extract_field("Further Investigation"),
            "detailed_analysis": content,
            "log": log,
        }

    except Exception as e:
        # Fallback analysis
        return {
            "anomaly_type": "UNKNOWN_ANOMALY",
            "severity": "medium",
            "root_cause": "Analysis failed due to API error",
            "impact": "Unknown",
            "immediate_actions": "Review log manually",
            "long_term_solutions": "N/A",
            "further_investigation": "Manual investigation required",
            "detailed_analysis": f"Error in analysis: {str(e)}",
            "log": log,
        }


# Global analysis lock to prevent multiple simultaneous analyses
_analysis_lock = False


def two_stage_analysis_with_threading(logs_list, max_workers=5):
    """
    Perform two-stage analysis with multithreading.

    Stage 1: Classify all logs as NORMAL or ANOMALY
    Stage 2: Perform detailed analysis only on anomalous logs using multithreading
    """
    global _analysis_lock

    # Prevent multiple simultaneous analyses
    if _analysis_lock:
        st.warning("Another analysis is already in progress. Please wait...")
        return []

    _analysis_lock = True

    try:
        if not logs_list:
            return []

        # Stage 1: Classify all logs
        classification_results = []

        # Add progress indicator
        progress_text = st.empty()
        progress_bar = st.progress(0)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all classification tasks
            future_to_log = {
                executor.submit(stage1_classification, log): log for log in logs_list
            }

            # Collect results with progress updates
            completed = 0
            for future in as_completed(future_to_log):
                try:
                    result = future.result()
                    classification_results.append(result)
                    completed += 1
                    progress = completed / len(logs_list)
                    progress_bar.progress(progress)
                    progress_text.text(
                        f"📊 Stage 1 Progress: {completed}/{len(logs_list)} logs classified"
                    )
                except Exception as e:
                    st.error(f"Error in classification: {str(e)}")

        # Separate normal and anomalous logs
        normal_logs = [r for r in classification_results if not r["is_anomaly"]]
        anomalous_logs = [r for r in classification_results if r["is_anomaly"]]

        # Show classification summary
        st.info(
            f"📊 Stage 1 Summary: {len(anomalous_logs)} anomalous logs, {len(normal_logs)} normal logs"
        )

        # Stage 2: Detailed analysis of anomalous logs only
        detailed_results = []

        if anomalous_logs:
            # Reset progress for stage 2
            progress_text = st.empty()
            progress_bar = st.progress(0)

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit detailed analysis tasks for anomalous logs only
                future_to_log = {
                    executor.submit(stage2_detailed_analysis, r["log"]): r
                    for r in anomalous_logs
                }

                # Collect results with progress updates
                completed = 0
                for future in as_completed(future_to_log):
                    try:
                        result = future.result()
                        detailed_results.append(result)
                        completed += 1
                        progress = completed / len(anomalous_logs)
                        progress_bar.progress(progress)
                        progress_text.text(
                            f"📊 Stage 2 Progress: {completed}/{len(anomalous_logs)} logs analyzed"
                        )
                    except Exception as e:
                        st.error(f"Error in detailed analysis: {str(e)}")
        else:
            # Show that no anomalies were found
            st.info(
                f"📊 Stage 2: No anomalous logs found in Stage 1. All {len(normal_logs)} logs were classified as normal."
            )

        # Combine results
        final_results = []

        # Add normal logs with minimal analysis
        for normal_log in normal_logs:
            final_results.append(
                {
                    "log": normal_log["log"],
                    "anomaly": 0,
                    "anomaly_type": "NORMAL",
                    "reason": "Log classified as normal during stage 1 analysis",
                    "solution": "No action needed",
                    "detailed_analysis": "Normal log entry",
                    "root_cause": "N/A",
                    "further_investigation": "N/A",
                    "severity": "N/A",
                    "impact": "N/A",
                    "immediate_actions": "N/A",
                    "long_term_solutions": "N/A",
                }
            )

        # Add anomalous logs with detailed analysis
        for detailed_result in detailed_results:
            final_results.append(
                {
                    "log": detailed_result["log"],
                    "anomaly": 1,
                    "anomaly_type": detailed_result["anomaly_type"],
                    "reason": detailed_result["root_cause"],
                    "solution": detailed_result["immediate_actions"],
                    "detailed_analysis": detailed_result["detailed_analysis"],
                    "root_cause": detailed_result["root_cause"],
                    "further_investigation": detailed_result["further_investigation"],
                    "severity": detailed_result["severity"],
                    "impact": detailed_result["impact"],
                    "immediate_actions": detailed_result["immediate_actions"],
                    "long_term_solutions": detailed_result["long_term_solutions"],
                }
            )

        return final_results

    finally:
        # Always release the lock
        _analysis_lock = False
