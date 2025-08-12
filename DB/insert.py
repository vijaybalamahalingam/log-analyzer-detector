import requests
import json
from datetime import datetime
import hashlib

def create_mongodb_payload(analysis_data):
    """
    Create MongoDB payload from real analysis data
    
    Args:
        analysis_data (dict): Dictionary containing analysis results from Streamlit app
    
    Returns:
        dict: Formatted payload for MongoDB insertion
    """
    
    def convert_to_json_serializable(obj):
        """Convert pandas/numpy objects to JSON serializable types"""
        if hasattr(obj, 'item'):  # numpy scalar types
            return obj.item()
        elif hasattr(obj, 'isoformat'):  # datetime objects
            return obj.isoformat()
        elif isinstance(obj, (list, tuple)):
            return [convert_to_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: convert_to_json_serializable(value) for key, value in obj.items()}
        else:
            return obj
    
    # Extract data from analysis_data
    file_info = analysis_data.get('file_info', {})
    analysis_config = analysis_data.get('analysis_config', {})
    analysis_status = analysis_data.get('analysis_status', {})
    statistics = analysis_data.get('statistics', {})
    time_groups = analysis_data.get('time_groups', [])
    log_entries = analysis_data.get('log_entries', [])
    anomaly_distribution = analysis_data.get('anomaly_distribution', {})
    time_series_data = analysis_data.get('time_series_data', [])
    error_logs = analysis_data.get('error_logs', [])
    
    payload = {
        "server": "cluster0.rygynkb.mongodb.net",
        "database": "MAGE",
        "collection": "loganalyzer",
        "data": {
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "file_info": {
                "file_name": file_info.get('file_name'),
                "file_size": file_info.get('file_size'),
                "file_hash": file_info.get('file_hash')
            },
            "analysis_config": {
                "standard_range": analysis_config.get('standard_range'),
                "time_window": analysis_config.get('time_window'),
                "use_time_grouping": analysis_config.get('use_time_grouping'),
                "max_workers": analysis_config.get('max_workers')
            },
            "analysis_status": {
                "status": analysis_status.get('status'),
                "start_time": analysis_status.get('start_time'),
                "end_time": analysis_status.get('end_time'),
                "progress_percentage": analysis_status.get('progress_percentage'),
                "current_stage": analysis_status.get('current_stage'),
                "error_message": analysis_status.get('error_message')
            },
            "statistics": {
                "total_logs": statistics.get('total_logs'),
                "valid_timestamps": statistics.get('valid_timestamps'),
                "invalid_timestamps": statistics.get('invalid_timestamps'),
                "timestamp_success_rate": statistics.get('timestamp_success_rate'),
                "anomalies_detected": statistics.get('anomalies_detected'),
                "normal_logs": statistics.get('normal_logs'),
                "anomaly_rate": statistics.get('anomaly_rate'),
                "analysis_duration_seconds": statistics.get('analysis_duration_seconds'),
                "time_groups_analyzed": statistics.get('time_groups_analyzed')
            },
            "time_groups": time_groups,
            "log_entries": log_entries,
            "anomaly_distribution": anomaly_distribution,
            "time_series_data": time_series_data,
            "error_logs": error_logs
        }
    }
    
    # Convert all data to JSON serializable types
    payload = convert_to_json_serializable(payload)
    
    return payload

def insert_to_mongodb(analysis_data):
    """
    Insert analysis data to MongoDB via Maige API
    
    Args:
        analysis_data (dict): Analysis results from Streamlit app
    
    Returns:
        dict: API response from MongoDB insertion
    """
    
    url = "https://api.maige.htcnxt.ai/platform/databasecrud/mongodb/insert"
    
    # Create payload from analysis data
    payload = create_mongodb_payload(analysis_data)
    
    # Debug: Show what's being sent to HTC database
    print(f"🚀 Sending data to HTC MongoDB API:")
    print(f"   URL: {url}")
    print(f"   Database: {payload.get('database', 'N/A')}")
    print(f"   Collection: {payload.get('collection', 'N/A')}")
    print(f"   Data keys: {list(payload.get('data', {}).keys())}")
    
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        
        return {
            "success": True,
            "status_code": response.status_code,
            "response": response.json() if response.text else response.text,
            "message": "Data successfully inserted to MongoDB"
        }
        
    except requests.exceptions.RequestException as e:
        return {
            "success": False,
            "status_code": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None,
            "response": str(e),
            "message": "Failed to insert data to MongoDB"
        }

def prepare_analysis_data_for_mongodb(results_df, file_info, analysis_config, analysis_status, statistics, time_groups=None, hourly_groups=None):
    """
    Prepare analysis data from Streamlit app for MongoDB insertion
    
    Args:
        results_df (DataFrame): Analysis results DataFrame
        file_info (dict): File information
        analysis_config (dict): Analysis configuration
        analysis_status (dict): Analysis status
        statistics (dict): Analysis statistics
        time_groups (list): Time groups data
        hourly_groups (dict): Hourly groups data
    
    Returns:
        dict: Formatted data ready for MongoDB insertion
    """
    
    # Debug: Print data types for troubleshooting
    print(f"DEBUG: results_df type: {type(results_df)}")
    print(f"DEBUG: time_groups type: {type(time_groups)}")
    if time_groups:
        print(f"DEBUG: time_groups[0] type: {type(time_groups[0])}")
        print(f"DEBUG: time_groups[0] value: {time_groups[0]}")
    print(f"DEBUG: hourly_groups type: {type(hourly_groups)}")
    if hourly_groups:
        print(f"DEBUG: hourly_groups keys: {list(hourly_groups.keys()) if isinstance(hourly_groups, dict) else 'Not a dict'}")
    
    # Prepare log entries from results DataFrame
    log_entries = []
    if results_df is not None and not results_df.empty:
        for idx, row in results_df.iterrows():
            log_entry = {
                "log_index": idx,
                "raw_log": row.get('Log', ''),
                "extracted_timestamp": row.get('timestamp', None),
                "timestamp_format": "ISO_8601" if row.get('timestamp') else None,
                "time_group": row.get('TimeGroup', None),
                "analysis_results": {
                    "anomaly": row.get('Anomaly', 0),
                    "anomaly_type": row.get('AnomalyType', 'NORMAL'),
                    "status": row.get('Status', 'Normal'),
                    "reason": row.get('Reason', ''),
                    "solution": row.get('Solution', ''),
                    "detailed_analysis": row.get('DetailedAnalysis', ''),
                    "root_cause": row.get('RootCause', ''),
                    "further_investigation": row.get('FurtherInvestigation', ''),
                    "severity": row.get('Severity', 'N/A'),
                    "impact": row.get('Impact', 'N/A'),
                    "immediate_actions": row.get('ImmediateActions', ''),
                    "long_term_solutions": row.get('LongTermSolutions', '')
                },
                "analysis_metadata": {
                    "stage1_classification": {
                        "is_anomaly": bool(row.get('Anomaly', 0)),
                        "classification": row.get('AnomalyType', 'NORMAL'),
                        "confidence": 0.95 if row.get('Anomaly', 0) else 0.99
                    },
                    "stage2_analysis": {
                        "analysis_id": f"analysis_{idx}",
                        "processing_time": 0.0
                    }
                }
            }
            log_entries.append(log_entry)
    
    # Prepare time groups data - use hourly_groups if available, otherwise time_groups
    time_groups_data = []
    
    # Prefer hourly_groups if available as it has more complete data
    if hourly_groups and isinstance(hourly_groups, dict):
        for timestamp, group_df in hourly_groups.items():
            time_group = {
                "time_group_start": timestamp,
                "time_group_end": None,  # Calculate if needed
                "time_window": analysis_config.get('time_window', '1H'),
                "total_logs": len(group_df) if hasattr(group_df, '__len__') else 0,
                "sample_size": min(5, len(group_df)) if hasattr(group_df, '__len__') else 0,
                "anomalies_found": 0,  # Will calculate from log entries
                "normal_logs": 0,      # Will calculate from log entries
                "anomaly_rate": 0.0,   # Will calculate from log entries
                "sample_logs": []
            }
            
            # Add sample logs from the group DataFrame
            if hasattr(group_df, 'iterrows'):
                for idx, (_, sample_row) in enumerate(group_df.iterrows()):
                    if idx < 5:  # Limit to 5 sample logs
                        sample_log = {
                            "log_index": sample_row.name if hasattr(sample_row, 'name') else idx,
                            "raw_log": sample_row.get('Log', ''),
                            "extracted_timestamp": sample_row.get('timestamp'),
                            "timestamp_format": "ISO_8601" if sample_row.get('timestamp') else None
                        }
                        time_group["sample_logs"].append(sample_log)
            
            time_groups_data.append(time_group)
    
    # Fallback to time_groups if hourly_groups not available
    elif time_groups:
        for group in time_groups:
            # Handle different time_groups data structures
            if isinstance(group, dict):
                # If group is a dictionary with time_group key
                time_group_start = group.get('time_group')
                total_logs = group.get('total_logs', 0)
                sample_size = group.get('sample_size', 0)
                sample_logs = group.get('sample_logs', [])
            elif hasattr(group, 'isoformat'):
                # If group is a pandas Timestamp object
                time_group_start = group
                total_logs = 0
                sample_size = 0
                sample_logs = []
            else:
                # Fallback for other types
                time_group_start = group
                total_logs = 0
                sample_size = 0
                sample_logs = []
            
            time_group = {
                "time_group_start": time_group_start,
                "time_group_end": None,  # Calculate if needed
                "time_window": analysis_config.get('time_window', '1H'),
                "total_logs": total_logs,
                "sample_size": sample_size,
                "anomalies_found": 0,  # Calculate from log entries
                "normal_logs": 0,      # Calculate from log entries
                "anomaly_rate": 0.0,   # Calculate from log entries
                "sample_logs": []
            }
            
            # Add sample logs if available
            if sample_logs and hasattr(sample_logs, 'iterrows'):
                for _, sample_row in sample_logs.iterrows():
                    sample_log = {
                        "log_index": sample_row.name,
                        "raw_log": sample_row.get('Log', ''),
                        "extracted_timestamp": sample_row.get('timestamp'),
                        "timestamp_format": "ISO_8601" if sample_row.get('timestamp') else None
                    }
                    time_group["sample_logs"].append(sample_log)
            
            time_groups_data.append(time_group)
    
    # Calculate anomaly distribution
    anomaly_distribution = {
        "by_type": {},
        "by_severity": {}
    }
    
    if log_entries:
        # Count by anomaly type
        for entry in log_entries:
            anomaly_type = entry["analysis_results"]["anomaly_type"]
            if anomaly_type not in anomaly_distribution["by_type"]:
                anomaly_distribution["by_type"][anomaly_type] = 0
            anomaly_distribution["by_type"][anomaly_type] += 1
            
            # Count by severity
            severity = entry["analysis_results"]["severity"]
            if severity not in anomaly_distribution["by_severity"]:
                anomaly_distribution["by_severity"][severity] = 0
            anomaly_distribution["by_severity"][severity] += 1
    
    # Prepare time series data
    time_series_data = []
    if time_groups_data:
        for group in time_groups_data:
            time_series_entry = {
                "time_group": group["time_group_start"],
                "anomaly_rate": group["anomaly_rate"],
                "total_logs": group["total_logs"],
                "anomalies": group["anomalies_found"],
                "normal_logs": group["normal_logs"]
            }
            time_series_data.append(time_series_entry)
    
    # Prepare final data structure
    analysis_data = {
        "file_info": file_info,
        "analysis_config": analysis_config,
        "analysis_status": analysis_status,
        "statistics": statistics,
        "time_groups": time_groups_data,
        "log_entries": log_entries,
        "anomaly_distribution": anomaly_distribution,
        "time_series_data": time_series_data,
        "error_logs": []
    }
    
    return analysis_data


