import streamlit as st
import pandas as pd
import time
import altair as alt
from utils import *
from constants import *
import sys
import os

# Add DB folder to path for importing insert functions
sys.path.append(os.path.join(os.path.dirname(__file__), 'DB'))
from insert import prepare_analysis_data_for_mongodb, insert_to_mongodb

# Check if streamlit-aggrid is available
try:
    from streamlit_aggrid import AgGrid

    aggrid_available = True
except ImportError:
    aggrid_available = False

# Azure OpenAI config and constants are handled in utils.py and constants.py


# FIXME: Use .get for dict access to avoid KeyError
# TODO: Add logs
# FIXME: Termination is not working, add a way to stop the app gracefully with ctrl+c


def main():
    st.title(APP_TITLE)
    st.markdown(APP_DESCRIPTION)
    sidebar_result = setup_sidebar()
    if sidebar_result is None:
        st.error("Failed to setup sidebar configuration.")
        return
    standard_range, time_window, use_time_grouping = sidebar_result
    if "current_tab" not in st.session_state:
        st.session_state.current_tab = TAB_UPLOAD
    tab1, tab2 = st.tabs([TAB_UPLOAD, TAB_RESULTS])
    with tab1:
        upload_and_configure_tab(standard_range, time_window, use_time_grouping)
    with tab2:
        results_tab()


def upload_and_configure_tab(standard_range, time_window, use_time_grouping):
    """Content for the upload and configuration tab."""
    st.subheader(UPLOAD_SUBHEADER)

    # File upload
    uploaded_file = st.file_uploader(
        FILE_UPLOADER_LABEL,
        type=FILE_UPLOADER_TYPES,
        help=FILE_UPLOADER_HELP,
        key="file_uploader",
    )

    # Persist uploaded file and parsed DataFrame in session_state
    if uploaded_file is not None:
        # Reset analysis state when new file is uploaded
        if (
            "uploaded_file" not in st.session_state
            or st.session_state["uploaded_file"] != uploaded_file
        ):
            st.session_state["analysis_completed"] = False
            st.session_state["analysis_in_progress"] = False
            if "results_df" in st.session_state:
                del st.session_state["results_df"]
            if "hourly_groups" in st.session_state:
                del st.session_state["hourly_groups"]
            if "analyzed_file_hash" in st.session_state:
                del st.session_state["analyzed_file_hash"]

        st.session_state["uploaded_file"] = uploaded_file
        df = parse_log_file(uploaded_file)
        if df is not None:
            st.session_state["df"] = df
    elif "uploaded_file" in st.session_state and "df" in st.session_state:
        uploaded_file = st.session_state["uploaded_file"]
        df = st.session_state["df"]
    else:
        df = None

    if uploaded_file is not None and df is not None:
        st.success(SUCCESS_FILE_UPLOADED.format(filename=uploaded_file.name))
        st.subheader(FILE_PREVIEW_SUBHEADER)
        st.dataframe(df.head(), use_container_width=True)

        # --- Standard Analysis Filtering ---
        df["timestamp"] = df["Log"].apply(extract_timestamp)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        last_log_ts = df["timestamp"].max()
        if standard_range == SIDEBAR_STANDARD_RANGE_OPTIONS[0]:
            delta = pd.Timedelta(hours=6)
        elif standard_range == SIDEBAR_STANDARD_RANGE_OPTIONS[1]:
            delta = pd.Timedelta(hours=12)
        else:
            delta = pd.Timedelta(hours=24)

        # TODO: Mention the last log timestamp in the UI
        filtered_df = df[df["timestamp"] >= (last_log_ts - delta)].reset_index(
            drop=True
        )
        st.info(
            INFO_ANALYZING_LOGS.format(
                num_logs=len(filtered_df),
                delta=delta,
                end_time=last_log_ts.strftime("%Y-%m-%d %H:%M:%S"),
            )
        )

        # Analysis and Reset buttons
        col1, col2 = st.columns([3, 1])

        with col1:
            # Add a unique key to prevent multiple button clicks
            if st.button(
                ANALYZE_BUTTON_LABEL, type=ANALYZE_BUTTON_TYPE, key="analyze_button"
            ):
                # Prevent multiple analysis runs
                if (
                    "analysis_in_progress" in st.session_state
                    and st.session_state["analysis_in_progress"]
                ):
                    st.warning("Analysis already in progress. Please wait...")
                    return

                # Prevent analysis if it was started recently (within last 60 seconds)
                if "analysis_start_time" in st.session_state:
                    time_since_start = (
                        pd.Timestamp.now() - st.session_state["analysis_start_time"]
                    )
                    if time_since_start.total_seconds() < 60:
                        st.warning(
                            "Analysis was recently started. Please wait 60 seconds before trying again..."
                        )
                        return

                # Check if analysis was already completed for this data
                if (
                    "analysis_completed" in st.session_state
                    and st.session_state["analysis_completed"]
                ):
                    st.info(
                        "Analysis already completed. View results in the 'Results' tab."
                    )
                    st.session_state["current_tab"] = TAB_RESULTS
                    return

                # Check if analysis is currently running
                if (
                    "analysis_in_progress" in st.session_state
                    and st.session_state["analysis_in_progress"]
                ):
                    st.warning("Analysis already in progress. Please wait...")
                    return

                # Check if results already exist
                if (
                    "results_df" in st.session_state
                    and st.session_state["results_df"] is not None
                ):
                    st.info(
                        "Analysis results already exist. View results in the 'Results' tab."
                    )
                    st.session_state["current_tab"] = TAB_RESULTS
                    return

                # Check if this exact file has already been analyzed
                if "analyzed_file_hash" in st.session_state:
                    current_file_hash = str(
                        hash(uploaded_file.name + str(uploaded_file.size))
                    )
                    if st.session_state["analyzed_file_hash"] == current_file_hash:
                        st.info(
                            "This file has already been analyzed. View results in the 'Results' tab."
                        )
                        st.session_state["current_tab"] = TAB_RESULTS
                        return

                # Set analysis in progress flag with timestamp and unique ID
                analysis_id = str(pd.Timestamp.now().timestamp())
                st.session_state["analysis_in_progress"] = True
                st.session_state["analysis_start_time"] = pd.Timestamp.now()
                st.session_state["current_analysis_id"] = analysis_id

                try:
                    with st.spinner("🔍 Starting Azure OpenAI GPT-4o analysis..."):
                        # Show progress for two-stage analysis
                        progress_bar = st.progress(0)
                        status_text = st.empty()

                        # Add detailed logging
                        st.info(
                            f"📊 Analyzing {len(filtered_df)} logs using Azure OpenAI GPT-4o..."
                        )

                        status_text.text(STAGE1_PROGRESS_TEXT)
                        progress_bar.progress(25)

                        # Log the start of analysis
                        st.info(
                            "🚀 Stage 1: Making API calls to Azure OpenAI for classification..."
                        )

                        # Check if this analysis is still valid (not superseded by another)
                        if st.session_state.get("current_analysis_id") != analysis_id:
                            st.warning(
                                "Analysis was superseded by a new request. Stopping."
                            )
                            return
                        if not use_time_grouping:
                            results = analyze_logs(
                                filtered_df,
                                time_window,
                                use_time_grouping,
                                standard_range,
                            )
                        else:
                            results = None
                        # Check if this analysis is still valid
                        if st.session_state.get("current_analysis_id") != analysis_id:
                            st.warning(
                                "Analysis was superseded by a new request. Stopping."
                            )
                            return

                        status_text.text(STAGE2_PROGRESS_TEXT)
                        progress_bar.progress(75)

                        # Log the completion of analysis
                        st.success("✅ API calls completed successfully!")

                        # Check if this analysis is still valid
                        if st.session_state.get("current_analysis_id") != analysis_id:
                            st.warning(
                                "Analysis was superseded by a new request. Stopping."
                            )
                            return
                    # TODO: Check if it can be out of the with block
                    # Now I moved it outside.
                    # Ensure results_df is always a DataFrame
                    if use_time_grouping:
                        # Use split_logs_by_hour to get groups, then concatenate
                        hourly_groups = split_logs_by_hour(filtered_df)
                        st.session_state["hourly_groups"] = hourly_groups
                        all_logs_df = pd.concat(
                            hourly_groups.values(), ignore_index=True
                        )
                        # Run anomaly detection on the concatenated DataFrame
                        results_df = analyze_logs(
                            all_logs_df, time_window="1H", use_time_grouping=False
                        )
                    elif isinstance(results, tuple):
                        # If time grouping is not used but analyze_logs returns tuple
                        _, results_df = results
                        if "hourly_groups" in st.session_state:
                            del st.session_state["hourly_groups"]
                    else:
                        results_df = results
                        if "hourly_groups" in st.session_state:
                            del st.session_state["hourly_groups"]

                    # Final check if this analysis is still valid
                    if st.session_state.get("current_analysis_id") != analysis_id:
                        st.warning(
                            "Analysis was superseded by a new request. Stopping."
                        )
                        return

                    progress_bar.progress(100)
                    status_text.text(ANALYSIS_COMPLETE_TEXT)

                    # Show analysis summary
                    if results_df is not None:
                        anomalies = (
                            results_df["Anomaly"].sum()
                            if "Anomaly" in results_df.columns
                            else 0
                        )
                        st.success(
                            f"🎉 Analysis complete! Found {anomalies} anomalies out of {len(results_df)} logs."
                        )

                    # Store results and switch to results tab
                    st.session_state["results_df"] = results_df
                    st.session_state["use_time_grouping"] = use_time_grouping
                    st.session_state["current_tab"] = TAB_RESULTS
                    st.session_state["analysis_completed"] = True

                    # Store file hash to prevent re-analysis of the same file
                    current_file_hash = str(
                        hash(uploaded_file.name + str(uploaded_file.size))
                    )
                    st.session_state["analyzed_file_hash"] = current_file_hash

                    # Automatically insert analysis results to MongoDB
                    try:
                        with st.spinner("📊 Inserting analysis results to MongoDB..."):
                            
                            # Prepare file info
                            file_info = {
                                "file_name": uploaded_file.name,
                                "file_size": uploaded_file.size,
                                "file_hash": current_file_hash
                            }
                            
                            # Prepare analysis config
                            analysis_config = {
                                "standard_range": standard_range,
                                "time_window": time_window,
                                "use_time_grouping": use_time_grouping,
                                "max_workers": 5
                            }
                            
                            # Prepare analysis status with safe timestamp handling
                            analysis_start_time = st.session_state.get("analysis_start_time")
                            if analysis_start_time:
                                start_time_str = analysis_start_time.isoformat() if hasattr(analysis_start_time, 'isoformat') else str(analysis_start_time)
                            else:
                                start_time_str = pd.Timestamp.now().isoformat()
                            
                            analysis_status = {
                                "status": "completed",
                                "start_time": start_time_str,
                                "end_time": pd.Timestamp.now().isoformat(),
                                "progress_percentage": 100,
                                "current_stage": "completed",
                                "error_message": ""
                            }
                            
                            # Calculate statistics
                            anomalies = results_df["Anomaly"].sum() if "Anomaly" in results_df.columns else 0
                            total_logs = len(results_df)
                            normal_logs = total_logs - anomalies
                            anomaly_rate = (anomalies / total_logs * 100) if total_logs > 0 else 0
                            
                            # Get timestamp statistics safely
                            try:
                                timestamp_stats = get_timestamp_statistics(results_df)
                            except Exception as e:
                                st.warning(f"⚠️ Could not get timestamp statistics: {str(e)}")
                                timestamp_stats = {
                                    "valid_timestamps": total_logs,
                                    "invalid_timestamps": 0,
                                    "success_rate": 100.0
                                }
                            
                            # Calculate analysis duration safely
                            if analysis_start_time:
                                try:
                                    analysis_duration = (pd.Timestamp.now() - analysis_start_time).total_seconds()
                                except:
                                    analysis_duration = 0
                            else:
                                analysis_duration = 0
                            
                            statistics = {
                                "total_logs": total_logs,
                                "valid_timestamps": timestamp_stats.get("valid_timestamps", total_logs),
                                "invalid_timestamps": timestamp_stats.get("invalid_timestamps", 0),
                                "timestamp_success_rate": timestamp_stats.get("success_rate", 100.0),
                                "anomalies_detected": anomalies,
                                "normal_logs": normal_logs,
                                "anomaly_rate": anomaly_rate,
                                "analysis_duration_seconds": analysis_duration,
                                "time_groups_analyzed": len(st.session_state.get("hourly_groups", {}))
                            }
                            
                            # Debug: Show what we're sending to MongoDB
                            st.info(f"📊 Preparing MongoDB data: {total_logs} logs, {anomalies} anomalies")
                            
                            # Prepare data for MongoDB
                            analysis_data = prepare_analysis_data_for_mongodb(
                                results_df=results_df,
                                file_info=file_info,
                                analysis_config=analysis_config,
                                analysis_status=analysis_status,
                                statistics=statistics,
                                time_groups=None,  # Don't pass time_groups as it's causing issues
                                hourly_groups=st.session_state.get("hourly_groups", {})
                            )
                            
                            # Insert to MongoDB
                            mongodb_result = insert_to_mongodb(analysis_data)
                            
                            if mongodb_result["success"]:
                                st.success(f"✅ Analysis results successfully saved to MongoDB!")
                                st.info(f"📊 MongoDB Response: {mongodb_result['message']}")
                            else:
                                st.warning(f"⚠️ MongoDB insertion failed: {mongodb_result['message']}")
                                st.error(f"Error details: {mongodb_result['response']}")
                                
                    except Exception as e:
                        st.error(f"❌ Error inserting to MongoDB: {str(e)}")
                        st.info("Analysis completed but MongoDB insertion failed. Results are still available in the app.")
                        # Debug: Show the full error traceback
                        import traceback
                        st.error(f"Full error: {traceback.format_exc()}")

                finally:
                    # Clear the in-progress flag
                    st.session_state["analysis_in_progress"] = False

        with col2:
            if st.button("🔄 Reset Analysis", type="secondary", key="reset_button"):
                st.session_state["analysis_completed"] = False
                st.session_state["analysis_in_progress"] = False
                if "results_df" in st.session_state:
                    del st.session_state["results_df"]
                if "hourly_groups" in st.session_state:
                    del st.session_state["hourly_groups"]
                if "analyzed_file_hash" in st.session_state:
                    del st.session_state["analyzed_file_hash"]
                st.success("Analysis reset. You can now run analysis again.")
    else:
        st.info(INFO_UPLOAD_TO_BEGIN)


def results_tab():
    """Content for the analysis results tab."""
    st.subheader(ANALYSIS_RESULTS_SUBHEADER)

    # Check if results exist
    if "results_df" not in st.session_state or st.session_state["results_df"] is None:
        st.info(INFO_NO_RESULTS)
        return

    results_df = st.session_state["results_df"]
    use_time_grouping = st.session_state.get("use_time_grouping", False)

    # --- Show all batches (time groups), including empty ones ---
    hourly_groups = st.session_state.get("hourly_groups")
    total_batches = None
    if hourly_groups is not None:
        total_batches = len(hourly_groups)
    elif "TimeGroup" in results_df.columns and use_time_grouping:
        # Fallback: count unique time groups in results_df
        total_batches = results_df["TimeGroup"].nunique()
    else:
        total_batches = 1

    # Summary statistics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(METRIC_TOTAL_LOGS, len(results_df))
    with col2:
        anomalies = results_df["Anomaly"].sum()
        st.metric(METRIC_ANOMALIES, anomalies)
    with col3:
        if len(results_df) > 0:
            anomaly_rate = (anomalies / len(results_df)) * 100
            st.metric(METRIC_ANOMALY_RATE, f"{anomaly_rate:.1f}%")
    with col4:
        st.metric(METRIC_TIME_GROUPS, total_batches)

    # Debug information expander
    with st.expander("🔍 Debug Information", expanded=False):
        st.write("**Analysis Details:**")
        st.write(f"- Total logs analyzed: {len(results_df)}")
        st.write(f"- Anomalies detected: {anomalies}")
        st.write(f"- Normal logs: {len(results_df) - anomalies}")
        st.write(f"- Anomaly rate: {(anomalies / len(results_df) * 100):.1f}%")

        if anomalies == 0:
            st.warning("⚠️ No anomalies detected. This could mean:")
            st.write("• All logs are genuinely normal")
            st.write("• The classification might be too conservative")
            st.write("• Logs might not contain error patterns")
            st.write("• Consider uploading logs with known issues to test the system")

    # --- Show a summary table of all time groups (batches), including empty ones ---
    if hourly_groups is not None:
        st.subheader(TIME_GROUP_SUMMARY_SUBHEADER)
        batch_summary = pd.DataFrame(
            [
                {
                    "TimeGroup Start": hour.strftime("%Y-%m-%d %H:%M"),
                    "Logs in Batch": len(df),
                }
                for hour, df in hourly_groups.items()
            ]
        )
        st.dataframe(batch_summary, use_container_width=True)

    # Anomaly type analysis
    if anomalies > 0:
        st.subheader(ANOMALY_TYPE_ANALYSIS_SUBHEADER)
        anomaly_types = results_df[results_df["Anomaly"] == 1][
            "AnomalyType"
        ].value_counts()
        if not anomaly_types.empty:
            col1, col2 = st.columns(2)
            with col1:
                st.write(ANOMALY_TYPES_DETECTED_LABEL)
                for anomaly_type, count in anomaly_types.items():
                    st.write(f"• {anomaly_type}: {count} occurrences")
            with col2:
                # Create a bar chart for anomaly types
                anomaly_type_df = anomaly_types.reset_index()
                anomaly_type_df.columns = ["AnomalyType", "Count"]
                bar_chart = (
                    alt.Chart(anomaly_type_df)
                    .mark_bar()
                    .encode(
                        x=alt.X("AnomalyType:N", title="Anomaly Type"),
                        y=alt.Y("Count:Q", title="Count"),
                        color=alt.Color("AnomalyType:N"),
                        tooltip=["AnomalyType", "Count"],
                    )
                    .properties(
                        title=ANOMALY_TYPES_DISTRIBUTION_TITLE, width=300, height=200
                    )
                )
                st.altair_chart(bar_chart, use_container_width=True)

    # Time-based analysis (if available)
    if "TimeGroup" in results_df.columns and use_time_grouping:
        st.subheader(ANOMALY_RATE_OVER_TIME_SUBHEADER)
        time_analysis = (
            results_df.groupby("TimeGroup")
            .agg({"Anomaly": ["count", "sum"], "GroupTotalLogs": "first"})
            .reset_index()
        )
        time_analysis.columns = [
            "TimeGroup",
            "SamplesAnalyzed",
            "AnomaliesFound",
            "TotalLogsInGroup",
        ]
        time_analysis["AnomalyRate"] = (
            time_analysis["AnomaliesFound"] / time_analysis["SamplesAnalyzed"]
        ) * 100

        # Altair line chart
        chart = (
            alt.Chart(time_analysis)
            .mark_line(point=True)
            .encode(
                x=alt.X("TimeGroup:T", title="Time Group"),
                y=alt.Y("AnomalyRate:Q", title="Anomaly Rate (%)"),
                tooltip=[
                    "TimeGroup",
                    "AnomalyRate",
                    "SamplesAnalyzed",
                    "TotalLogsInGroup",
                ],
            )
            .properties(title=ANOMALY_RATE_OVER_TIME_TITLE)
        )
        st.altair_chart(chart, use_container_width=True)

        st.subheader(ANOMALY_DISTRIBUTION_SUBHEADER)
        pie_data = results_df["Status"].value_counts().reset_index()
        pie_data.columns = ["Status", "Count"]
        # Altair donut chart
        pie_chart = (
            alt.Chart(pie_data)
            .mark_arc(innerRadius=50)
            .encode(
                theta=alt.Theta(field="Count", type="quantitative"),
                color=alt.Color(field="Status", type="nominal"),
                tooltip=["Status", "Count"],
            )
            .properties(title=ANOMALY_VS_NORMAL_TITLE)
        )
        st.altair_chart(pie_chart, use_container_width=True)

        # Add AgGrid advanced table for results
        st.subheader(DETAILED_RESULTS_TABLE_SUBHEADER)
        if "aggrid_available" in globals() and aggrid_available:
            AgGrid(results_df)
        else:
            # FIXME: Remove this warning, By default, AgGrid should be available
            st.warning(
                "st_aggrid is not installed. Run 'pip install streamlit-aggrid' for advanced table features."
            )

    # Filter dropdown and detailed results
    st.subheader(DETAILED_RESULTS_SUBHEADER)

    # Enhanced filtering options
    filter_option = st.selectbox(
        FILTER_RESULTS_LABEL, FILTER_RESULTS_OPTIONS, key="filter_option_selectbox"
    )

    # Additional anomaly type filtering
    if filter_option == FILTER_RESULTS_OPTIONS[1] and anomalies > 0:
        anomaly_types = results_df[results_df["Anomaly"] == 1]["AnomalyType"].unique()
        if len(anomaly_types) > 1:
            selected_anomaly_types = st.multiselect(
                FILTER_BY_ANOMALY_TYPE_LABEL,
                options=anomaly_types,
                default=anomaly_types,
                help=FILTER_BY_ANOMALY_TYPE_HELP,
                key="anomaly_type_filter",
            )
        else:
            selected_anomaly_types = anomaly_types

    if filter_option == FILTER_RESULTS_OPTIONS[1]:
        filtered_df = results_df[results_df["Anomaly"] == 1]
        if "selected_anomaly_types" in locals() and selected_anomaly_types:
            filtered_df = filtered_df[
                filtered_df["AnomalyType"].isin(selected_anomaly_types)
            ]
    elif filter_option == FILTER_RESULTS_OPTIONS[2]:
        filtered_df = results_df[results_df["Anomaly"] == 0]
    else:
        filtered_df = results_df
    if not filtered_df.empty:
        for idx, row in filtered_df.iterrows():
            if "Timestamp" in row and pd.notnull(row["Timestamp"]):
                title = f"Log {idx+1} ({row['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')}): {row['Log'][:80]}..."
            else:
                title = f"Log {idx+1}: {row['Log'][:100]}..."
            with st.expander(title):
                st.text(f"Full Log: {row['Log']}")
                if "Timestamp" in row and pd.notnull(row["Timestamp"]):
                    st.write(
                        f"**Timestamp:** {row['Timestamp'].strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                if "TimeGroup" in row and pd.notnull(row["TimeGroup"]):
                    st.write(
                        f"**Time Group:** {row['TimeGroup'].strftime('%Y-%m-%d %H:%M')}"
                    )
                if "GroupTotalLogs" in row:
                    st.write(
                        f"**Group Info:** {row['GroupSampleSize']} samples from {row['GroupTotalLogs']} total logs"
                    )
                st.write(f"**Status:** {row['Status']}")
                if row["Anomaly"] == 1:
                    st.write(f"**Anomaly Type:** {row.get('AnomalyType', 'Unknown')}")
                    st.write(f"**Severity:** {row.get('Severity', 'N/A')}")
                    st.write(f"**Impact:** {row.get('Impact', 'N/A')}")
                    st.write(f"**Root Cause:** {row.get('Reason', 'N/A')}")
                    st.write(
                        f"**Immediate Actions:** {row.get('ImmediateActions', 'N/A')}"
                    )
                    st.write(
                        f"**Long-term Solutions:** {row.get('LongTermSolutions', 'N/A')}"
                    )
                    st.write(
                        f"**Further Investigation:** {row.get('FurtherInvestigation', 'N/A')}"
                    )
                    st.error("🚨 This log has been flagged as anomalous")
                else:
                    st.write(f"**Reason:** {row.get('Reason', 'N/A')}")
                    st.write(f"**Solution:** {row.get('Solution', 'N/A')}")
                    st.success("✅ This log appears normal")
        # Download filtered results
        csv = filtered_df.to_csv(index=False)
        st.download_button(
            label=DOWNLOAD_BUTTON_LABEL,
            data=csv,
            file_name=DOWNLOAD_FILE_NAME,
            mime="text/csv",
        )
    else:
        st.info(INFO_NO_MATCHING_LOGS)


def setup_sidebar():
    """Setup the sidebar configuration."""
    st.sidebar.header(SIDEBAR_HEADER)

    # Remove AI Model Selection UI and logic
    # Only keep time range, time grouping, and file upload

    # Standard Analysis: Time range selection
    st.sidebar.subheader(SIDEBAR_STANDARD_RANGE_SUBHEADER)
    standard_range = st.sidebar.selectbox(
        SIDEBAR_STANDARD_RANGE_LABEL,
        SIDEBAR_STANDARD_RANGE_OPTIONS,
        help=SIDEBAR_STANDARD_RANGE_HELP,
        key="standard_range_selectbox",
    )

    # Set allowed time window options based on selected range
    if standard_range == SIDEBAR_STANDARD_RANGE_OPTIONS[0]:
        time_window_options = SIDEBAR_TIME_WINDOW_OPTIONS_6H
    elif standard_range == SIDEBAR_STANDARD_RANGE_OPTIONS[1]:
        time_window_options = SIDEBAR_TIME_WINDOW_OPTIONS_12H
    else:
        time_window_options = SIDEBAR_TIME_WINDOW_OPTIONS_24H

    # Optional: Time Window Grouping within the selected range
    use_time_grouping = st.sidebar.checkbox(
        SIDEBAR_TIME_GROUPING_LABEL,
        value=False,
        help=SIDEBAR_TIME_GROUPING_HELP,
        key="time_grouping_checkbox",
    )
    time_window = "1H"
    if use_time_grouping:
        st.sidebar.subheader(SIDEBAR_TIME_GROUPING_SUBHEADER)
        time_window = st.sidebar.selectbox(
            SIDEBAR_TIME_WINDOW_LABEL,
            time_window_options,
            help=SIDEBAR_TIME_WINDOW_HELP,
            key="time_window_selectbox",
        )
        st.sidebar.info(SIDEBAR_TIME_GROUPING_INFO.format(time_window=time_window))

    return standard_range, time_window, use_time_grouping


if __name__ == "__main__":
    main()
