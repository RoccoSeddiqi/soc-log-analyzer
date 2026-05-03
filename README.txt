LogMentor: SOC-Style Log Analysis Tool

Overview
LogMentor is a lightweight command-line tool designed to help students and entry-level SOC analysts analyze log files, detect suspicious activity, and understand security events. The system processes logs through a pipeline consisting of ingestion, normalization, detection, reporting, and export.


Features
- Supports CSV, JSON, and JSONL log formats
- Normalizes logs into a unified schema
- Applies rule-based detection to identify suspicious activity
- Generates structured alerts with severity and supporting evidence
- Produces summary reports with aggregated statistics
- Exports results as JSON files
- Optional local dashboard visualization


System Requirements
Python 3.10 or higher
Windows 10/11 or Linux
Recommended: 8 GB RAM
Dependencies



1. How to Run
Clone Repository:
git clone https://github.com/RoccoSeddiqi/soc-log-analyzer.git

Navigate to the project directory:
cd soc-log-analyzer


2. Install Required Dependencies and Run the program:
Install required dependencies:
pip install -r requirements.txt

Then Run: 
$env:PYTHONPATH="src"
python -m src.soclog.main wizard


## Sample Data
Example log files are located in the /data folder.
You can select either: linux_datasets or windows_datasets
You can use these to test the system when running the program.
Ex. data/linux_datasets/defense_evasion/sh_binary_padding_dd_2020-11-10081941.log


3. Follow the CLI prompts:
- Enter log file path
- Select source type (Windows/Linux)
- Choose normalization settings
- Select detection profile and rule category
- Provide output folder
- Choose export options


Example Workflow
1. Provide log file path
2. Logs are loaded and validated
3. Events are normalized
4. Detection engine analyzes events
5. Alerts are generated and displayed
6. Summary report is created
7. Results are exported to JSON files
8. Optional dashboard can be launched


Output Files
Generated in the specified output directory:
- alerts.json
    - Contains all detected alerts with rule name, severity, category, and evidence

- summary_report.json
    - Contains aggregated statistics such as total alerts and counts by severity and rule

- normalized_events.json
    - Contains processed log events after normalization


Project Structure (Simplified)
soc-log-analyzer/
│
├── main.py
├── log_loader.py
├── event_normalizer.py
├── detection_engine.py
├── report_generator.py
├── export_reporter.py
├── dashboard.py (optional)
├── data/
├── output/
└── README.txt


Limitations
- Detection rules are predefined and limited in scope
- No real-time log ingestion
- Possible false positives depending on dataset
- Designed for educational use, not production environments


Future Improvements
- Additional detection rules and categories
- Configurable thresholds and rule tuning
- Real-time monitoring support
- Enhanced dashboard visualization
- Machine learning-based detection


Authors
Rocco Seddiqi
Winstar Tabaco

University of the Pacific
Spring 2026

Repository
https://github.com/RoccoSeddiqi/soc-log-analyzer