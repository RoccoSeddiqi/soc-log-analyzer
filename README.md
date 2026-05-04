# SOC Log Analyzer

## Overview
The SOC Log Analyzer is a command-line tool that processes security log files
and identifies potentially suspicious activity. The system loads log data,
normalizes events into a consistent format, applies detection rules, and
generates summary reports.

This project is being developed as a senior project and focuses on
clear architecture, reproducibility, and extensibility.


## Project Goals
- Load and parse security log files (initially Windows event logs)
- Normalize log data into a consistent internal format
- Detect suspicious activity using rule-based detection
- Generate readable summary reports of detected activity
- Support future expansion into statistical or machine-learning analysis


## Project Structure
soc-log-analyzer/

├── src/ # Application source code

├── data/ # Sample logs and datasets

├── tests/ # Automated tests

└── README.md


## Architecture Overview
The system follows a simple processing pipeline:

1. **LogLoader** loads raw log data from files
2. **EventNormalizer** validates and normalizes events
3. **DetectionEngine** applies detection rules
4. **ReportGenerator** summarizes alerts
5. **ExportReporter** writes reports to disk

Each stage is modular and can be extended independently.


## Data Sources

This project uses publicly available security datasets for testing and
validation. Initial datasets are sourced from the Security Datasets
project, which provides Windows event logs generated from controlled
attack simulations.

- https://securitydatasets.com/


## Getting Started

### Requirements
- Python 3.10 or newer
- Git

### Setup
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
python -m soclog.main wizard


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

