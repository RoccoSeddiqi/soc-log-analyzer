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
TBD