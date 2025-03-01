# Elastic Rule Planner

A comprehensive tool for extracting, analyzing, and organizing Elastic detection rules into balanced batches for Red Team testing in AWS environments.

## Overview

This project helps plan and organize Red Team testing of Elastic detection rules by:

1. Extracting relevant rules from TOML files
2. Filtering rules based on environment constraints (AWS, Linux/Windows VMs)
3. Analyzing rule complexity and dependencies
4. Organizing rules into balanced two-week testing batches
5. Generating comprehensive reports for test planning
6. Identifying rules with pre-built RTA tests and adjusting complexity scores
7. Running RTA tests for specific batches or ranges of rules

## Usage

The project provides a single script (`elastic_rule_planner.py`) that combines all functionality and offers multiple ways to use it:

### Interactive Mode (Recommended for First-Time Users)

```bash
python elastic_rule_planner.py interactive
```

This mode guides you through each step with prompts, making it easy to understand the process.

### All-in-One Command

```bash
python elastic_rule_planner.py all
```

This runs all steps in sequence:

1. Extracts rules from TOML files
2. Plans batches
3. Generates batch reports
4. Updates with RTA test information

### Run with Tests

```bash
python elastic_rule_planner.py all --run -b 1 -o windows
```

This runs all steps and then runs RTA tests for batch 1 with Windows OS filtering.

### Individual Commands

For more control, you can run individual steps:

```bash
# Extract rules from TOML files
python elastic_rule_planner.py extract

# Plan batches
python elastic_rule_planner.py plan

# Generate batch reports
python elastic_rule_planner.py report

# Update with RTA test information
python elastic_rule_planner.py rta-info

# List available batches
python elastic_rule_planner.py list

# Run tests for a specific batch
python elastic_rule_planner.py run -b 1
```

## Features

### Rule Extraction

- Recursively scans all `.toml` files in the rules directory
- Filters out rules that use "machine_learning" type
- Filters out rules that use ".alerts-security.*" index
- Filters out macOS-only rules
- Filters out rules that reference external media
- Adds OS information for easier filtering
- Identifies AWS-related rules
- Extracts MITRE ATT&CK tactics and techniques
- Categorizes rules based on their file path

### Batch Planning

- Calculates complexity scores for each rule
- Identifies dependencies between rules
- Suggests batch assignments for rules
- Identifies prerequisites needed for testing each rule
- Calculates priority scores for rules
- Enhances the CSV file with batch planning information

### Report Generation

- Creates a summary markdown report with batch statistics
- Generates detailed CSV files for each batch
- Provides insights into tactics coverage, prerequisites, and sample rules

### RTA Test Integration

- Identifies which rules have pre-built RTA tests
- Adds a `has_rta_test` column to the batch CSV files
- Adds a `rta_test_files` column listing the RTA test files for each rule
- Adds an `adjusted_complexity` column that reduces complexity by 2 points for rules with RTA tests
- Updates the batch summary with RTA test coverage statistics

### Test Execution

- Runs RTA tests for specific batches or ranges of rules
- Supports OS filtering to run only Windows, Linux, or macOS tests
- Allows running a specific range of rules from a batch
- Customizable delay between test executions

## Complexity Scoring System

The complexity scoring system uses a scale from 1 (simplest) to 5 (most complex) to estimate the difficulty of testing each detection rule.

### Base Complexity Score

Every rule starts with a base complexity score of **1**.

### Complexity Factors

The complexity score increases based on several key factors:

- **Technique Complexity**: +1 for rules with 2-3 techniques, +2 for more than 3 techniques
- **Tactical Complexity**: +1 for rules involving 2 or more tactics
- **AWS Environment Requirements**: +1 for AWS-specific rules
- **Network Complexity**: +1 for network-related rules

### RTA Test Adjustment

Rules with pre-built RTA tests have their complexity reduced by 2 points (minimum 1), as they require less effort to test.

## Output

The batch report includes:

- **Overview Table**: Summary of all batches with statistics
- **Batch Details**: Detailed information about each batch
- **Tactics Coverage**: Distribution of MITRE ATT&CK tactics in each batch
- **Prerequisites**: Infrastructure needed for each batch
- **Sample Rules**: High-priority rules in each batch
- **RTA Test Coverage**: Statistics on rules with pre-built RTA tests

## Project Structure

### Repository Setup

The project requires the Elastic detection rules repository to be cloned into a specific location:

1. Clone the Elastic detection rules repository:

   ```bash
   git clone https://github.com/elastic/detection-rules.git
   ```

2. Place the repository in the following directory structure:

   ```
   working-directory/
   ├── ElasticRule-Planner/  # This project
   └── rules/
       └── detection-rules/  # Cloned Elastic detection-rules repository
   ```

### ElasticRule-Planner Structure

The ElasticRule-Planner project is organized with a clean, modular structure:

```
ElasticRule-Planner/
├── elastic_rule_planner.py  - Main script that provides the unified interface
├── README.md                - Documentation for the project
└── modules/                 - Directory containing supporting modules
    ├── __init__.py          - Package initialization file
    ├── rule_extractor.py    - Used to extract rules from TOML files
    ├── batch_planner.py     - Used to plan batches
    ├── generate_batch_report.py - Used to generate batch reports
    └── update_batch_with_rta_info.py - Used to update batch files with RTA test information
```

This structure keeps the main script separate from the supporting modules, making the codebase more maintainable and easier to navigate.

### Elastic Detection Rules Repository Structure

The Elastic detection rules repository contains the following key directories:

```
detection-rules/
├── rules/              - Contains the detection rules in TOML format
├── rta/                - Red Team Automation test scripts
├── detection_rules/    - Python modules for rule management
└── etc/                - Configuration files
```

The ElasticRule-Planner tool primarily interacts with the `rules/` and `rta/` directories to extract rule information and run tests.

## Requirements

- Python 3.6+
- Required Python packages:
  - toml
  - csv (standard library)
  - json (standard library)
  - datetime (standard library)
  - collections (standard library)
  - math (standard library)

## Deployment on Air-Gapped Systems

This project can be deployed and run on air-gapped systems (systems without internet access) by following these steps:

### Packaging the Project

1. On a system with internet access, create a package containing:
   - All project files from the `ElasticRule-Planner` directory
   - The Elasticsearch detection rules repository (`rules/detection-rules`)
   - The Python `toml` package (can be downloaded using `pip download toml -d ./dependencies`)

2. Transfer this package to the air-gapped system using approved media transfer protocols.

### Installation on Air-Gapped System

1. Install Python 3.6+ if not already installed
2. Install the `toml` package:

   ```bash
   pip install ./dependencies/toml-*.whl
   ```

3. Extract the project files to a directory of your choice
4. Ensure the directory structure matches the expected structure:

   ```
   working-directory/
   ├── ElasticRule-Planner/
   │   ├── elastic_rule_planner.py
   │   ├── README.md
   │   └── modules/
   │       ├── __init__.py
   │       ├── rule_extractor.py
   │       ├── batch_planner.py
   │       ├── generate_batch_report.py
   │       └── update_batch_with_rta_info.py
   ├── rules/
   │   └── detection-rules/
   │       ├── rules/
   │       ├── rta/
   │       └── ...
   └── Output/
   ```

### Running on Air-Gapped System

The project does not require internet access to function. All operations are performed locally:

1. Navigate to the working directory
2. Run the tool as described in the Usage section:

   ```bash
   python ElasticRule-Planner/elastic_rule_planner.py interactive
   ```

### Notes for Air-Gapped Environments

- The project does not make any external API calls or require internet access during operation
- All data processing is done locally
- Output files are stored in the `Output` directory
- RTA tests can be run locally without internet access
