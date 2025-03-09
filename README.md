# Elastic Security Rule Testing Framework

A comprehensive framework for planning, organizing, and executing red team tests for Elastic detection rules in AWS environments.

## Overview

This project combines two powerful components to provide an end-to-end solution for validating Elastic detection rules:

1. **ElasticRule-Planner**: Plans and organizes detection rules into balanced testing batches
2. **RedTeam-Tests**: Generates detailed validation guides with step-by-step testing procedures

Together, these tools enable security teams to systematically validate their Elastic detection capabilities through controlled red team testing.

## Key Features

- **Rule Extraction & Analysis**: Extract relevant rules from TOML files and analyze their complexity
- **Intelligent Batch Planning**: Organize rules into balanced batches based on complexity, dependencies, and tactics
- **Comprehensive Reporting**: Generate detailed reports for test planning and execution
- **AI-Powered Test Procedures**: Create customized test procedures using Anthropic Claude API
- **Template-Based Guides**: Generate test guides using pre-defined templates (no API required)
- **RTA Test Integration**: Identify and leverage pre-built Red Team Automation tests
- **Test Execution**: Run RTA tests for specific batches with OS filtering

## Workflow

1. Use **ElasticRule-Planner** to extract rules and organize them into manageable batches
2. Generate batch reports with detailed information about each rule
3. Use **RedTeam-Tests** to create step-by-step validation guides for each batch
4. Execute tests following the generated guides in a controlled environment
5. Document results and improve detection capabilities

## Getting Started

See the individual README files for detailed instructions:
- [ElasticRule-Planner README](ElasticRule-Planner/README.md)
- [RedTeam-Tests README](RedTeam-Tests/README.md)

## Requirements

- Python 3.6+
- Elastic detection rules repository
- Required Python packages (see individual READMEs)
- Anthropic API key (optional, for AI-powered test procedures)

## Important Notes

- All tests should be performed in isolated test environments, not on production systems
- Some tests may involve activities that could trigger security alerts
- Always follow your organization's security policies and obtain proper authorization before testing
- The test procedures are designed to be non-destructive where possible
