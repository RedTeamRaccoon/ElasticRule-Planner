# Elastic Rule Validation Tools

This directory contains tools for generating red team validation guides for Elastic detection rules. These guides provide step-by-step instructions for testing Elastic detection rules in a controlled environment, allowing security teams to validate their detection capabilities.

## Available Tools

### 1. `elastic_rule_validator.py`

This script uses the Anthropic Claude API to generate detailed, customized test procedures for each Elastic detection rule. It provides the most comprehensive and accurate test procedures but requires an Anthropic API key.

#### Features:
- Uses AI to generate detailed test procedures tailored to each rule
- Analyzes rule queries to understand detection logic
- Provides comprehensive prerequisites, test steps, cleanup procedures, and warnings
- Categorizes rules based on their type for better organization
- Supports loading the API key from a `.env` file for better security

#### Requirements:
- Python 3.6+
- Anthropic API key
- `anthropic` Python package
- `python-dotenv` package

#### Installation:
```bash
pip install anthropic python-dotenv
```

#### Usage:
```bash
# Using command-line API key
python elastic_rule_validator.py --csv_file path/to/rules.csv --api_key your_anthropic_api_key --output path/to/output.md

# Using API key from .env file
python elastic_rule_validator.py --csv_file path/to/rules.csv --output path/to/output.md
```

#### Setting up the .env file:
Create a file named `.env` in the same directory as the script with the following content:
```
ANTHROPIC_API_KEY=your_anthropic_api_key
```

#### Parameters:
- `--csv_file`: Path to the CSV file containing detection rules (required)
- `--api_key`: Anthropic API key (optional if provided in .env file)
- `--output`: Output markdown file path (default: red_team_validation_guide.md)
- `--model`: Anthropic model to use (default: claude-3.7-sonnet, options: claude-3.7-sonnet, claude-3.5-sonnet)
- `--max_tokens`: Maximum tokens for response (default: 4000)
- `--temperature`: Temperature for response generation (default: 0.1)
- `--batch_size`: Number of rules to process in each batch (default: 5)
- `--env_file`: Path to .env file containing ANTHROPIC_API_KEY (default: .env)
- `--concurrent_requests`: Number of concurrent API requests (default: 3)

### 2. `generate_red_team_guide.py`

This script uses pre-defined templates to generate test procedures for Elastic detection rules. It doesn't require an API key but provides less customized test procedures.

#### Features:
- Uses templates for different types of rules
- No API key required
- Fast generation of test procedures
- Categorizes rules based on their type

#### Requirements:
- Python 3.6+

#### Usage:
```bash
python generate_red_team_guide.py --csv_file path/to/rules.csv --output path/to/output.md
```

#### Parameters:
- `--csv_file`: Path to the CSV file containing detection rules (required)
- `--output`: Output markdown file path (default: red_team_validation_guide.md)

## CSV File Format

Both scripts expect a CSV file with the following columns:
- `rule_name`: Name of the rule
- `rule_rule_id`: Unique identifier for the rule
- `rule_description`: Description of the rule
- `mitre_tactics`: MITRE ATT&CK tactics associated with the rule
- `mitre_techniques`: MITRE ATT&CK techniques associated with the rule
- `rule_query`: The query used by the rule to detect suspicious activity

## Example Usage

#### Rate Limiting

The script includes built-in rate limiting to respect Anthropic API limits:
- Claude 3.7 Sonnet: 2,000 requests/min, 80,000 input tokens/min, 32,000 output tokens/min
- Claude 3.5 Sonnet: 2,000 requests/min, 160,000 input tokens/min, 32,000 output tokens/min

The rate limiter automatically pauses processing when approaching these limits to avoid API errors. It also implements concurrent processing with multiple threads to maximize throughput while staying within API limits.

#### Troubleshooting

If you encounter errors when running the script, try the following:
- Ensure you have the latest version of the `anthropic` Python package: `pip install --upgrade anthropic`
- Check that your API key is correct and has the necessary permissions
- Reduce the number of concurrent requests with `--concurrent_requests 1` to simplify processing
- Increase the delay between batches by reducing the batch size with `--batch_size 1`

### Using `elastic_rule_validator.py` with Anthropic API:

```bash
# Using command-line API key with default model (Claude 3.7 Sonnet)
python elastic_rule_validator.py --csv_file ../Output/batch_report_20250304_082321/batch_1_details.csv --api_key sk-ant-api03-your-api-key-here --output red_team_validation_guide_detailed.md

# Using API key from .env file
python elastic_rule_validator.py --csv_file ../Output/batch_report_20250304_082321/batch_1_details.csv --output red_team_validation_guide_detailed.md

# Using Claude 3.5 Sonnet model with higher concurrency
python elastic_rule_validator.py --csv_file ../Output/batch_report_20250304_082321/batch_1_details.csv --model claude-3.5-sonnet --concurrent_requests 5 --output red_team_validation_guide_detailed.md
```

### Using `generate_red_team_guide.py` without API:

```bash
python generate_red_team_guide.py --csv_file ../Output/batch_report_20250304_082321/batch_1_details.csv --output red_team_validation_guide_template.md
```

## Output

Both scripts generate a markdown file with the following structure:
- Title and introduction
- Table of contents with categories and rules
- Sections for each category
- Test procedures for each rule, including:
  - Rule information (name, ID, description, MITRE tactics and techniques)
  - Prerequisites
  - Step-by-step test instructions with commands
  - Cleanup procedures
  - Warnings about potential risks

## Important Notes

- All tests should be performed in isolated test environments, not on production systems.
- Some tests may involve activities that could trigger security alerts or be detected as malicious by security tools.
- Always follow your organization's security policies and obtain proper authorization before conducting any security testing.
- The test procedures are designed to be non-destructive where possible, but some tests may have unintended consequences if not performed carefully.
