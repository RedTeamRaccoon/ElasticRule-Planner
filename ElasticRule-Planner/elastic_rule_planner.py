#!/usr/bin/env python3
"""
Elastic Rule Planner

A single script that combines all the functionality of the Elastic Rule Planner project.
This script serves as a wrapper for the files in the "rules/detection-rules" directory,
allowing Red Team operators to plan and execute tests for Elastic detection rules.
"""

import os
import sys
import csv
import re
import json
import toml
import time
import argparse
import subprocess
import importlib.util
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(os.path.dirname(BASE_DIR), "rules", "detection-rules", "rules")
OUTPUT_DIR = os.path.join(os.path.dirname(BASE_DIR), "Output")
RTA_DIR = os.path.join(os.path.dirname(BASE_DIR), "rules", "detection-rules", "rta")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Import functionality from other scripts
def import_module_from_file(module_name, file_path):
    """Import a module from a file path."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

# Import functionality from modules
rule_extractor = import_module_from_file("rule_extractor", os.path.join(BASE_DIR, "modules", "rule_extractor.py"))
batch_planner = import_module_from_file("batch_planner", os.path.join(BASE_DIR, "modules", "batch_planner.py"))
generate_batch_report = import_module_from_file("generate_batch_report", os.path.join(BASE_DIR, "modules", "generate_batch_report.py"))
update_batch_with_rta_info = import_module_from_file("update_batch_with_rta_info", os.path.join(BASE_DIR, "modules", "update_batch_with_rta_info.py"))

def extract_rules(os_filter=None, aws_filter=None):
    """
    Extract rules from TOML files.
    
    Args:
        os_filter (str, optional): Filter rules by OS type ('windows', 'linux', 'macos', or None for all)
        aws_filter (str, optional): Filter AWS-related rules ('include' to only include AWS rules, 
                                   'exclude' to exclude AWS rules, or None for no filtering)
    """
    print("\n=== Extracting Rules ===\n")
    
    # Generate a timestamp for the output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"elastic_rules_{timestamp}.csv")
    
    # Process the TOML files and create the CSV
    rule_extractor.process_toml_files(RULES_DIR, output_file, os_filter, aws_filter)
    
    return output_file

def plan_batches(input_file):
    """Plan batches for testing."""
    print("\n=== Planning Batches ===\n")
    
    # Generate a timestamp for the output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(OUTPUT_DIR, f"elastic_rules_batched_{timestamp}.csv")
    
    # Enhance the CSV file with batch planning information
    batch_planner.enhance_csv_for_batch_planning(input_file, output_file)
    
    return output_file

def generate_report(input_file):
    """Generate batch report."""
    print("\n=== Generating Batch Report ===\n")
    
    # Generate the batch report
    report_dir = generate_batch_report.generate_batch_report(input_file, OUTPUT_DIR)
    
    return report_dir

def update_with_rta_info():
    """Update batch files with RTA test information."""
    print("\n=== Updating with RTA Test Information ===\n")
    
    # Update batch files with RTA test information
    update_batch_with_rta_info.update_batch_files()

def run_rta_tests(batch_number, os_filter=None, start_index=None, end_index=None, delay=1):
    """Run RTA tests for a specific batch."""
    print(f"\n=== Running RTA Tests for Batch {batch_number} ===\n")
    
    # Find the most recent batch report directory
    batch_dirs = [d for d in os.listdir(OUTPUT_DIR) if d.startswith("batch_report_")]
    if not batch_dirs:
        print("No batch report directories found in the Output directory")
        return 1
    
    # Sort by timestamp (newest first)
    batch_dirs.sort(reverse=True)
    batch_dir = os.path.join(OUTPUT_DIR, batch_dirs[0])
    
    # Find the batch CSV file
    batch_file = os.path.join(batch_dir, f"batch_{batch_number}_details.csv")
    if not os.path.exists(batch_file):
        print(f"Batch file not found: {batch_file}")
        return 1
    
    # Read the batch file to get rule IDs
    rule_ids = []
    with open(batch_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rule_id = row.get('rule_rule_id', '')
            if rule_id:
                rule_ids.append(rule_id)
    
    print(f"Found {len(rule_ids)} rule IDs in batch file")
    
    # Apply range filtering if specified
    if start_index is not None or end_index is not None:
        start = start_index if start_index is not None else 0
        end = end_index if end_index is not None else len(rule_ids)
        
        # Validate indices
        start = max(0, start)
        end = min(len(rule_ids), end)
        
        if start >= end:
            print(f"Invalid range: start={start}, end={end}")
            return 1
        
        print(f"Applying range filter: {start} to {end} (out of {len(rule_ids)} rules)")
        rule_ids = rule_ids[start:end]
    
    # Get all available RTA tests
    rta_rule_ids, rule_id_to_file = get_rta_rule_ids()
    
    # Find matching tests
    tests_to_run = []
    for rule_id in rule_ids:
        if rule_id in rta_rule_ids:
            for test_file in rule_id_to_file.get(rule_id, []):
                test_name = os.path.splitext(test_file)[0]
                if test_name not in tests_to_run:
                    tests_to_run.append(test_name)
    
    print(f"Found {len(tests_to_run)} matching RTA tests")
    
    # Run the tests
    errors = []
    for test_name in sorted(tests_to_run):
        print(f"---- {test_name} ----")
        
        # Check if the test is compatible with the current OS
        if os_filter and os_filter != "all":
            # Import the test module to check its metadata
            try:
                sys.path.insert(0, os.path.dirname(RTA_DIR))
                module = importlib.import_module(f"rta.{test_name}")
                if os_filter not in module.metadata.platforms:
                    print(f"Skipping {test_name} (not compatible with {os_filter})")
                    continue
            except Exception as e:
                print(f"Error checking test compatibility: {e}")
                continue
            finally:
                sys.path.pop(0)
        
        # Run the test
        cmd = [sys.executable, "-m", "rta", "-n", test_name]
        p = subprocess.Popen(cmd, cwd=os.path.dirname(RTA_DIR))
        p.wait()
        code = p.returncode

        if p.returncode:
            errors.append((test_name, code))

        time.sleep(delay)
        print("")
    
    return len(errors)

def get_rta_rule_ids():
    """Get all rule IDs from the RTA tests."""
    rule_ids = set()
    rule_id_to_file = {}
    
    for root, dirs, files in os.walk(RTA_DIR):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        content = f.read()
                        matches = re.findall(r'rule_id\": \"([^\"]+)\"', content)
                        for match in matches:
                            rule_ids.add(match)
                            if match not in rule_id_to_file:
                                rule_id_to_file[match] = []
                            rule_id_to_file[match].append(file)
                except Exception as e:
                    print(f"Error reading {file}: {e}")
    
    return rule_ids, rule_id_to_file

def list_batches(show_rule_counts=False):
    """List all available batches."""
    # Find the most recent batch report directory
    batch_dirs = [d for d in os.listdir(OUTPUT_DIR) if d.startswith("batch_report_")]
    if not batch_dirs:
        print("No batch report directories found in the Output directory")
        return 1
    
    # Sort by timestamp (newest first)
    batch_dirs.sort(reverse=True)
    batch_dir = os.path.join(OUTPUT_DIR, batch_dirs[0])
    
    print(f"Listing batches in {batch_dir}")
    
    # Find all batch CSV files
    batch_files = [f for f in os.listdir(batch_dir) if f.startswith("batch_") and f.endswith("_details.csv")]
    if not batch_files:
        print("No batch files found in the batch report directory")
        return 1
    
    # Extract batch numbers
    batch_numbers = []
    for f in batch_files:
        try:
            batch_number = int(f.split("_")[1])
            batch_numbers.append(batch_number)
        except:
            continue
    
    # Sort batch numbers
    batch_numbers.sort()
    
    # Print batch numbers
    print("Available batches:")
    for batch_number in batch_numbers:
        batch_file = os.path.join(batch_dir, f"batch_{batch_number}_details.csv")
        
        # Count rules if requested
        rule_count = 0
        if show_rule_counts:
            try:
                with open(batch_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    rule_count = sum(1 for _ in reader)
            except:
                pass
            
            print(f"  Batch {batch_number}: {batch_file} ({rule_count} rules)")
        else:
            print(f"  Batch {batch_number}: {batch_file}")
    
    return 0

def interactive_mode(os_filter=None, aws_filter=None):
    """
    Run in interactive mode, prompting the user for input.
    
    Args:
        os_filter (str, optional): Filter rules by OS type ('windows', 'linux', 'macos', or None for all)
        aws_filter (str, optional): Filter AWS-related rules ('include' to only include AWS rules, 
                                   'exclude' to exclude AWS rules, or None for no filtering)
    """
    print("=== Elastic Rule Planner Interactive Mode ===\n")
    
    # Step 1: Extract rules
    print("Step 1: Extract rules from TOML files")
    if os_filter is None:
        os_filter = input("Enter OS filter (windows/linux/macos/all, default=all): ").lower()
        if not os_filter or os_filter not in ["windows", "linux", "macos", "all"]:
            os_filter = None
        elif os_filter == "all":
            os_filter = None
    else:
        print(f"Using OS filter: {os_filter}")
    
    if aws_filter is None:
        aws_filter = input("Enter AWS filter (include/exclude/none, default=none): ").lower()
        if not aws_filter or aws_filter not in ["include", "exclude"]:
            aws_filter = None
    else:
        print(f"Using AWS filter: {aws_filter}")
    
    input("Press Enter to continue...")
    rules_file = extract_rules(os_filter, aws_filter)
    
    # Step 2: Plan batches
    print("\nStep 2: Plan batches for testing")
    input("Press Enter to continue...")
    batched_file = plan_batches(rules_file)
    
    # Step 3: Generate batch report
    print("\nStep 3: Generate batch report")
    input("Press Enter to continue...")
    report_dir = generate_report(batched_file)
    
    # Step 4: Update with RTA test information
    print("\nStep 4: Update with RTA test information")
    input("Press Enter to continue...")
    update_with_rta_info()
    
    # Step 5: Run RTA tests (optional)
    print("\nStep 5: Run RTA tests (optional)")
    run_tests = input("Do you want to run RTA tests? (y/n): ").lower() == 'y'
    
    if run_tests:
        # List available batches
        list_batches(show_rule_counts=True)
        
        # Get batch number
        batch_number = int(input("\nEnter batch number to run: "))
        
        # Get OS filter
        os_filter = input("Enter OS filter (windows/linux/macos/all, default=all): ").lower()
        if not os_filter:
            os_filter = "all"
        
        # Get range
        use_range = input("Do you want to run a specific range of rules? (y/n): ").lower() == 'y'
        start_index = None
        end_index = None
        
        if use_range:
            range_input = input("Enter range (start-end, e.g., 0-10): ")
            try:
                start, end = map(int, range_input.split('-'))
                start_index = start
                end_index = end
            except:
                print("Invalid range format. Using all rules.")
        
        # Get delay
        delay = input("Enter delay between tests (seconds, default=1): ")
        if not delay:
            delay = 1
        else:
            delay = int(delay)
        
        # Run tests
        run_rta_tests(batch_number, os_filter, start_index, end_index, delay)
    
    print("\nElastic Rule Planner completed successfully!")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Elastic Rule Planner")
    
    # Add subparsers for different commands
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Extract rules command
    extract_parser = subparsers.add_parser("extract", help="Extract rules from TOML files")
    extract_parser.add_argument("-o", "--os-filter", choices=["windows", "linux", "macos", "all"], default=None, help="Filter rules by OS")
    extract_parser.add_argument("-a", "--aws-filter", choices=["include", "exclude"], default=None, help="Filter AWS rules ('include' to only include AWS rules, 'exclude' to exclude AWS rules)")
    
    # Plan batches command
    plan_parser = subparsers.add_parser("plan", help="Plan batches for testing")
    plan_parser.add_argument("-i", "--input", help="Input CSV file (default: most recent extracted rules)")
    
    # Generate report command
    report_parser = subparsers.add_parser("report", help="Generate batch report")
    report_parser.add_argument("-i", "--input", help="Input CSV file (default: most recent batched rules)")
    
    # Update with RTA info command
    rta_info_parser = subparsers.add_parser("rta-info", help="Update batch files with RTA test information")
    
    # Run RTA tests command
    run_parser = subparsers.add_parser("run", help="Run RTA tests for a specific batch")
    run_parser.add_argument("-b", "--batch", type=int, help="Batch number to run tests for")
    run_parser.add_argument("-o", "--os-filter", choices=["windows", "linux", "macos", "all"], default="all", help="Filter tests by OS")
    run_parser.add_argument("--start", type=int, help="Start index for range of rules to test (0-based)")
    run_parser.add_argument("--end", type=int, help="End index for range of rules to test (exclusive)")
    run_parser.add_argument("--range", help="Range of rules to test in format 'start-end' (e.g., '0-10')")
    run_parser.add_argument("--delay", type=int, default=1, help="Delay between test executions (default: 1)")
    
    # List batches command
    list_parser = subparsers.add_parser("list", help="List all available batches")
    list_parser.add_argument("-c", "--count", action="store_true", help="Show rule counts when listing batches")
    
    # All-in-one command
    all_parser = subparsers.add_parser("all", help="Run all steps in sequence")
    all_parser.add_argument("--run", action="store_true", help="Also run RTA tests after generating reports")
    all_parser.add_argument("-b", "--batch", type=int, help="Batch number to run tests for (if --run is specified)")
    all_parser.add_argument("-o", "--os-filter", choices=["windows", "linux", "macos", "all"], default="all", help="Filter tests by OS (if --run is specified)")
    all_parser.add_argument("-a", "--aws-filter", choices=["include", "exclude"], default=None, help="Filter AWS rules ('include' to only include AWS rules, 'exclude' to exclude AWS rules)")
    
    # Interactive mode command
    interactive_parser = subparsers.add_parser("interactive", help="Run in interactive mode, prompting for input")
    interactive_parser.add_argument("-o", "--os-filter", choices=["windows", "linux", "macos", "all"], default=None, help="Filter rules by OS")
    interactive_parser.add_argument("-a", "--aws-filter", choices=["include", "exclude"], default=None, help="Filter AWS rules ('include' to only include AWS rules, 'exclude' to exclude AWS rules)")
    
    # Parse arguments
    args = parser.parse_args()
    
    # If no command is specified, show help
    if not args.command:
        parser.print_help()
        return 0
    
    # Execute the appropriate command
    if args.command == "extract":
        extract_rules(args.os_filter, args.aws_filter)
    
    elif args.command == "plan":
        # Find the most recent extracted rules file if not specified
        if not args.input:
            csv_files = [f for f in os.listdir(OUTPUT_DIR) if f.startswith('elastic_rules_') and f.endswith('.csv') and not f.startswith('elastic_rules_batched_')]
            if not csv_files:
                print("No extracted rules files found in the Output directory")
                return 1
            
            # Sort by timestamp (newest first)
            csv_files.sort(reverse=True)
            args.input = os.path.join(OUTPUT_DIR, csv_files[0])
        
        plan_batches(args.input)
    
    elif args.command == "report":
        # Find the most recent batched rules file if not specified
        if not args.input:
            csv_files = [f for f in os.listdir(OUTPUT_DIR) if f.startswith('elastic_rules_batched_') and f.endswith('.csv')]
            if not csv_files:
                print("No batched rules files found in the Output directory")
                return 1
            
            # Sort by timestamp (newest first)
            csv_files.sort(reverse=True)
            args.input = os.path.join(OUTPUT_DIR, csv_files[0])
        
        generate_report(args.input)
    
    elif args.command == "rta-info":
        update_with_rta_info()
    
    elif args.command == "run":
        if not args.batch:
            print("Batch number is required")
            return 1
        
        # Handle range argument
        start_index = args.start
        end_index = args.end
        
        if args.range:
            try:
                start, end = map(int, args.range.split('-'))
                start_index = start
                end_index = end
            except:
                print(f"Invalid range format: {args.range}. Use format 'start-end' (e.g., '0-10')")
                return 1
        
        run_rta_tests(args.batch, args.os_filter, start_index, end_index, args.delay)
    
    elif args.command == "list":
        list_batches(show_rule_counts=args.count)
    
    elif args.command == "all":
        # Run all steps in sequence
        rules_file = extract_rules(args.os_filter, args.aws_filter)
        batched_file = plan_batches(rules_file)
        report_dir = generate_report(batched_file)
        update_with_rta_info()
        
        # Run tests if requested
        if args.run:
            if not args.batch:
                print("Batch number is required for running tests")
                return 1
            
            run_rta_tests(args.batch, args.os_filter)
    
    elif args.command == "interactive":
        interactive_mode(args.os_filter, args.aws_filter)
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
