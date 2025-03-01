#!/usr/bin/env python3
"""
Batch Planner for Elastic Detection Rules

This script takes the CSV file of filtered Elastic detection rules and enhances it
with additional information to assist with planning and executing Red Team tests
in two-week blocks.
"""

import os
import csv
import json
import math
from datetime import datetime
from collections import defaultdict

def calculate_complexity(rule_data):
    """
    Calculate a complexity score for testing the rule.
    Returns a value from 1 (simple) to 5 (complex).
    """
    complexity = 1  # Start with the simplest complexity
    
    # Increase complexity based on various factors
    
    # More complex if it involves multiple techniques
    techniques = rule_data.get('mitre_techniques', '')
    if techniques:
        technique_count = techniques.count(',') + 1
        if technique_count > 3:
            complexity += 2
        elif technique_count > 1:
            complexity += 1
    
    # More complex if it involves multiple tactics
    tactics = rule_data.get('mitre_tactics', '')
    if tactics and tactics.count(',') > 0:
        complexity += 1
    
    # More complex if it's AWS-related (might require specific AWS setup)
    if rule_data.get('is_aws_related', '') == 'Yes':
        complexity += 1
    
    # More complex if it's network-related
    if rule_data.get('is_network_related', '') == 'Yes':
        complexity += 1
    
    # Cap at 5
    return min(complexity, 5)

def identify_dependencies(rules):
    """
    Identify rules that are related or dependent on each other.
    Returns a dictionary mapping rule IDs to lists of related rule IDs.
    """
    dependencies = defaultdict(list)
    
    # Group rules by tactic
    tactic_groups = defaultdict(list)
    for rule in rules:
        tactics = rule.get('mitre_tactics', '').split(', ')
        for tactic in tactics:
            if tactic:
                tactic_groups[tactic].append(rule)
    
    # Group rules by technique
    technique_groups = defaultdict(list)
    for rule in rules:
        # Extract just the technique IDs (e.g., "T1078" from "T1078 - Valid Accounts")
        techniques_full = rule.get('mitre_techniques', '').split(', ')
        techniques = [t.split(' - ')[0].strip() for t in techniques_full if t]
        for technique in techniques:
            if technique:
                technique_groups[technique].append(rule)
    
    # Rules with the same technique are considered related
    for rule in rules:
        rule_id = rule.get('rule_rule_id', '')
        if not rule_id:
            continue
        
        # Find related rules by technique
        techniques_full = rule.get('mitre_techniques', '').split(', ')
        techniques = [t.split(' - ')[0].strip() for t in techniques_full if t]
        for technique in techniques:
            if technique:
                for related_rule in technique_groups[technique]:
                    related_id = related_rule.get('rule_rule_id', '')
                    if related_id and related_id != rule_id and related_id not in dependencies[rule_id]:
                        dependencies[rule_id].append(related_id)
    
    return dependencies

def suggest_batch_grouping(rules, num_batches=6):  # Default to 6 batches for 12 weeks (2 weeks per batch)
    """
    Suggest which batch each rule should be in.
    Returns a dictionary mapping rule IDs to batch numbers.
    """
    # First, calculate complexity for each rule
    for rule in rules:
        rule['complexity'] = calculate_complexity(rule)
    
    # Identify dependencies
    dependencies = identify_dependencies(rules)
    
    # Group rules by OS
    windows_rules = [r for r in rules if 'Windows' in r.get('os_types', '')]
    linux_rules = [r for r in rules if 'Linux' in r.get('os_types', '')]
    other_rules = [r for r in rules if 'Windows' not in r.get('os_types', '') and 'Linux' not in r.get('os_types', '')]
    
    # Sort rules by complexity (descending)
    windows_rules.sort(key=lambda r: r['complexity'], reverse=True)
    linux_rules.sort(key=lambda r: r['complexity'], reverse=True)
    other_rules.sort(key=lambda r: r['complexity'], reverse=True)
    
    # Calculate target rules per batch
    total_rules = len(rules)
    target_per_batch = math.ceil(total_rules / num_batches)
    
    # Calculate target rules per OS per batch
    windows_per_batch = math.ceil(len(windows_rules) / num_batches)
    linux_per_batch = math.ceil(len(linux_rules) / num_batches)
    other_per_batch = math.ceil(len(other_rules) / num_batches)
    
    # Assign rules to batches
    batch_assignments = {}
    batch_counts = defaultdict(int)
    
    # Helper function to assign a rule to a batch
    def assign_to_batch(rule, preferred_batch=None):
        rule_id = rule.get('rule_rule_id', '')
        if not rule_id:
            return
        
        # If a preferred batch is specified and it's not full, use it
        if preferred_batch is not None and batch_counts[preferred_batch] < target_per_batch:
            batch_assignments[rule_id] = preferred_batch
            batch_counts[preferred_batch] += 1
            return
        
        # Find the batch with the fewest rules
        min_batch = min(range(1, num_batches + 1), key=lambda b: batch_counts[b])
        batch_assignments[rule_id] = min_batch
        batch_counts[min_batch] += 1
    
    # First, assign AWS-related rules (distribute evenly)
    aws_rules = [r for r in rules if r.get('is_aws_related', '') == 'Yes']
    aws_per_batch = math.ceil(len(aws_rules) / num_batches)
    
    for i, rule in enumerate(aws_rules):
        batch = (i // aws_per_batch) + 1
        assign_to_batch(rule, batch)
    
    # Then assign Windows rules
    for i, rule in enumerate(windows_rules):
        rule_id = rule.get('rule_rule_id', '')
        if rule_id in batch_assignments:
            continue  # Skip if already assigned
        
        # Check if any related rules are already assigned
        related_batch = None
        for dep_id in dependencies.get(rule_id, []):
            if dep_id in batch_assignments:
                related_batch = batch_assignments[dep_id]
                break
        
        if related_batch:
            assign_to_batch(rule, related_batch)
        else:
            batch = (i // windows_per_batch) + 1
            assign_to_batch(rule, batch)
    
    # Then assign Linux rules
    for i, rule in enumerate(linux_rules):
        rule_id = rule.get('rule_rule_id', '')
        if rule_id in batch_assignments:
            continue  # Skip if already assigned
        
        # Check if any related rules are already assigned
        related_batch = None
        for dep_id in dependencies.get(rule_id, []):
            if dep_id in batch_assignments:
                related_batch = batch_assignments[dep_id]
                break
        
        if related_batch:
            assign_to_batch(rule, related_batch)
        else:
            batch = (i // linux_per_batch) + 1
            assign_to_batch(rule, batch)
    
    # Finally, assign other rules
    for i, rule in enumerate(other_rules):
        rule_id = rule.get('rule_rule_id', '')
        if rule_id in batch_assignments:
            continue  # Skip if already assigned
        
        batch = (i // other_per_batch) + 1
        assign_to_batch(rule, batch)
    
    return batch_assignments

def identify_prerequisites(rule_data):
    """
    Identify prerequisites needed to test the rule.
    Returns a string describing the prerequisites.
    """
    prerequisites = []
    
    # Check if AWS-related
    if rule_data.get('is_aws_related', '') == 'Yes':
        prerequisites.append("AWS environment")
        
        # Check for specific AWS services
        description = rule_data.get('rule_description', '').lower()
        query = rule_data.get('rule_query', '').lower()
        
        aws_services = {
            'ec2': 'EC2 instance',
            's3': 'S3 bucket',
            'lambda': 'Lambda function',
            'cloudtrail': 'CloudTrail enabled',
            'guardduty': 'GuardDuty enabled',
            'iam': 'IAM access',
            'kms': 'KMS keys',
            'rds': 'RDS database',
            'dynamodb': 'DynamoDB table',
            'sqs': 'SQS queue',
            'sns': 'SNS topic',
            'cloudwatch': 'CloudWatch',
            'elasticache': 'ElastiCache',
            'elb': 'Load Balancer',
            'vpc': 'VPC configuration'
        }
        
        for service, prereq in aws_services.items():
            if service in description or service in query:
                prerequisites.append(prereq)
    
    # Check OS requirements
    os_types = rule_data.get('os_types', '')
    if 'Windows' in os_types:
        prerequisites.append("Windows VM")
    if 'Linux' in os_types:
        prerequisites.append("Linux VM")
    
    # Check for network requirements
    if rule_data.get('is_network_related', '') == 'Yes':
        prerequisites.append("Network access between VMs")
    
    # Check for specific software or configurations
    description = rule_data.get('rule_description', '').lower()
    query = rule_data.get('rule_query', '').lower()
    
    software_configs = {
        'powershell': 'PowerShell access',
        'wmi': 'WMI access',
        'registry': 'Registry access',
        'active directory': 'Active Directory setup',
        'domain controller': 'Domain Controller',
        'sql': 'SQL Server/Database',
        'web server': 'Web Server',
        'iis': 'IIS Server',
        'apache': 'Apache Server',
        'nginx': 'Nginx Server',
        'ssh': 'SSH access',
        'sudo': 'Sudo privileges',
        'cron': 'Cron job access',
        'docker': 'Docker environment',
        'kubernetes': 'Kubernetes cluster',
        'container': 'Container environment'
    }
    
    for keyword, prereq in software_configs.items():
        if keyword in description or keyword in query:
            prerequisites.append(prereq)
    
    return ", ".join(prerequisites) if prerequisites else "Basic VM environment"

def calculate_priority(rule_data):
    """
    Calculate a priority score for the rule.
    Returns a value from 1 (low priority) to 5 (high priority).
    """
    priority = 3  # Start with medium priority
    
    # Adjust based on severity
    severity = rule_data.get('rule_severity', '').lower()
    if severity == 'critical':
        priority += 2
    elif severity == 'high':
        priority += 1
    elif severity == 'low':
        priority -= 1
    
    # Adjust based on risk score
    risk_score = rule_data.get('rule_risk_score', '')
    if risk_score:
        try:
            risk_score = int(risk_score)
            if risk_score >= 75:
                priority += 1
            elif risk_score <= 25:
                priority -= 1
        except:
            pass
    
    # AWS-related rules might be higher priority in an AWS environment
    if rule_data.get('is_aws_related', '') == 'Yes':
        priority += 1
    
    # Cap at 1-5 range
    return max(1, min(priority, 5))

def enhance_csv_for_batch_planning(input_file, output_file, num_batches=6):
    """
    Enhance the CSV file with additional information for batch planning.
    """
    # Read the input CSV file
    rules = []
    with open(input_file, 'r', newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            rules.append(row)
    
    print(f"Read {len(rules)} rules from {input_file}")
    
    # Calculate complexity for each rule
    for rule in rules:
        rule['complexity'] = calculate_complexity(rule)
    
    # Identify dependencies
    dependencies = identify_dependencies(rules)
    
    # Suggest batch grouping
    batch_assignments = suggest_batch_grouping(rules, num_batches)
    
    # Add additional information to each rule
    for rule in rules:
        rule_id = rule.get('rule_rule_id', '')
        
        # Add batch assignment
        rule['suggested_batch'] = str(batch_assignments.get(rule_id, ''))
        
        # Add prerequisites
        rule['prerequisites'] = identify_prerequisites(rule)
        
        # Add priority
        rule['priority'] = str(calculate_priority(rule))
        
        # Add related rules
        related_rules = dependencies.get(rule_id, [])
        rule['related_rules'] = json.dumps(related_rules)
    
    # Write the enhanced CSV file
    fieldnames = list(rules[0].keys())
    
    # Move the new fields to the beginning for better visibility
    for field in ['suggested_batch', 'complexity', 'priority', 'prerequisites', 'related_rules']:
        if field in fieldnames:
            fieldnames.remove(field)
            fieldnames.insert(0, field)
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rules)
    
    print(f"Enhanced CSV file created at {output_file}")
    
    # Generate batch summary
    batch_summary = defaultdict(lambda: defaultdict(int))
    for rule in rules:
        batch = rule.get('suggested_batch', '')
        if not batch:
            continue
        
        # Count by OS
        os_types = rule.get('os_types', '')
        if 'Windows' in os_types:
            batch_summary[batch]['Windows'] += 1
        if 'Linux' in os_types:
            batch_summary[batch]['Linux'] += 1
        
        # Count by AWS
        if rule.get('is_aws_related', '') == 'Yes':
            batch_summary[batch]['AWS'] += 1
        
        # Count by complexity
        complexity = rule.get('complexity', '')
        if complexity:
            batch_summary[batch][f'Complexity {complexity}'] += 1
        
        # Count by priority
        priority = rule.get('priority', '')
        if priority:
            batch_summary[batch][f'Priority {priority}'] += 1
        
        # Total count
        batch_summary[batch]['Total'] += 1
    
    # Print batch summary
    print("\nBatch Summary:")
    for batch in sorted(batch_summary.keys(), key=int):
        print(f"\nBatch {batch}:")
        print(f"  Total Rules: {batch_summary[batch]['Total']}")
        print(f"  Windows Rules: {batch_summary[batch]['Windows']}")
        print(f"  Linux Rules: {batch_summary[batch]['Linux']}")
        print(f"  AWS-related Rules: {batch_summary[batch]['AWS']}")
        
        # Print complexity distribution
        print("  Complexity Distribution:")
        for i in range(1, 6):
            print(f"    Complexity {i}: {batch_summary[batch][f'Complexity {i}']}")
        
        # Print priority distribution
        print("  Priority Distribution:")
        for i in range(1, 6):
            print(f"    Priority {i}: {batch_summary[batch][f'Priority {i}']}")
    
    return batch_summary

def main():
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "..", "Output")
    
    # Find the most recent CSV file
    csv_files = [f for f in os.listdir(output_dir) if f.startswith('elastic_rules_') and f.endswith('.csv')]
    if not csv_files:
        print("No CSV files found in the Output directory")
        return
    
    # Sort by timestamp (newest first)
    csv_files.sort(reverse=True)
    input_file = os.path.join(output_dir, csv_files[0])
    
    # Generate a timestamp for the output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"elastic_rules_batched_{timestamp}.csv")
    
    # Number of batches (default to 6 for 12 weeks, 2 weeks per batch)
    num_batches = 6
    
    # Enhance the CSV file
    enhance_csv_for_batch_planning(input_file, output_file, num_batches)
    
    print(f"\nEnhanced CSV file created at {output_file}")
    print(f"This file includes additional columns for batch planning:")
    print("  - suggested_batch: Recommended batch number (1-6) for two-week testing blocks")
    print("  - complexity: Estimated complexity of testing (1-5 scale)")
    print("  - priority: Suggested priority for testing (1-5 scale)")
    print("  - prerequisites: Infrastructure and setup needed for testing")
    print("  - related_rules: Other rules that should be tested together")

if __name__ == "__main__":
    main()
