#!/usr/bin/env python3
"""
Generate a batch summary report for Red Team testing.
"""

import os
import csv
import json
from collections import defaultdict
from datetime import datetime

def generate_batch_report(csv_file, output_dir):
    """
    Generate a batch summary report for Red Team testing.
    """
    print(f"Generating batch summary report from {csv_file}")
    
    # Read the CSV file
    rules_by_batch = defaultdict(list)
    with open(csv_file, 'r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            batch = row.get('suggested_batch', '')
            if batch:
                rules_by_batch[batch].append(row)
    
    # Generate a timestamp for the report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create the report directory
    report_dir = os.path.join(output_dir, f"batch_report_{timestamp}")
    os.makedirs(report_dir, exist_ok=True)
    
    # Generate the main summary report
    summary_file = os.path.join(report_dir, "batch_summary.md")
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("# Elastic Rule Batch Testing Plan\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Overview\n\n")
        f.write(f"Total rules to test: {sum(len(rules) for rules in rules_by_batch.values())}\n\n")
        
        f.write("| Batch | Total Rules | Windows Rules | Linux Rules | AWS Rules | Avg. Complexity | Avg. Priority |\n")
        f.write("|-------|-------------|---------------|-------------|-----------|----------------|---------------|\n")
        
        for batch in sorted(rules_by_batch.keys(), key=int):
            rules = rules_by_batch[batch]
            windows_count = sum(1 for r in rules if 'Windows' in r.get('os_types', ''))
            linux_count = sum(1 for r in rules if 'Linux' in r.get('os_types', ''))
            aws_count = sum(1 for r in rules if r.get('is_aws_related', '') == 'Yes')
            
            # Calculate average complexity and priority
            complexities = [int(r.get('complexity', '3')) for r in rules if r.get('complexity', '')]
            priorities = [int(r.get('priority', '3')) for r in rules if r.get('priority', '')]
            avg_complexity = sum(complexities) / len(complexities) if complexities else 0
            avg_priority = sum(priorities) / len(priorities) if priorities else 0
            
            f.write(f"| {batch} | {len(rules)} | {windows_count} | {linux_count} | {aws_count} | {avg_complexity:.1f} | {avg_priority:.1f} |\n")
        
        f.write("\n## Batch Details\n\n")
        
        for batch in sorted(rules_by_batch.keys(), key=int):
            rules = rules_by_batch[batch]
            f.write(f"### Batch {batch}\n\n")
            
            # Count rules by tactic
            tactic_counts = defaultdict(int)
            for rule in rules:
                tactics = rule.get('mitre_tactics', '').split(', ')
                for tactic in tactics:
                    if tactic:
                        tactic_counts[tactic] += 1
            
            f.write("#### Tactics Coverage\n\n")
            f.write("| Tactic | Count |\n")
            f.write("|--------|-------|\n")
            for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {tactic} | {count} |\n")
            
            f.write("\n#### Prerequisites\n\n")
            prereq_counts = defaultdict(int)
            for rule in rules:
                prereqs = rule.get('prerequisites', '').split(', ')
                for prereq in prereqs:
                    if prereq:
                        prereq_counts[prereq] += 1
            
            f.write("| Prerequisite | Count |\n")
            f.write("|--------------|-------|\n")
            for prereq, count in sorted(prereq_counts.items(), key=lambda x: x[1], reverse=True):
                f.write(f"| {prereq} | {count} |\n")
            
            f.write("\n#### Sample Rules\n\n")
            
            # Sort rules by priority (high to low)
            sorted_rules = sorted(rules, key=lambda r: int(r.get('priority', '3')) if r.get('priority', '') else 3, reverse=True)
            
            # Take top 5 rules
            for i, rule in enumerate(sorted_rules[:5]):
                name = rule.get('rule_name', '')
                description = rule.get('rule_description', '')
                if len(description) > 200:
                    description = description[:200] + "..."
                
                f.write(f"**{i+1}. {name}**\n\n")
                f.write(f"- **Priority:** {rule.get('priority', '')}\n")
                f.write(f"- **Complexity:** {rule.get('complexity', '')}\n")
                f.write(f"- **OS:** {rule.get('os_types', '')}\n")
                f.write(f"- **AWS Related:** {rule.get('is_aws_related', '')}\n")
                f.write(f"- **Prerequisites:** {rule.get('prerequisites', '')}\n")
                f.write(f"- **Description:** {description}\n\n")
            
            # Generate detailed batch file
            batch_file = os.path.join(report_dir, f"batch_{batch}_details.csv")
            with open(batch_file, 'w', newline='', encoding='utf-8') as batch_f:
                # Select relevant fields for the batch CSV
                fieldnames = [
                    'rule_name', 'rule_description', 'os_types', 'is_aws_related',
                    'complexity', 'priority', 'prerequisites', 'mitre_tactics',
                    'mitre_techniques', 'rule_rule_id', 'rule_severity', 'rule_risk_score'
                ]
                
                writer = csv.DictWriter(batch_f, fieldnames=fieldnames)
                writer.writeheader()
                
                for rule in sorted_rules:
                    # Create a new row with only the selected fields
                    row = {field: rule.get(field, '') for field in fieldnames}
                    writer.writerow(row)
    
    print(f"Batch summary report generated at {report_dir}")
    return report_dir

def main():
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(base_dir, "..", "Output")
    
    # Find the most recent batched CSV file
    csv_files = [f for f in os.listdir(output_dir) if f.startswith('elastic_rules_batched_') and f.endswith('.csv')]
    if not csv_files:
        print("No batched CSV files found in the Output directory")
        return
    
    # Sort by timestamp (newest first)
    csv_files.sort(reverse=True)
    csv_file = os.path.join(output_dir, csv_files[0])
    
    # Generate the batch report
    report_dir = generate_batch_report(csv_file, output_dir)
    
    print(f"\nBatch report generated at: {report_dir}")
    print("The report includes:")
    print("  - batch_summary.md: Overview of all batches with statistics")
    print("  - batch_X_details.csv: Detailed CSV file for each batch")

if __name__ == "__main__":
    main()
