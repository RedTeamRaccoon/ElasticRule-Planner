#!/usr/bin/env python3
"""
Update batch CSV files with RTA test information.

This script adds a column to the batch CSV files indicating if a pre-built RTA test exists
for each rule, and if so, lowers the complexity by 2 points (minimum 1).
"""

import os
import re
import csv
import sys
from pathlib import Path

def get_rta_rule_ids():
    """Get all rule IDs from the RTA tests."""
    rule_ids = set()
    rule_id_to_file = {}
    # Fix the path to the RTA directory - need to go up one more level
    rta_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules", "detection-rules", "rta")
    
    print(f"Checking RTA directory: {rta_dir}")
    
    file_count = 0
    for root, dirs, files in os.walk(rta_dir):
        for file in files:
            if file.endswith('.py') and not file.startswith('__'):
                file_count += 1
                try:
                    with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                        # Standard pattern for simple rule_id references
                        matches = re.findall(r'rule_id[\"\']?\s*[:=]\s*[\"\']([^\"\']+)[\"\']', content)
                        
                        # Additional pattern for list structures with rule_id in JSON-like objects
                        list_matches = re.findall(r'\{[^}]*\"rule_id\":\s*\"([^\"]+)\"[^}]*\}', content)
                        matches.extend(list_matches)
                        
                        for match in matches:
                            rule_ids.add(match)
                            if match not in rule_id_to_file:
                                rule_id_to_file[match] = []
                            if file not in rule_id_to_file[match]:
                                rule_id_to_file[match].append(file)
                except Exception as e:
                    print(f"Error reading {file}: {e}")
    
    print(f"Found {len(rule_ids)} unique rule IDs in {file_count} RTA test files")
    return rule_ids, rule_id_to_file

def update_batch_files():
    """Update batch CSV files with RTA test information."""
    # Get all rule IDs from the RTA tests
    rta_rule_ids, rule_id_to_file = get_rta_rule_ids()
    
    # Find the most recent batch report directory
    # Fix the path to the Output directory - need to go up one more level
    base_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "Output")
    
    batch_dirs = [d for d in os.listdir(output_dir) if d.startswith("batch_report_")]
    if not batch_dirs:
        print("No batch report directories found in the Output directory")
        return 1
    
    # Sort by timestamp (newest first)
    batch_dirs.sort(reverse=True)
    batch_dir = os.path.join(output_dir, batch_dirs[0])
    
    print(f"Updating batch files in {batch_dir}")
    
    # Find all batch CSV files
    batch_files = [f for f in os.listdir(batch_dir) if f.startswith("batch_") and f.endswith("_details.csv")]
    if not batch_files:
        print("No batch files found in the batch report directory")
        return 1
    
    # Update each batch file
    for batch_file in batch_files:
        batch_path = os.path.join(batch_dir, batch_file)
        print(f"Updating {batch_path}")
        
        # Read the batch file
        rows = []
        with open(batch_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            original_fieldnames = reader.fieldnames
            
            # Process each row
            for row in reader:
                rule_id = row.get('rule_rule_id', '')
                has_rta_test = 'No'
                rta_test_files = ''
                
                if rule_id in rta_rule_ids:
                    has_rta_test = 'Yes'
                    rta_test_files = ', '.join(rule_id_to_file.get(rule_id, []))
                
                # Add new fields
                row['has_rta_test'] = has_rta_test
                row['rta_test_files'] = rta_test_files
                
                # Adjust complexity
                complexity = int(row.get('complexity', '3'))
                if has_rta_test == 'Yes':
                    adjusted_complexity = max(1, complexity - 2)
                else:
                    adjusted_complexity = complexity
                
                row['adjusted_complexity'] = str(adjusted_complexity)
                
                rows.append(row)
        
        # Define the order of columns according to requirements
        ordered_fields = [
            'rule_name',                # 1. rule_name
            'rule_description',         # 2. rule_description
            'rule_rule_id',             # 3. rule_id
            'os_types',                 # 4. os_types
            'mitre_tactics',            # 5. mitre_tactics
            'mitre_techniques',         # 6. mitre_techniques
            'suggested_batch',          # 7. suggested_batch
            'priority',                 # 8. batch priority
            'complexity',               # 9. complexity
            'rule_query',               # 10. rule_query
            # Additional fields in a logical order for analysts
            'prerequisites',
            'rta_test_files',
            'is_aws_related',
            'is_network_related',
            'rule_severity',
            'rule_risk_score',
            'has_rta_test',
            'adjusted_complexity',
            'related_rules',
            'rule_category'
        ]
        
        # Get all available fields from the rows
        all_fields = set()
        for row in rows:
            all_fields.update(row.keys())
        
        # Create the final fieldnames list
        # First add the ordered fields that exist in the data
        fieldnames = [field for field in ordered_fields if field in all_fields]
        
        # Then add any remaining fields that weren't in our ordered list
        remaining_fields = sorted(list(all_fields - set(fieldnames)))
        fieldnames.extend(remaining_fields)
        
        # Write the updated batch file
        with open(batch_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        
        print(f"Updated {len(rows)} rows in {batch_path}")
    
    # Update the batch summary file
    update_batch_summary(batch_dir, rta_rule_ids)
    
    return 0

def update_batch_summary(batch_dir, rta_rule_ids):
    """Update the batch summary file with RTA test information."""
    summary_path = os.path.join(batch_dir, "batch_summary.md")
    if not os.path.exists(summary_path):
        print(f"Batch summary file not found: {summary_path}")
        return
    
    print(f"Updating batch summary file: {summary_path}")
    
    # Read the batch summary file
    with open(summary_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Add a new section about RTA tests
    rta_section = """
## RTA Test Coverage

| Batch | Total Rules | Rules with RTA Tests | Coverage % | Avg. Original Complexity | Avg. Adjusted Complexity |
|-------|-------------|----------------------|------------|--------------------------|--------------------------|
"""
    
    # Calculate RTA test coverage for each batch
    batch_files = [f for f in os.listdir(batch_dir) if f.startswith("batch_") and f.endswith("_details.csv")]
    for batch_file in sorted(batch_files, key=lambda x: int(x.split('_')[1])):
        batch_number = batch_file.split('_')[1]
        batch_path = os.path.join(batch_dir, batch_file)
        
        total_rules = 0
        rules_with_rta = 0
        original_complexity_sum = 0
        adjusted_complexity_sum = 0
        
        with open(batch_path, 'r', newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_rules += 1
                rule_id = row.get('rule_rule_id', '')
                if rule_id in rta_rule_ids:
                    rules_with_rta += 1
                
                complexity = int(row.get('complexity', '3'))
                original_complexity_sum += complexity
                
                if rule_id in rta_rule_ids:
                    adjusted_complexity = max(1, complexity - 2)
                else:
                    adjusted_complexity = complexity
                
                adjusted_complexity_sum += adjusted_complexity
        
        coverage = (rules_with_rta / total_rules) * 100 if total_rules > 0 else 0
        avg_original_complexity = original_complexity_sum / total_rules if total_rules > 0 else 0
        avg_adjusted_complexity = adjusted_complexity_sum / total_rules if total_rules > 0 else 0
        
        rta_section += f"| {batch_number} | {total_rules} | {rules_with_rta} | {coverage:.1f}% | {avg_original_complexity:.1f} | {avg_adjusted_complexity:.1f} |\n"
    
    # Add the RTA section to the content
    if "## RTA Test Coverage" in content:
        # Replace the existing RTA section
        content = re.sub(r"## RTA Test Coverage.*?(?=##|\Z)", rta_section, content, flags=re.DOTALL)
    else:
        # Add the RTA section before the last section
        content = content.rstrip() + "\n" + rta_section + "\n"
    
    # Write the updated batch summary file
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Updated batch summary file: {summary_path}")

if __name__ == "__main__":
    sys.exit(update_batch_files())
