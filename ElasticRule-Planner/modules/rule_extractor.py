#!/usr/bin/env python3
"""
Rule Extractor for Elastic Detection Rules

This script extracts rules from .toml files in the rules/detection-rules directory,
filters out rules that use "machine_learning" type or ".alerts-security.*" index,
and creates a CSV file with all fields from the source .toml files.

The CSV file is saved to the Output directory.
"""

import os
import csv
import toml
import json
from pathlib import Path
from datetime import datetime

def flatten_dict(d, parent_key='', sep='_'):
    """
    Flatten a nested dictionary into a single level dictionary.
    This helps in creating CSV columns for nested fields.
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            # Convert lists to JSON strings to preserve the data
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, v))
    
    return dict(items)

def extract_os_from_tags(tags_json):
    """
    Extract OS information from the tags field.
    Returns a comma-separated string of OS names.
    """
    try:
        if not tags_json:
            return ""
        
        tags = json.loads(tags_json)
        os_tags = []
        
        for tag in tags:
            if tag.startswith("OS: "):
                os_tags.append(tag.replace("OS: ", ""))
        
        return ", ".join(os_tags)
    except:
        return ""

def is_network_related(tags_json, file_path=""):
    """
    Check if the rule is network-related based on tags and file path.
    Returns "Yes" if network-related, "" otherwise.
    """
    try:
        # Check file path for network directory
        if "network" in file_path.lower():
            return "Yes"
        
        if not tags_json:
            return ""
        
        tags = json.loads(tags_json)
        
        # Check for network-related tags
        for tag in tags:
            if "network" in tag.lower() or "traffic" in tag.lower() or "packet" in tag.lower():
                return "Yes"
        
        return ""
    except:
        return ""

def extract_tactics(rule_data):
    """
    Extract MITRE ATT&CK tactics from the rule data.
    Returns a comma-separated string of tactic names.
    """
    try:
        tactics = set()
        
        # Extract from threat.tactic.name
        threats = rule_data.get('rule', {}).get('threat', [])
        if threats:
            for threat in threats:
                tactic = threat.get('tactic', {}).get('name', '')
                if tactic:
                    tactics.add(tactic)
        
        # Extract from tags
        tags = rule_data.get('rule', {}).get('tags', [])
        for tag in tags:
            if tag.startswith("Tactic: "):
                tactics.add(tag.replace("Tactic: ", ""))
        
        return ", ".join(sorted(tactics))
    except:
        return ""

def extract_techniques(rule_data):
    """
    Extract MITRE ATT&CK techniques from the rule data.
    Returns a comma-separated string of technique IDs and names.
    """
    try:
        techniques = set()
        
        # Extract from threat.technique
        threats = rule_data.get('rule', {}).get('threat', [])
        if threats:
            for threat in threats:
                for technique in threat.get('technique', []):
                    tech_id = technique.get('id', '')
                    tech_name = technique.get('name', '')
                    if tech_id and tech_name:
                        techniques.add(f"{tech_id} - {tech_name}")
                    
                    # Check for subtechniques
                    for subtechnique in technique.get('subtechnique', []):
                        subtech_id = subtechnique.get('id', '')
                        subtech_name = subtechnique.get('name', '')
                        if subtech_id and subtech_name:
                            techniques.add(f"{subtech_id} - {subtech_name}")
        
        return ", ".join(sorted(techniques))
    except:
        return ""

def extract_rule_category(file_path):
    """
    Extract rule category from the file path.
    Returns a string representing the category.
    """
    try:
        # Extract from file path
        parts = file_path.split(os.sep)
        
        # Find the index of 'rules' directory
        if 'rules' in parts:
            rules_index = parts.index('rules')
            if rules_index + 1 < len(parts):
                # Get the category (directory after 'rules')
                category = parts[rules_index + 1]
                return category
        
        # If we can't determine the category from the path, extract from filename
        filename = os.path.basename(file_path)
        if '_' in filename:
            # Use the part before the first underscore as the category
            category = filename.split('_')[0]
            return category
        
        return ""
    except:
        return ""

def is_aws_related(rule_data, file_path=""):
    """
    Check if the rule is AWS-related based on tags, file path, and other indicators.
    Returns "Yes" if AWS-related, "" otherwise.
    """
    try:
        # Check file path for AWS directory
        if "aws" in file_path.lower():
            return "Yes"
        
        # Check integration for AWS
        integrations = rule_data.get('metadata', {}).get('integration', [])
        if isinstance(integrations, list) and any("aws" in integration.lower() for integration in integrations):
            return "Yes"
        
        # Check tags for AWS
        tags = rule_data.get('rule', {}).get('tags', [])
        if isinstance(tags, list) and any("aws" in tag.lower() for tag in tags):
            return "Yes"
        
        # Check index for AWS
        indices = rule_data.get('rule', {}).get('index', [])
        if isinstance(indices, list) and any("aws" in index.lower() for index in indices):
            return "Yes"
        
        # Check description for AWS
        description = rule_data.get('rule', {}).get('description', '')
        if "aws" in description.lower() or "amazon" in description.lower() or "ec2" in description.lower():
            return "Yes"
        
        return ""
    except:
        return ""

def references_external_media(rule_data):
    """
    Check if the rule references external media (USB, CD, DVD, etc.).
    Returns "Yes" if it references external media, "" otherwise.
    """
    try:
        # Check description for external media references
        description = rule_data.get('rule', {}).get('description', '').lower()
        query = rule_data.get('rule', {}).get('query', '').lower()
        
        external_media_keywords = [
            "usb", "thumb drive", "flash drive", "external drive", "external media",
            "removable media", "removable drive", "cd-rom", "dvd", "optical drive",
            "external device", "removable device"
        ]
        
        # Check description
        if any(keyword in description for keyword in external_media_keywords):
            return "Yes"
        
        # Check query
        if any(keyword in query for keyword in external_media_keywords):
            return "Yes"
        
        return ""
    except:
        return ""

def is_macos_only(os_types):
    """
    Check if the rule is macOS-only.
    Returns True if the rule is macOS-only, False otherwise.
    """
    if not os_types:
        return False
    
    return "macOS" in os_types and "Windows" not in os_types and "Linux" not in os_types

def process_toml_files(rules_dir, output_file):
    """
    Process all .toml files in the rules directory, filter based on criteria,
    and write the results to a CSV file.
    """
    # Get all .toml files recursively
    toml_files = []
    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith('.toml'):
                toml_files.append(os.path.join(root, file))
    
    print(f"Found {len(toml_files)} .toml files")
    print(f"Rules directory: {rules_dir}")
    print(f"First few files: {toml_files[:5] if toml_files else 'No files found'}")
    
    # Process each file and collect rules that meet the criteria
    valid_rules = []
    all_fields = set()
    
    for file_path in toml_files:
        try:
            # Parse the TOML file
            rule_data = toml.load(file_path)
            
            # Skip if the rule type is "machine_learning"
            if rule_data.get('rule', {}).get('type') == "machine_learning":
                continue
            
            # Skip if the rule uses ".alerts-security.*" index
            indices = rule_data.get('rule', {}).get('index', [])
            if any(".alerts-security.*" in index for index in indices):
                continue
            
            # Extract OS types first to check if macOS-only
            tags_json = json.dumps(rule_data.get('rule', {}).get('tags', []))
            os_types = extract_os_from_tags(tags_json)
            
            # Skip if the rule is macOS-only
            if is_macos_only(os_types):
                continue
            
            # Skip if the rule references external media
            if references_external_media(rule_data) == "Yes":
                continue
            
            # Add the file path as a reference
            rule_data['file_path'] = file_path
            
            # Flatten the rule data
            flattened_rule = flatten_dict(rule_data)
            
            # Add OS field for easier filtering
            tags_json = flattened_rule.get('rule_tags', '')
            flattened_rule['os_types'] = os_types  # Use the already extracted os_types
            
            # Add network field for easier filtering
            flattened_rule['is_network_related'] = is_network_related(tags_json, file_path)
            
            # Add fields for targeted testing
            flattened_rule['mitre_tactics'] = extract_tactics(rule_data)
            flattened_rule['mitre_techniques'] = extract_techniques(rule_data)
            flattened_rule['rule_category'] = extract_rule_category(file_path)
            
            # Add AWS-related field
            flattened_rule['is_aws_related'] = is_aws_related(rule_data, file_path)
            
            # Update the set of all fields
            all_fields.update(flattened_rule.keys())
            
            # Add the rule to the list of valid rules
            valid_rules.append(flattened_rule)
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
    
    print(f"Found {len(valid_rules)} rules that meet the criteria")
    
    # Sort fields to ensure consistent column order
    all_fields = sorted(list(all_fields))
    
    # Write the rules to a CSV file
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=all_fields)
        writer.writeheader()
        
        for rule in valid_rules:
            # Ensure all fields are present in the rule
            row = {field: rule.get(field, '') for field in all_fields}
            writer.writerow(row)
    
    print(f"CSV file created at {output_file}")

def main():
    # Define paths
    base_dir = os.path.dirname(os.path.abspath(__file__))
    rules_dir = os.path.join(base_dir, "..", "rules", "detection-rules", "rules")
    output_dir = os.path.join(base_dir, "..", "Output")
    
    print(f"Base directory: {base_dir}")
    print(f"Rules directory: {rules_dir}")
    print(f"Output directory: {output_dir}")
    
    # Check if the rules directory exists
    if not os.path.exists(rules_dir):
        print(f"Error: Rules directory does not exist: {rules_dir}")
        print(f"Current working directory: {os.getcwd()}")
        print(f"Directory contents: {os.listdir(os.path.dirname(rules_dir))}")
        return
    
    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate a timestamp for the output file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"elastic_rules_{timestamp}.csv")
    
    # Process the TOML files and create the CSV
    process_toml_files(rules_dir, output_file)

if __name__ == "__main__":
    main()
