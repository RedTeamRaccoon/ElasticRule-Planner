#!/usr/bin/env python3
"""
Elastic Rule Validator

This script processes a CSV file containing Elastic detection rules and generates
a comprehensive red team validation guide with step-by-step instructions for testing
each rule in a controlled environment.

Usage:
    python elastic_rule_validator.py --csv_file path/to/rules.csv [--api_key your_anthropic_api_key] --output path/to/output.md

The script can load the Anthropic API key from a .env file if not provided as a command-line argument.
Example .env file:
    ANTHROPIC_API_KEY=your_anthropic_api_key

The script includes rate limiting to respect Anthropic API limits:
- Claude 3.7 Sonnet: 2,000 requests/min, 80,000 input tokens/min, 32,000 output tokens/min
- Claude 3.5 Sonnet: 2,000 requests/min, 160,000 input tokens/min, 32,000 output tokens/min
"""

import argparse
import csv
import os
import time
import anthropic
from anthropic import Anthropic
from dotenv import load_dotenv
import threading
import queue
import datetime
import signal
import sys

# Rate limiting configuration
class RateLimiter:
    """Rate limiter for API calls."""
    def __init__(self, requests_per_minute, input_tokens_per_minute, output_tokens_per_minute, disable_rate_limiting=False):
        self.requests_per_minute = requests_per_minute
        self.input_tokens_per_minute = input_tokens_per_minute
        self.output_tokens_per_minute = output_tokens_per_minute
        self.disable_rate_limiting = disable_rate_limiting
        
        self.request_timestamps = []
        self.input_tokens = []
        self.output_tokens = []
        
        self.lock = threading.Lock()
    
    def wait_if_needed(self, input_token_count, output_token_count=0):
        """Wait if rate limits would be exceeded."""
        # Skip rate limiting if disabled
        if self.disable_rate_limiting:
            # Still record the usage for tracking purposes
            now = datetime.datetime.now()
            with self.lock:
                self.request_timestamps.append(now)
                self.input_tokens.append((now, input_token_count))
                if output_token_count > 0:
                    self.output_tokens.append((now, output_token_count))
            return
        
        # Maximum wait time in seconds (to prevent indefinite waiting)
        MAX_WAIT_TIME = 30
        
        with self.lock:
            now = datetime.datetime.now()
            minute_ago = now - datetime.timedelta(minutes=1)
            
            # Clean up old timestamps and token counts
            self.request_timestamps = [ts for ts in self.request_timestamps if ts > minute_ago]
            self.input_tokens = [(ts, tokens) for ts, tokens in self.input_tokens if ts > minute_ago]
            self.output_tokens = [(ts, tokens) for ts, tokens in self.output_tokens if ts > minute_ago]
            
            # Calculate current usage
            current_requests = len(self.request_timestamps)
            current_input_tokens = sum(tokens for _, tokens in self.input_tokens)
            current_output_tokens = sum(tokens for _, tokens in self.output_tokens)
            
            # Print current usage stats
            print(f"Current API usage: {current_requests}/{self.requests_per_minute} requests, {current_input_tokens}/{self.input_tokens_per_minute} input tokens, {current_output_tokens}/{self.output_tokens_per_minute} output tokens")
            
            # Check if we need to wait (using 80% threshold to be more conservative)
            need_to_wait = False
            wait_reason = ""
            wait_time = 0
            
            if current_requests >= self.requests_per_minute * 0.8 and self.request_timestamps:
                oldest_timestamp = min(self.request_timestamps)
                wait_time = max(wait_time, (oldest_timestamp - minute_ago).total_seconds())
                need_to_wait = True
                wait_reason = f"requests ({current_requests}/{self.requests_per_minute})"
            
            if current_input_tokens + input_token_count > self.input_tokens_per_minute * 0.8 and self.input_tokens:
                oldest_timestamp = min(ts for ts, _ in self.input_tokens)
                wait_time = max(wait_time, (oldest_timestamp - minute_ago).total_seconds())
                need_to_wait = True
                wait_reason = f"input tokens ({current_input_tokens}/{self.input_tokens_per_minute})"
            
            if current_output_tokens + output_token_count > self.output_tokens_per_minute * 0.8 and self.output_tokens:
                oldest_timestamp = min(ts for ts, _ in self.output_tokens)
                wait_time = max(wait_time, (oldest_timestamp - minute_ago).total_seconds())
                need_to_wait = True
                wait_reason = f"output tokens ({current_output_tokens}/{self.output_tokens_per_minute})"
            
            # Cap the wait time to prevent excessive waiting
            wait_time = min(wait_time, MAX_WAIT_TIME)
            
            # Wait if needed
            if need_to_wait and wait_time > 0:
                print(f"Rate limit approaching for {wait_reason}. Waiting up to {wait_time:.2f} seconds...")
                # Sleep in smaller increments to provide feedback
                for i in range(int(wait_time)):
                    time.sleep(1)
                    if i % 5 == 0 and i > 0:  # Show progress every 5 seconds
                        print(f"Still waiting... {i}/{int(wait_time)} seconds elapsed")
                
                # Sleep any remaining fraction of a second
                time.sleep(max(0, wait_time - int(wait_time)))
                
                print(f"Wait complete. Continuing processing...")
            
            # Record this request
            self.request_timestamps.append(now)
            self.input_tokens.append((now, input_token_count))
            if output_token_count > 0:
                self.output_tokens.append((now, output_token_count))

# Model configurations
MODEL_CONFIGS = {
    "claude-3.7-sonnet": {
        "name": "claude-3-7-sonnet-20250219",
        "requests_per_minute": 2000,
        "input_tokens_per_minute": 80000,
        "output_tokens_per_minute": 32000
    },
    "claude-3.5-sonnet": {
        "name": "claude-3-5-sonnet-20241022",
        "requests_per_minute": 2000,
        "input_tokens_per_minute": 160000,
        "output_tokens_per_minute": 32000
    }
}

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate a red team validation guide for Elastic detection rules.')
    parser.add_argument('--csv_file', required=True, help='Path to the CSV file containing detection rules')
    parser.add_argument('--api_key', required=False, help='Anthropic API key (can also be set in .env file as ANTHROPIC_API_KEY)')
    parser.add_argument('--output', default='red_team_validation_guide.md', help='Output markdown file path')
    parser.add_argument('--model', default='claude-3.7-sonnet', choices=MODEL_CONFIGS.keys(), 
                        help='Anthropic model to use (claude-3.7-sonnet or claude-3.5-sonnet)')
    parser.add_argument('--max_tokens', type=int, default=4000, help='Maximum tokens for response')
    parser.add_argument('--temperature', type=float, default=0.1, help='Temperature for response generation')
    parser.add_argument('--batch_size', type=int, default=5, help='Number of rules to process in each batch')
    parser.add_argument('--env_file', default='.env', help='Path to .env file containing ANTHROPIC_API_KEY')
    parser.add_argument('--concurrent_requests', type=int, default=3, 
                        help='Number of concurrent API requests (careful with rate limits)')
    parser.add_argument('--disable_rate_limiting', action='store_true', 
                        help='Disable rate limiting (use with caution, may result in API errors)')
    parser.add_argument('--delay_between_requests', type=float, default=0.0,
                        help='Add a delay between API requests in seconds (useful when rate limiting is disabled)')
    return parser.parse_args()

def read_rules_from_csv(csv_file):
    """Read detection rules from a CSV file."""
    rules = []
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rules.append(row)
    return rules

def categorize_rules(rules):
    """Categorize rules based on their type."""
    categories = {
        'SSH and Container Security': [],
        'Container Security': [],
        'System Modification and Persistence': [],
        'Package Manager Manipulation': [],
        'Obfuscation and Encoding': [],
        'Network and Web Server Activity': [],
        'Reverse Shell and Command Execution': [],
        'Hidden Files and Privilege Escalation': [],
        'Git and NetworkManager Hooks': [],
        'Kernel and Boot Process Manipulation': [],
        'Miscellaneous': []
    }
    
    for rule in rules:
        # Extract relevant information for categorization
        rule_name = rule.get('rule_name', '')
        rule_description = rule.get('rule_description', '')
        rule_query = rule.get('rule_query', '')
        mitre_tactics = rule.get('mitre_tactics', '')
        mitre_techniques = rule.get('mitre_techniques', '')
        
        # Categorize based on keywords in name, description, and query
        if any(keyword in rule_name.lower() or keyword in rule_description.lower() 
               for keyword in ['ssh', 'sshd']):
            if 'container' in rule_name.lower() or 'container' in rule_description.lower() or 'container.id' in rule_query:
                categories['SSH and Container Security'].append(rule)
            else:
                categories['SSH and Container Security'].append(rule)
        elif 'container' in rule_name.lower() or 'container' in rule_description.lower() or 'container.id' in rule_query:
            categories['Container Security'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['apt', 'dpkg', 'rpm', 'yum', 'dnf', 'package manager']):
            categories['Package Manager Manipulation'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['base64', 'hex', 'encoded', 'encoding', 'obfuscated', 'obfuscation']):
            categories['Obfuscation and Encoding'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['network', 'web server', 'http', 'connection']):
            categories['Network and Web Server Activity'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['reverse shell', 'shell', 'command execution']):
            categories['Reverse Shell and Command Execution'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['hidden', 'suid', 'sgid', 'privilege']):
            categories['Hidden Files and Privilege Escalation'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['git', 'networkmanager']):
            categories['Git and NetworkManager Hooks'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['kernel', 'boot', 'initramfs', 'dracut']):
            categories['Kernel and Boot Process Manipulation'].append(rule)
        elif any(keyword in rule_name.lower() or keyword in rule_description.lower() 
                for keyword in ['hosts file', 'authentication', 'pam', 'elastic agent', 'dynamic linker', 'persistence']):
            categories['System Modification and Persistence'].append(rule)
        else:
            categories['Miscellaneous'].append(rule)
    
    # Remove empty categories
    return {k: v for k, v in categories.items() if v}

def estimate_token_count(text):
    """Estimate the number of tokens in a text string."""
    # A very rough estimate: 1 token ≈ 4 characters for English text
    return len(text) // 4

def generate_test_procedure(rule, client, model_name, max_tokens, temperature, rate_limiter, delay_between_requests=0):
    """Generate a test procedure for a rule using the Anthropic API."""
    rule_name = rule.get('rule_name', 'Unknown Rule')
    rule_id = rule.get('rule_rule_id', 'Unknown ID')
    rule_description = rule.get('rule_description', 'No description available')
    mitre_tactics = rule.get('mitre_tactics', 'Unknown')
    mitre_techniques = rule.get('mitre_techniques', 'Unknown')
    rule_query = rule.get('rule_query', 'No query available')
    
    prompt = f"""
You are a cybersecurity expert specializing in red team operations and detection engineering. 
Your task is to create a detailed test procedure for validating an Elastic detection rule.

Here is the information about the rule:

Rule Name: {rule_name}
Rule ID: {rule_id}
Description: {rule_description}
MITRE Tactics: {mitre_tactics}
MITRE Techniques: {mitre_techniques}
Rule Query: {rule_query}

Please create a comprehensive test procedure that includes:
1. Prerequisites (required tools, permissions, environment)
2. Step-by-step test instructions with actual commands to execute
3. Cleanup procedures to restore the system to its original state
4. Warnings about potential risks or destructive aspects of the test

The test should be:
- Non-destructive where possible
- Realistic enough to trigger the detection rule
- Detailed enough for a security professional to follow
- Include actual bash commands that can be copy-pasted
- Include explanations of what each step does and why it triggers the rule

Format your response in Markdown, with the following structure:

### Rule Name

**Rule ID**: rule_id

**Description**: Brief description

**MITRE Tactics**: Tactics

**MITRE Techniques**: Techniques

#### Prerequisites

- List of prerequisites

#### Test Procedure

1. **Step 1 title**

```bash
# Command 1
# Command 2
```

2. **Step 2 title**

```bash
# Command 1
# Command 2
```

#### Cleanup

```bash
# Cleanup commands
```

#### Warning

Warning text about potential risks
"""

    # Estimate token count
    estimated_input_tokens = estimate_token_count(prompt)
    
    # Wait if needed to respect rate limits
    rate_limiter.wait_if_needed(estimated_input_tokens, max_tokens)
    
    try:
        # Add optional delay between requests (useful when rate limiting is disabled)
        if delay_between_requests > 0:
            print(f"Adding delay of {delay_between_requests} seconds between requests...")
            time.sleep(delay_between_requests)
            
        response = client.messages.create(
            model=model_name,
            max_tokens=max_tokens,
            temperature=temperature,
            system="You are a cybersecurity expert specializing in red team operations and detection engineering.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        # Record actual output tokens
        output_text = response.content[0].text
        estimated_output_tokens = estimate_token_count(output_text)
        
        # No need to wait after the last request in a batch
        # This prevents the script from waiting unnecessarily
        # rate_limiter.wait_if_needed(0, estimated_output_tokens)
        
        return output_text
    except Exception as e:
        print(f"Error generating test procedure for {rule_name}: {e}")
        return f"### {rule_name}\n\n**Error**: Failed to generate test procedure. Please try again later."

def create_table_of_contents(categories):
    """Create a table of contents for the validation guide."""
    toc = "## Table of Contents\n\n"
    
    for i, category in enumerate(categories.keys(), 1):
        toc += f"{i}. [{category}](#{category.lower().replace(' ', '-').replace('&', 'and')})\n"
        for rule in categories[category]:
            rule_name = rule.get('rule_name', 'Unknown Rule')
            toc += f"   - [{rule_name}](#{rule_name.lower().replace(' ', '-').replace('(', '').replace(')', '').replace('/', '').replace(',', '').replace('&', 'and')})\n"
        toc += "\n"
    
    return toc

def worker(rule_queue, result_queue, client, model_name, max_tokens, temperature, rate_limiter, delay_between_requests=0):
    """Worker function for processing rules in parallel."""
    worker_id = threading.get_ident()
    print(f"Worker {worker_id} started")
    
    while True:
        try:
            category, rule = rule_queue.get(block=False)
            if rule is None:
                print(f"Worker {worker_id} received stop signal")
                rule_queue.task_done()
                break
                
            rule_name = rule.get('rule_name', 'Unknown Rule')
            print(f"Worker {worker_id} generating test procedure for: {rule_name}")
            
            test_procedure = generate_test_procedure(
                rule, client, model_name, max_tokens, temperature, rate_limiter, delay_between_requests
            )
            
            result_queue.put((category, rule, test_procedure))
            print(f"Worker {worker_id} completed test procedure for: {rule_name}")
            rule_queue.task_done()
            
        except queue.Empty:
            print(f"Worker {worker_id} queue empty, exiting")
            break
        except Exception as e:
            print(f"Error in worker {worker_id}: {e}")
            rule_queue.task_done()
    
    print(f"Worker {worker_id} finished")

def generate_validation_guide(categories, client, model_config, max_tokens, temperature, batch_size, concurrent_requests, disable_rate_limiting=False, delay_between_requests=0):
    """Generate the complete validation guide."""
    guide = "# Red Team Validation Guide for Elastic Detection Rules\n\n"
    guide += "This guide provides step-by-step instructions for testing Elastic detection rules in a controlled environment. "
    guide += "Each section includes detailed procedures to safely trigger detection rules, allowing security teams to validate their detection capabilities.\n\n"
    
    # Add table of contents
    guide += create_table_of_contents(categories)
    guide += "---\n\n"
    
    # Initialize rate limiter
    rate_limiter = RateLimiter(
        model_config["requests_per_minute"],
        model_config["input_tokens_per_minute"],
        model_config["output_tokens_per_minute"],
        disable_rate_limiting
    )
    
    # Create a dictionary to store results by category
    results = {category: [] for category in categories.keys()}
    
    # Create queues for tasks and results
    rule_queue = queue.Queue()
    result_queue = queue.Queue()
    
    # Count total rules
    total_rules = sum(len(rules) for rules in categories.values())
    processed_rules = 0
    
    # Add all rules to the queue
    for category, rules in categories.items():
        for rule in rules:
            rule_queue.put((category, rule))
    
    # Create a progress tracking function
    def update_progress():
        nonlocal processed_rules
        processed_rules += 1
        progress_pct = (processed_rules / total_rules) * 100
        print(f"Progress: {processed_rules}/{total_rules} rules processed ({progress_pct:.1f}%)")
        # Save intermediate results every 10% progress
        if processed_rules % max(1, total_rules // 10) == 0:
            print(f"Saving intermediate results at {progress_pct:.1f}% completion...")
            save_intermediate_results()
    
    # Function to save intermediate results
    def save_intermediate_results():
        # Create a copy of the current results
        current_results = {category: list(category_results) for category, category_results in results.items()}
        
        # Generate intermediate guide
        intermediate_guide = guide
        
        # Add results so far
        for category, category_results in current_results.items():
            if category_results:
                intermediate_guide += f"## {category}\n\n"
                
                # Sort results by rule name
                category_results.sort(key=lambda x: x[0].get('rule_name', ''))
                
                for rule, test_procedure in category_results:
                    intermediate_guide += test_procedure + "\n\n---\n\n"
        
        # Write intermediate guide to file with timestamp
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        intermediate_file = f"red_team_guide_intermediate_{timestamp}.md"
        with open(intermediate_file, 'w', encoding='utf-8') as f:
            f.write(intermediate_guide)
        print(f"Intermediate results saved to {intermediate_file}")
    
    # Create a result handler function
    def handle_result(category, rule, test_procedure):
        results[category].append((rule, test_procedure))
        update_progress()
    
    # Create and start worker threads
    threads = []
    for i in range(min(concurrent_requests, rule_queue.qsize())):
        thread = threading.Thread(
            target=worker,
            args=(rule_queue, result_queue, client, model_config["name"], max_tokens, temperature, rate_limiter, delay_between_requests),
            name=f"Worker-{i+1}"
        )
        thread.daemon = True  # Make threads daemon so they exit when main thread exits
        thread.start()
        threads.append(thread)
    
    # Process results as they come in
    print(f"Starting processing of {total_rules} rules with {concurrent_requests} concurrent workers")
    
    # Process results while workers are running
    while processed_rules < total_rules:
        try:
            # Try to get a result with timeout
            category, rule, test_procedure = result_queue.get(timeout=1)
            handle_result(category, rule, test_procedure)
            result_queue.task_done()
        except queue.Empty:
            # Check if all workers are done
            if all(not thread.is_alive() for thread in threads):
                # If all workers are done but we haven't processed all rules, something went wrong
                if processed_rules < total_rules:
                    print(f"Warning: All workers finished but only {processed_rules}/{total_rules} rules processed")
                break
            # Otherwise, just continue waiting
            continue
        except Exception as e:
            print(f"Error processing result: {e}")
    
    # Wait for all tasks to be processed
    rule_queue.join()
    
    # Stop worker threads
    for _ in range(len(threads)):
        rule_queue.put((None, None))
    
    for thread in threads:
        thread.join(timeout=1)  # Join with timeout to avoid hanging
    
    # Process any remaining results
    while not result_queue.empty():
        try:
            category, rule, test_procedure = result_queue.get(block=False)
            handle_result(category, rule, test_procedure)
            result_queue.task_done()
        except queue.Empty:
            break
    
    # Generate the guide with results
    for category, category_results in results.items():
        if category_results:
            guide += f"## {category}\n\n"
            
            # Sort results by rule name to maintain consistent order
            category_results.sort(key=lambda x: x[0].get('rule_name', ''))
            
            for rule, test_procedure in category_results:
                guide += test_procedure + "\n\n---\n\n"
    
    return guide

def main():
    """Main function."""
    args = parse_args()
    
    # Add a keyboard interrupt handler
    def signal_handler(sig, frame):
        print("\nProcess interrupted by user. Saving current progress...")
        # You could add code here to save intermediate results
        print("Exiting gracefully.")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Load API key from .env file if not provided as command-line argument
    api_key = args.api_key
    if not api_key:
        # Load environment variables from .env file
        load_dotenv(args.env_file)
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Anthropic API key not found. Please provide it as a command-line argument or set ANTHROPIC_API_KEY in your .env file.")
    
    # Get model configuration
    model_config = MODEL_CONFIGS[args.model]
    print(f"Using model: {model_config['name']}")
    print(f"Rate limits: {model_config['requests_per_minute']} requests/min, "
          f"{model_config['input_tokens_per_minute']} input tokens/min, "
          f"{model_config['output_tokens_per_minute']} output tokens/min")
    
    if args.disable_rate_limiting:
        print("WARNING: Rate limiting is disabled. This may result in API errors if you exceed the rate limits.")
        if args.delay_between_requests > 0:
            print(f"Adding a delay of {args.delay_between_requests} seconds between requests to avoid API errors.")
    
    # Read rules from CSV
    print(f"Reading rules from {args.csv_file}...")
    rules = read_rules_from_csv(args.csv_file)
    print(f"Found {len(rules)} rules.")
    
    # Categorize rules
    print("Categorizing rules...")
    categories = categorize_rules(rules)
    print(f"Categorized rules into {len(categories)} categories.")
    
    # Initialize Anthropic client
    print("Initializing Anthropic client...")
    client = Anthropic(api_key=api_key)
    
    # Generate validation guide
    print(f"Generating validation guide with {args.concurrent_requests} concurrent requests...")
    print(f"This may take a while for {sum(len(rules) for rules in categories.values())} rules.")
    print("The script will save intermediate results periodically and show progress updates.")
    print("Press Ctrl+C to interrupt and save current progress.")
    
    try:
        guide = generate_validation_guide(
            categories, client, model_config, args.max_tokens, 
            args.temperature, args.batch_size, args.concurrent_requests,
            args.disable_rate_limiting, args.delay_between_requests
        )
        
        # Write guide to file
        print(f"Writing guide to {args.output}...")
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(guide)
        
        print("Done!")
    except Exception as e:
        print(f"Error during guide generation: {e}")
        print("Attempting to save partial results...")
        # You could add code here to save intermediate results
        raise

if __name__ == "__main__":
    main()
