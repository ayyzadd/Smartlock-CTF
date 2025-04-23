#!/usr/bin/env python3
"""
UnifiedFuzzer - A unified fuzzing framework with shared methods for both Django and BLE
"""

import sys
import os
import json
import random
import time
import asyncio
import datetime
import argparse
import traceback
import requests
from collections import defaultdict
from pathlib import Path

# Ensure BLE components are in the path
sys.path.append(str(Path(__file__).parent / "BLE"))

# Import BLE components conditionally
BLE_AVAILABLE = False
if len(sys.argv) > 1 and '--target' in sys.argv:
    target_index = sys.argv.index('--target')
    if target_index + 1 < len(sys.argv) and sys.argv[target_index + 1] in ['ble', 'both']:
        try:
            from BLEClient import BLEClient
            from UserInterface import ShowUserInterface
            BLE_AVAILABLE = True
        except Exception as e:
            print(f"Warning: Could not import BLE components: {e}")
            print("BLE fuzzing functionality will be disabled")
else:
    # Default is both targets, so try to import BLE components
    try:
        from BLEClient import BLEClient
        from UserInterface import ShowUserInterface
        BLE_AVAILABLE = True
    except Exception as e:
        print(f"Warning: Could not import BLE components: {e}")
        print("BLE fuzzing functionality will be disabled")

# Try to import coverage module for Django testing
try:
    import coverage as coverage_module
    COVERAGE_AVAILABLE = True
except ImportError:
    print("Warning: Could not import coverage module. Coverage reporting will be disabled.")
    COVERAGE_AVAILABLE = False

class UnifiedFuzzer:
    """Unified fuzzer that handles both Django and BLE targets with shared methods"""
    
    def __init__(self, config=None):
        """Initialize the unified fuzzer with configuration"""
        # Default configuration
        self.config = {
            'target': 'both',          # 'django', 'ble', or 'both'
            'iterations': 100,         # Number of fuzzing iterations
            'timeout': 30,             # Timeout in seconds
            'output_dir': 'results',   # Output directory
            'django_url': 'http://127.0.0.1:8000/datatb/product/',  # Django URL
            'ble_device': 'Smart Lock [Group 2]',   # BLE device name
            'django_input': 'input.json',    # Django input file
            'ble_input': 'Input1.json',          # BLE input file
            'enable_coverage': True,
            'coverage_source': ['.']

        }
        
        # Update with provided config
        if config:
            self.config.update(config)
        
        # Create timestamp for results
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"{self.config['output_dir']}_{timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Create subdirectories for each target
        self.django_output_dir = os.path.join(self.output_dir, "django")
        self.ble_output_dir = os.path.join(self.output_dir, "ble")
        os.makedirs(self.django_output_dir, exist_ok=True)
        os.makedirs(self.ble_output_dir, exist_ok=True)
        
        # Combined results tracking
        self.results = {
            'django': {'total_tests': 0, 'crashes': 0, 'unique_issues': 0},
            'ble': {'total_tests': 0, 'crashes': 0, 'unique_issues': 0}
        }
        
        # Django specific variables
        self.django_seed_queue = []
        self.django_failure_queue = []
        self.django_failure_types = {}
        self.django_request_counter = 0
        self.django_success_counter = 0
        self.django_error_counter = 0
        self.django_coverage = None
        
        # BLE specific variables
        self.ble_client = None
        self.ble_state = "Locked"  # Initial state
        self.ble_interesting_count = defaultdict(int)
        self.ble_seeds = []
        self.ble_test_counter = 0
        self.ble_interesting_behaviors = 0
        
        print(f"Initialized UnifiedFuzzer with target: {self.config['target']}")
        print(f"Results will be saved to: {self.output_dir}")
    
    #------ Common Unified Methods ------#
    
    def load_seeds(self, target):
        """Load seeds for the specified target"""
        if target == 'django':
            try:
                with open(self.config['django_input'], 'r') as f:
                    seeds = json.load(f)
                    self.django_seed_queue.extend(seeds)
                    print(f"Loaded {len(seeds)} Django seeds from {self.config['django_input']}")
            except Exception as e:
                print(f"Error loading Django seeds: {e}")
                # Create default seeds if loading fails
                default_seeds = [
                    {
                        "name": "Default Product",
                        "price": 99.99,
                        "info": "Default product information"
                    },
                    {
                        "name": "Test Item",
                        "price": 100,
                        "info": "Sample description"
                    }
                ]
                self.django_seed_queue.extend(default_seeds)
                print(f"Using {len(default_seeds)} default Django seeds instead")
        elif target == 'ble':
            try:
                with open(self.config['ble_input'], 'r') as f:
                    self.ble_seeds = json.load(f)
                    print(f"[+] Loaded {len(self.ble_seeds)} BLE seeds from {self.config['ble_input']}")
            except Exception as e:
                print(f"[X] Failed to load BLE seed file: {e}")
                self.ble_seeds = []
    
    def choose_next(self, target):
        """Choose the next seed for the specified target"""
        if target == 'django':
            if not self.django_seed_queue:
                # If seed queue is empty, add a basic template
                default_seed = {
                    "name": f"Replenished Product {random.randint(1000, 9999)}",
                    "price": round(random.uniform(10, 1000), 2),
                    "info": f"Replenished product information {datetime.datetime.now()}"
                }
                self.django_seed_queue.append(default_seed)
                print(f"Django seed queue replenished with: {default_seed}")
            return self.django_seed_queue.pop(0)
        elif target == 'ble':
            if not self.ble_seeds:
                print("BLE seed list is empty. Creating default seeds.")
                default_seeds = [
                    {
                        "from_state": "any",
                        "to_state": "Locked",
                        "command": [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
                    },
                    {
                        "from_state": "Authenticated",
                        "to_state": "Unlocked",
                        "command": [0x01]
                    },
                    {
                        "from_state": "Unlocked",
                        "to_state": "Locked",
                        "command": [0x02]
                    }
                ]
                self.ble_seeds = default_seeds
                print(f"Using {len(default_seeds)} default BLE seeds instead")

            candidates = [s for s in self.ble_seeds if s["from_state"] == self.ble_state or s["from_state"] == "any"]
            if not candidates:
                return random.choice(self.ble_seeds)
            return random.choice(candidates) 
    
    def assign_energy(self, target, seed=None):
        """Assign energy for the specified target"""
        if target == 'django':
            return 10  # Constant value for Django
        elif target == 'ble':
            base = 5
            bonus = min(self.ble_interesting_count[json.dumps(seed)], 7)
            return base + bonus + random.randint(0, 3)
    
    def mutate_input(self, target, seed):
        """Create a mutated input for the specified target"""
        if target == 'django':
            mutated = seed.copy()
            
            # Track what mutation was applied for debugging
            mutation_type = random.choice([
                'flip_char', 
                'remove_field', 
                'invalid_type', 
                'boundary_value', 
                'division_by_zero', 
                'malformed_json',
                'empty_value',
                'extremely_long_value'
            ])
            
            # Record the mutation type for analysis
            mutated['_mutation_type'] = mutation_type

            if mutation_type == 'flip_char' and 'name' in mutated:
                chars = list(mutated['name'])
                if chars:
                    pos = random.randint(0, len(chars) - 1)
                    chars[pos] = random.choice('!@#$%^&*()_+-=[]{}|;:,.<>?')  # Flip a character
                    mutated['name'] = ''.join(chars)
            
            elif mutation_type == 'remove_field':
                field = random.choice(['name', 'info', 'price'])
                mutated.pop(field, None)
            
            elif mutation_type == 'invalid_type':
                field = random.choice(['name', 'info', 'price'])
                invalid_values = [None, [], {}, True, "".encode('utf-8'), set([1, 2, 3]), (1, 2, 3)]
                mutated[field] = random.choice(invalid_values)
            
            elif mutation_type == 'boundary_value' and 'price' in mutated:
                mutated['price'] = random.choice([
                    -1,          # Negative price
                    2**31-1,     # Large number
                    "💰💰💰",     # Unexpected data type
                    float('nan'),# Not a number
                    0.000001,    # Very small number
                    float('inf'),# Infinity
                ])

            elif mutation_type == 'division_by_zero':
                # Introducing a division by zero case
                mutated['divide_by'] = 0
            
            elif mutation_type == 'malformed_json':
                # For malformed JSON testing, we'll keep a valid structure but with strange values
                mutated = {
                    "name": "TestItem", 
                    "price": 100,
                    "info": "Sample", 
                    "extra_field": "Something extra,}",
                    "_mutation_type": mutation_type
                }
                
            elif mutation_type == 'empty_value':
                field = random.choice(['name', 'info', 'price'])
                mutated[field] = ""
                
            elif mutation_type == 'extremely_long_value':
                mutated['price'] = 10 ** 200

            return mutated
            
        elif target == 'ble':
            mutation_type = random.choice(["bit_flip", "remove_field", "invalid_type", "boundary_value"])
            command = seed["command"].copy()

            if mutation_type == "bit_flip" and command:
                idx = random.randint(0, len(command) - 1)
                bit = 1 << random.randint(0, 7)
                command[idx] ^= bit

            elif mutation_type == "remove_field" and len(command) > 1:
                command.pop(random.randint(0, len(command) - 1))

            elif mutation_type == "invalid_type":
                command[random.randint(0, len(command) - 1)] = "invalid"

            elif mutation_type == "boundary_value":
                for i in range(len(command)):
                    if random.random() < 0.4:
                        command[i] = random.choice([0x00, 0xFF, 0x7F, 0x80])

            return command
    
    def is_interesting(self, target, test_input, result):
        """Determine if a result is interesting for the specified target"""
        if target == 'django':
            if not result.get('response'):
                return True
            if result.get('response').status_code >= 400:
                return True
            if random.random() < 0.1:  # Sometimes consider responses interesting to diversify
                return True
            return False
            
        elif target == 'ble':
            seed = test_input
            res = result.get('response')
            log_line = result.get('log_line', '')
            
            expected = seed.get("to_state")
            if not res or not isinstance(res, list):
                return True
            if expected == "error" and res[0] == 0x00:
                return True
            if expected and expected.lower() not in log_line.lower():
                return True
            if "[Error]" in log_line or "Guru Meditation" in log_line:
                return True
            return False
    
    def save_results(self, target):
        """Save results for the specified target"""
        if target == 'django':
            self._save_django_results()
        elif target == 'ble':
            self._save_ble_results()
    
    async def run(self):
        """Run the fuzzing process for selected targets"""
        print(f"Starting unified fuzzing with target: {self.config['target']}")
        start_time = time.time()
        
        if self.config['target'] in ['django', 'both']:
            print("\n==== STARTING DJANGO FUZZING ====")
            await self.run_django_fuzzing()
            
        if self.config['target'] in ['ble', 'both']:
            print("\n==== STARTING BLE FUZZING ====")
            await self.run_ble_fuzzing()
            
        total_time = time.time() - start_time
        print(f"\nFuzzing completed in {total_time:.2f} seconds")
        
        # Summarize and save results
        self.summarize_results()
    
    def summarize_results(self):
        """Summarize the fuzzing results"""
        print("\n=== Fuzzing Results Summary ===")
        
        if self.config['target'] in ['django', 'both']:
            django_results = self.results['django']
            print(f"\nDjango Fuzzing:")
            print(f"  Total test cases: {django_results['total_tests']}")
            print(f"  Crashes/Errors: {django_results['crashes']}")
            print(f"  Unique issues: {django_results['unique_issues']}")
            
        if self.config['target'] in ['ble', 'both']:
            ble_results = self.results['ble']
            print(f"\nBLE Fuzzing:")
            print(f"  Total test cases: {ble_results['total_tests']}")
            print(f"  Interesting behaviors: {ble_results['crashes']}")
            print(f"  Unique issues: {ble_results['unique_issues']}")
        
        # Save combined results
        combined_results_path = os.path.join(self.output_dir, 'combined_results.json')
        with open(combined_results_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nCombined results saved to {combined_results_path}")
    
    #------ Django Specific Methods ------#
    
    def init_django_coverage(self):

        if not COVERAGE_AVAILABLE:
            print("Coverage module not available. Coverage tracking disabled.")
            return False
            
        if not self.config['enable_coverage']:
            print("Coverage tracking disabled in configuration.")
            return False
            
        try:
            self.django_coverage = coverage_module.Coverage(
                source=self.config['coverage_source'],
                branch=True
            )
            self.django_coverage.start()
            print("Django coverage tracking started")
            return True
        except Exception as e:
            print(f"Error starting coverage: {e}")
            self.django_coverage = None
            return False
    
    def finalize_django_coverage(self):
        """Finalize coverage tracking and generate report"""
        if self.django_coverage:
            try:
                self.django_coverage.stop()
                self.django_coverage.save()
                
                print("\nDjango Coverage Report:")
                self.django_coverage.report()
                
                # Generate HTML report
                html_dir = os.path.join(self.django_output_dir, "coverage_html")
                self.django_coverage.html_report(directory=html_dir)
                print(f"HTML coverage report saved to {html_dir}")
                
                # Clean up
                self.django_coverage.erase()
            except Exception as e:
                print(f"Error generating coverage report: {e}")

    def django_safe_json_serialize(self, obj):
        """Ensure inputs are in the correct JSON format for Django"""
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, float) and (obj != obj):  # NaN check
            return "NaN"
        if obj is None:
            return None  # Keep None as None, don't convert to string
        if isinstance(obj, (dict, list, int, float, bool)):
            return obj  # Keep native JSON types as they are
        return str(obj)  # Convert everything else to string
    
    async def django_execute_test(self, test_input):
        """Send a mutated input to the Django application"""
        self.django_request_counter += 1
        request_id = self.django_request_counter
        
        try:
            # Remove the mutation tracking field before sending
            send_input = test_input.copy()
            mutation_type = send_input.pop('_mutation_type', 'unknown')
            
            # First, properly serialize the input for JSON
            serializable_input = {k: self.django_safe_json_serialize(v) for k, v in send_input.items()}
            
            # Debug log of the actual data being sent
            print(f"\n=== DJANGO REQUEST #{request_id} ({mutation_type}) ===")
            endpoint_url = "add/"  # From original code
            url = self.config['django_url'] + endpoint_url
            print(f"URL: {url}")
            print(f"Data: {json.dumps(serializable_input, default=str)}")
            
            # Headers from original code
            headers = {
                'Content-Type': 'application/json',
                'Cookie': 'csrftoken=VALID_CSRF_TOKEN; sessionid=VALID_SESSION_ID',
            }
            
            # Make the actual request
            start_time = time.time()
            response = requests.post(
                url, 
                headers=headers, 
                json=serializable_input,
                timeout=10   # Timeout for crash detection
            )
            elapsed = time.time() - start_time
            
            # Log the complete response
            print(f"=== DJANGO RESPONSE #{request_id} ===")
            print(f"Status: {response.status_code}")
            print(f"Time: {elapsed:.2f}s")
            print(f"Headers: {dict(response.headers)}")
            print(f"Content: {response.text[:200]}")
            if len(response.text) > 200:
                print("...")
                
            # Check for error responses
            if response.status_code >= 400:
                self.django_error_counter += 1
                print(f"⚠️ ERROR DETECTED: Status {response.status_code}")

                if "<html" in response.text.lower():
                    if "request body exceeded" in response.text.lower():
                        simplified_error_message = "Memory error: request data too large"
                    else:
                        simplified_error_message = "Error response in HTML format - details omitted"
                else:
                    simplified_error_message = response.text
                
                # Add to failure queue
                failure_record = {
                    'input': serializable_input,
                    'status_code': response.status_code,
                    'response': simplified_error_message,
                    'mutation_type': mutation_type,
                    'request_id': request_id,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                self.django_failure_queue.append(failure_record)
                
                # Track failures by type
                if mutation_type not in self.django_failure_types:
                    self.django_failure_types[mutation_type] = 0
                self.django_failure_types[mutation_type] += 1
                
                print(f"Added to Django failure queue: {mutation_type} ({response.status_code})")
            else:
                self.django_success_counter += 1
                
            return {
                'response': response,
                'mutation_type': mutation_type,
                'request_id': request_id,
                'elapsed': elapsed,
                'serialized_input': serializable_input
            }
        
        except requests.exceptions.Timeout as e:
            print(f"⏰ DJANGO REQUEST TIMEOUT: No response in time for request #{request_id}")
            print(traceback.format_exc())

            failure_record = {
                'input': {k: str(v) for k, v in send_input.items()},
                'status_code': 'timeout',
                'response': 'No response - timeout occurred',
                'mutation_type': mutation_type,
                'request_id': request_id,
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e)
            }

            self.django_failure_queue.append(failure_record)
            self.django_error_counter += 1

            print(f"Added to Django failure queue: Timeout - {mutation_type}")
            return {
                'response': None,
                'mutation_type': mutation_type,
                'request_id': request_id,
                'elapsed': 10,  # assume full timeout used
                'error': 'timeout',
                'serialized_input': {k: str(v) for k, v in send_input.items()}
            }
            
        except Exception as e:
            print(f"⚠️ DJANGO REQUEST FAILED: {str(e)}")
            print(traceback.format_exc())
            
            # Add exception failures to the queue as well
            failure_record = {
                'input': {k: str(v) for k, v in send_input.items()},
                'status_code': 'exception',
                'response': str(e),
                'mutation_type': mutation_type,
                'request_id': request_id,
                'timestamp': datetime.datetime.now().isoformat(),
                'error': str(e)
            }
            
            self.django_failure_queue.append(failure_record)
            self.django_error_counter += 1
            
            print(f"Added to Django failure queue: Exception - {mutation_type}")
            
            return {
                'response': None,
                'mutation_type': mutation_type,
                'request_id': request_id,
                'elapsed': 0,
                'error': str(e),
                'serialized_input': {k: str(v) for k, v in send_input.items()}
            }
    
    def _save_django_results(self):
        """Save Django fuzzing results to files"""
        failure_file = os.path.join(self.django_output_dir, "failures.json")
        
        if self.django_failure_queue:
            print(f"\nSaving {len(self.django_failure_queue)} Django failures to file.")
            
            # Save all failures to the main failure file
            with open(failure_file, 'w') as f:
                json.dump(self.django_failure_queue, f, indent=2, default=str)
            
            # Also save categorized failures by mutation type
            by_type_dir = os.path.join(self.django_output_dir, "by_type")
            os.makedirs(by_type_dir, exist_ok=True)
            
            failures_by_type = {}
            for failure in self.django_failure_queue:
                mutation_type = failure.get('mutation_type', 'unknown')
                if mutation_type not in failures_by_type:
                    failures_by_type[mutation_type] = []
                failures_by_type[mutation_type].append(failure)
            
            for mutation_type, failures in failures_by_type.items():
                type_file = os.path.join(by_type_dir, f"{mutation_type}_failures.json")
                with open(type_file, 'w') as f:
                    json.dump(failures, f, indent=2, default=str)
            
            # Generate a summary report
            summary_file = os.path.join(self.django_output_dir, "summary.txt")
            with open(summary_file, 'w') as f:
                f.write(f"Django Fuzzing Summary Report\n")
                f.write(f"===========================\n")
                f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
                f.write(f"Total Requests: {self.django_request_counter}\n")
                f.write(f"Successful Responses: {self.django_success_counter}\n")
                f.write(f"Error Responses: {self.django_error_counter}\n")
                f.write(f"Failures Collected: {len(self.django_failure_queue)}\n\n")
                
                f.write("Failures by type:\n")
                for mutation_type, count in self.django_failure_types.items():
                    f.write(f"  {mutation_type}: {count} failures\n")
                
                f.write("\nStatus Code Distribution:\n")
                status_counts = {}
                for failure in self.django_failure_queue:
                    status = str(failure.get('status_code', 'unknown'))
                    if status not in status_counts:
                        status_counts[status] = 0
                    status_counts[status] += 1
                
                for status, count in sorted(status_counts.items(), key=lambda x: str(x[0])):
                    f.write(f"  {status}: {count} occurrences\n")
                
                # Include most common failure patterns
                if self.django_failure_queue:
                    f.write("\nSample Failures:\n")
                    for i, failure in enumerate(self.django_failure_queue[:5]):
                        f.write(f"\n--- Failure #{i+1} ---\n")
                        f.write(f"Mutation: {failure.get('mutation_type')}\n")
                        f.write(f"Status: {failure.get('status_code')}\n")
                        f.write(f"Input: {json.dumps(failure.get('input'), indent=2)}\n")
                        response_text = failure.get('response', '')
                        if len(response_text) > 200:
                            response_text = response_text[:200] + "..."
                        f.write(f"Response: {response_text}\n")
            
            print(f"Django failures saved in {failure_file}")
            print(f"Django summary report saved in {summary_file}")
        else:
            print("No Django failures to save.")
        
        # Update results for the unified report
        self.results['django']['total_tests'] = self.django_request_counter
        self.results['django']['crashes'] = self.django_error_counter
        self.results['django']['unique_issues'] = len(self.django_failure_types)
    
    async def run_django_fuzzing(self):
        """Run the Django fuzzing campaign"""
        # Initialize coverage tracking
        coverage_enabled = self.init_django_coverage()

        self.load_seeds('django')
        energy = self.assign_energy('django')
        iteration = 0
        max_iterations = self.config['iterations']
        
        print(f"\n{'=' * 60}")
        print(f"STARTING DJANGO FUZZING SESSION: {datetime.datetime.now()}")
        print(f"Base URL: {self.config['django_url']}")
        print(f"Max iterations: {max_iterations}")
        print(f"Energy per input: {energy}")
        print(f"Coverage tracking: {'Enabled' if coverage_enabled else 'Disabled'}")
        print(f"{'=' * 60}\n")
        
        try:
            while iteration < max_iterations and (self.django_seed_queue or iteration == 0):
                test_input = self.choose_next('django')
                
                print(f"\n--- Django Iteration {iteration+1}/{max_iterations} ---")
                print(f"Seed input: {json.dumps(test_input, default=str)}")
                
                for energy_level in range(energy):
                    try:
                        mutated_input = self.mutate_input('django', test_input)
                        result = await self.django_execute_test(mutated_input)
                        
                        if not result.get('response'):
                            print(f"Django request failed: {result.get('error', 'Unknown error')}")
                            continue
                            
                        # Short pause to avoid overwhelming the server
                        await asyncio.sleep(0.2)

                        if self.is_interesting('django', mutated_input, result):
                            self.django_seed_queue.append(mutated_input)
                            print(f"Found interesting Django input: {json.dumps(mutated_input, default=str)}")
                    
                    except Exception as e:
                        print(f"Error during Django fuzzing: {e}")
                        print(traceback.format_exc())
                        
                iteration += 1
                
                # Save failures incrementally to avoid losing data
                if len(self.django_failure_queue) % 5 == 0 and self.django_failure_queue:
                    print("Saving Django failures incrementally...")
                    self.save_results('django')
        
        except KeyboardInterrupt:
            print("\nDjango fuzzing interrupted by user. Saving results...")
        
        finally:
            # Print summary at the end
            print("\n" + "=" * 60)
            print(f"DJANGO FUZZING SESSION COMPLETE: {datetime.datetime.now()}")
            print(f"Total requests: {self.django_request_counter}")
            print(f"Successful responses: {self.django_success_counter}")
            print(f"Error responses: {self.django_error_counter}")
            print(f"Failures collected: {len(self.django_failure_queue)}")
            
            # Print failure types summary
            if self.django_failure_types:
                print("\nDjango failure types summary:")
                for mutation_type, count in self.django_failure_types.items():
                    print(f"  {mutation_type}: {count} failures")
            
            # Save all failures to files
            self.save_results('django')

            # Generate coverage report
            if coverage_enabled:
                self.finalize_django_coverage()
    
    #------ BLE Specific Methods ------#
    
    async def ble_execute_test(self, command):
        """Send command and collect BLE + log response"""
        self.ble_test_counter += 1
        
        try:
            print(f"[!] --> Command:  {command}")
            res = await self.ble_client.write_command(command)
            await asyncio.sleep(0)  # No delay between commands

            # Get logs
            logs = self.ble_client.read_logs()
            last_line = logs[-1] if logs else "[!] No logs"

            # Print response
            print(f"[!] <--  Response: {res}")
            print (f"[BLE Response]: {res}")
            print (f"[Device Log]: {last_line}")

            return {
                'response': res,
                'log_line': last_line,
                'all_logs': logs
            }
        except Exception as e:
            error_message = f"[!] Exception: {e}"
            print(error_message)
            return {
                'response': None,
                'log_line': error_message,
                'error': str(e),
                'all_logs': []
            }
    
    async def ble_handle_crash(self):
        """Handle BLE device crash with reconnection"""
        print("[*] Reconnecting BLE after crash...")
        try:
            await self.ble_client.disconnect()
        except:
            pass
        await asyncio.sleep(1.5)
        try:
            await self.ble_client.connect(self.config['ble_device'])
            return True
        except Exception as e:
            print(f"[X] BLE reconnect failed: {e}")
            return False
    
    def _save_ble_results(self):
        """Save BLE fuzzing results"""
        # Create result summary
        ble_results = {
            'total_tests': self.ble_test_counter,
            'interesting_behaviors': self.ble_interesting_behaviors,
            'unique_issues': len(self.ble_interesting_count),
            'seeds_triggered': [
                {'seed': json.loads(seed), 'count': count}
                for seed, count in self.ble_interesting_count.items()
            ]
        }
        
        # Save to file
        ble_results_path = os.path.join(self.ble_output_dir, 'ble_results.json')
        with open(ble_results_path, 'w') as f:
            json.dump(ble_results, f, indent=2, default=str)
        
        # Generate a summary report
        summary_file = os.path.join(self.ble_output_dir, "summary.txt")
        with open(summary_file, 'w') as f:
            f.write(f"BLE Fuzzing Summary Report\n")
            f.write(f"==========================\n")
            f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
            f.write(f"Total Tests: {self.ble_test_counter}\n")
            f.write(f"Interesting Behaviors: {self.ble_interesting_behaviors}\n")
            f.write(f"Unique Issues: {len(self.ble_interesting_count)}\n\n")
            
            f.write("Seeds that triggered interesting behavior:\n")
            for i, (seed_json, count) in enumerate(self.ble_interesting_count.items()):
                seed = json.loads(seed_json)
                f.write(f"\n--- Seed #{i+1} (triggered {count} times) ---\n")
                f.write(f"From state: {seed.get('from_state', 'unknown')}\n")
                f.write(f"To state: {seed.get('to_state', 'unknown')}\n")
                f.write(f"Command: {seed.get('command', [])}\n")
    
        print(f"BLE results saved in {ble_results_path}")
        print(f"BLE summary report saved in {summary_file}")
    
        # Update results for the unified report
        self.results['ble']['total_tests'] = self.ble_test_counter
        self.results['ble']['crashes'] = self.ble_interesting_behaviors
        self.results['ble']['unique_issues'] = len(self.ble_interesting_count)

    async def run_ble_fuzzing(self):
        """Run the BLE fuzzing campaign"""
        if not BLE_AVAILABLE:
            print("BLE fuzzing disabled due to missing components")
            return
            
        # Load seeds
        try:
            with open(self.config['ble_input'], 'r') as f:
                self.ble_seeds = json.load(f)
                print(f"[+] Loaded {len(self.ble_seeds)} seeds from {self.config['ble_input']}")
        except Exception as e:
            print(f"[X] Failed to load seed file: {e}")
            self.ble_seeds = []

            if not self.ble_seeds:
                self.ble_seeds = [
                    {
                        "from_state": "any",
                        "to_state": "Locked",
                        "command": [0x00, 0x01, 0x02, 0x03, 0x04, 0x05]
                    },
                    {
                        "from_state": "Authenticated",
                        "to_state": "Unlocked",
                        "command": [0x01]
                    }
                ]

        # Initialize BLE client
        self.ble_client = BLEClient()
        self.ble_client.init_logs()

        print(f"[*] Connecting to {self.config['ble_device']}...")
        try:
            await self.ble_client.connect(self.config['ble_device'])
        except Exception as e :
            print(f"[!] Initial connection failed: {e}")
            return
        
        try:
            # Same number of seed cycles as original
            for _ in range(20):
                candidates = [s for s in self.ble_seeds if s["from_state"] == self.ble_state or s["from_state"] == "any"]
                seed = random.choice(candidates) if candidates else random.choice(self.ble_seeds)

                # Calculate energy
                base = 5
                bonus = min(self.ble_interesting_count[json.dumps(seed)], 7)
                energy = base + bonus + random.randint(0, 3)

                print(f"[*] Fuzzing with energy = {energy} from state: {self.ble_state}")

                for _ in range(energy):
                    # Mutate input using original strategy
                    mutation_type = random.choice(["bit_flip", "remove_field", "invalid_type", "boundary_value"])
                    command = seed["command"].copy()

                    if mutation_type == "bit_flip" and command:
                        idx = random.randint(0, len(command) - 1)
                        bit = 1 << random.randint(0, 7)
                        command[idx] ^= bit
                    elif mutation_type == "remove_field" and len(command) > 1:
                        command.pop(random.randint(0, len(command) - 1))
                    elif mutation_type == "invalid_type":
                        command[random.randint(0, len(command) - 1)] = "invalid"
                    elif mutation_type == "boundary_value":
                        for i in range(len(command)):
                            if random.random() < 0.4:
                                command[i] = random.choice([0x00, 0xFF, 0x7F, 0x80])
                    
                    # Execute test
                    print(f"\n[>] BLE Test #{self.ble_test_counter+1}: Sending: {command}")
                    result = await self.ble_execute_test(command)

                    res = result.get('response')
                    last_log = result.get('log_line', '')

                    # Check for interesting behavior 
                    if self.is_interesting('ble', seed, result):
                        print("[!!] Interesting behavior detected!")
                        self.ble_interesting_count[json.dumps(seed)] += 1
                        self.ble_interesting_behaviors += 1

                    # Update state                    
                    if "Authenticated" in last_log:
                        self.ble_state = "Authenticated"
                    elif "Unlocked" in last_log or "Lock mechanism open" in last_log:
                        self.ble_state = "Unlocked"
                    elif "Locked" in last_log or "Lock mechanism closed" in last_log:
                        self.ble_state = "Locked"
                    
                    # Handle device crash
                    if "[!] Exception:" in last_log:
                        print("[*] Reconnecting after crash...")
                        try:
                            await self.ble_client.disconnect()
                        except:
                            pass
                        await asyncio.sleep(1.5)
                        try:
                            await self.ble_client.connect(self.config['ble_device'])
                        except Exception as e:
                            print(f"[X] Reconnect failed: {e}")
                            continue
        except KeyboardInterrupt:
                        print("\nBLE fuzzing interrupted by user. Saving results...")
        finally:
                        # Disconnect and show logs
                        print("\n[*] Disconnecting...")
                        try:
                            await self.ble_client.disconnect()
                        except Exception as e:
                            print(f"Error disconnecting: {e}")
                        
                        print("[*] Final Logs:")
                        try:
                            for line in self.ble_client.read_logs():
                                print(line)
                        except Exception as e:
                            print(f"Error reading logs: {e}")

                        # Save BLE results
                        self.save_results('ble')
        


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Unified Fuzzer for Django and BLE applications")
    parser.add_argument('--target', choices=['django', 'ble', 'both'], default='both',
                       help='Target to fuzz: django, ble, or both')
    parser.add_argument('--iterations', type=int, default=100,
                       help='Number of fuzzing iterations to run')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout in seconds for each fuzzing iteration')
    parser.add_argument('--output', type=str, default='fuzzing_results',
                       help='Directory to store fuzzing results')
    parser.add_argument('--django-url', type=str, default='http://127.0.0.1:8000/datatb/product/',
                       help='Base URL of the Django application to fuzz')
    parser.add_argument('--ble-device', type=str, default='Smart Lock [Group 2]',
                       help='BLE device name to connect to')
    parser.add_argument('--django-input', type=str, default='Django/input.json',
                       help='Path to Django input seeds file')
    parser.add_argument('--ble-input', type=str, default='Input1.json',
                       help='Path to BLE input seeds file')
    
    return parser.parse_args()


async def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Create configuration from arguments
    config = {
        'target': args.target,
        'iterations': args.iterations,
        'timeout': args.timeout,
        'output_dir': args.output,
        'django_url': args.django_url,
        'ble_device': args.ble_device,
        'django_input': args.django_input,
        'ble_input': args.ble_input
    }
    
    # Create and run the unified fuzzer
    fuzzer = UnifiedFuzzer(config)
    await fuzzer.run()


if __name__ == "__main__":
    asyncio.run(main())
