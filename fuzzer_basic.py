import random
import json
import os
import datetime
import sys
import traceback

# Generalised class with methods whose implementation can be customised for each target application:
class DjangoEndpointFuzzer:
    def __init__(self, input_file='input1.json', application='BLE'):
        # Common to both applications:
        self.seed_queue = []
        self.failure_queue = []
        self.create_output_dir()
        self.application = application  # Store the application type
        self.authenticated = False  # For BLE state tracking
        self.ble_client = None
        
        # For Django:
        if application == 'Django':
            self.base_url = 'http://127.0.0.1:8000/datatb/product/'
            self.endpoint_url = 'add/'
            self.url = self.base_url + self.endpoint_url
            self.headers = {
                'Content-Type': 'application/json',
                'Cookie': 'csrftoken=VALID_CSRF_TOKEN; sessionid=VALID_SESSION_ID',
            }
            
        # For BLE Smartlock:
        elif application == 'BLE':
            # BLE specific initialization
            self.device_name = "Smart Lock [Group 2]"  # Default device name
            
            # Define known commands for BLE Smartlock
            self.AUTH = [0x00]  # Authentication command (needs 6-byte passcode)
            self.OPEN = [0x01]  # Open command
            self.CLOSE = [0x02]  # Close command
            self.VALID_PASSCODE = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]  # Valid passcode from Smartlock.py
            
            # Expected response codes
            self.RESP_SUCCESS = 0x00
            self.RESP_AUTH_FAIL = 0x01
            self.RESP_INVALID_CMD = 0x02
            self.RESP_NOT_ALLOWED = 0x03
            self.RESP_LOCK_ERROR = 0x04
        
        # Load seeds from the input file
        self.load_seeds(input_file)
    
    # Load the seed input from the input file to the seed queue:
    def load_seeds(self, input_file):
        try:
            print(f"[*] Loading seeds from {input_file}...")
            with open(input_file, 'r') as f:
                seeds = json.load(f)
                self.seed_queue.extend(seeds)
                
            print(f"[*] Loaded {len(self.seed_queue)} seeds from {input_file}")
        except Exception as e:
            print(f"Error loading seeds: {e}")
    
    # To ensure that the inputs are sent in the correct json format:
    def safe_json_serialize(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        if isinstance(obj, (set, frozenset)):
            return list(obj)
        if isinstance(obj, list) and all(isinstance(x, int) for x in obj):
            return [x for x in obj]  # Return the list as is for BLE commands
        return str(obj)
    
    # ChooseNext():
    def chooseNext(self):
        # FIFO approach:
        if not self.seed_queue:
            return None
        return self.seed_queue.pop(0)
    
    # Assign energy:
    def assign_energy(self):
        return 10  # Some constant value

    # Mutate input():
    def mutate_input(self, test_input):
        mutated = test_input.copy()  # Make a copy to avoid modifying the original input

        # If BLE, use BLE-specific mutations
        if self.application == "BLE":
            return self.mutate_ble_input(test_input)
        
        # Django mutations
        mutation_type = random.choice(["flip_char", "remove_field", "invalid_type", "boundary_value"])

        if mutation_type == "flip_char":
            # Django: Flip a character in "name" or "info"
            field = random.choice(["name", "info"])
            if field in mutated:
                chars = list(mutated[field])
                if chars:
                    pos = random.randint(0, len(chars) - 1)
                    chars[pos] = random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
                    mutated[field] = "".join(chars)

        elif mutation_type == "remove_field":
            # Django only: Remove a field
            field = random.choice(["name", "info", "price"])
            mutated.pop(field, None)

        elif mutation_type == "invalid_type":
            # Django only: Replace a field with an invalid type
            field = random.choice(["name", "info", "price"])
            invalid_values = [None, [], {}, True, "".encode("utf-8"), set([1, 2, 3]), (1, 2, 3)]
            mutated[field] = random.choice(invalid_values)

        elif mutation_type == "boundary_value":
            # Django: Set price to extreme values
            mutated["price"] = random.choice([-1, 0, 2**31 - 1, 2**31, float("inf"), float("-inf"), float("nan")])

        return mutated
    
    # BLE-specific mutation strategies
    def mutate_ble_input(self, test_input):
        mutated = test_input.copy()
        if "command" in mutated and isinstance(mutated["command"], list):
            command = mutated["command"].copy()
        else:
            command = []
            
        # Select mutation strategy
        mutation_type = random.choice([
            'bit_flip', 
            'byte_change',
            'length_change',
            'boundary_value',
            'command_swap'
        ])
        
        # Apply mutation
        if mutation_type == 'bit_flip' and command:
            # Flip random bits in the command
            byte_idx = random.randint(0, len(command) - 1)
            bit_idx = random.randint(0, 7)
            command[byte_idx] ^= (1 << bit_idx)  # Flip the bit
            mutated["command"] = command
        
        elif mutation_type == 'byte_change' and command:
            # Change a byte to a random value
            byte_idx = random.randint(0, len(command) - 1)
            command[byte_idx] = random.randint(0, 255)
            mutated["command"] = command
            
        elif mutation_type == 'length_change':
            if random.random() < 0.5 and command:
                # Truncate the command
                truncate_to = random.randint(1, len(command)) if len(command) > 1 else 1
                command = command[:truncate_to]
                mutated["command"] = command
            else:
                # Extend the command with random bytes
                extra_bytes = [random.randint(0, 255) for _ in range(random.randint(1, 5))]
                command.extend(extra_bytes)
                mutated["command"] = command
                
        elif mutation_type == 'boundary_value' and command:
            # Replace bytes with boundary values
            for i in range(len(command)):
                if random.random() < 0.3:  # 30% chance to change each byte
                    command[i] = random.choice([0x00, 0x01, 0x7F, 0x80, 0xFF])
            mutated["command"] = command
            
        elif mutation_type == 'command_swap' and command and len(command) > 0:
            # Change the command code (first byte) to another command
            if len(command) > 0:
                # Either use a known command or a random value
                if random.random() < 0.7:  # 70% chance to use known command
                    command[0] = random.choice([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
                else:
                    command[0] = random.randint(0, 255)
                mutated["command"] = command
        
        return mutated
    
    # For BLE, we need to simulate the responses
    def execute_test(self, test_input):
        if self.application == 'BLE':
            # Since we can't actually connect to BLE without async code,
            # we'll simulate some basic responses for the test_driver
            command = test_input.get("command", [])
            if not command:
                return None
                
            # Simulate responses based on command type
            if command[0] == self.AUTH[0]:  # Authentication
                # Check if passcode is valid
                if len(command) > 6 and command[1:7] == self.VALID_PASSCODE:
                    self.authenticated = True
                    return [self.RESP_SUCCESS]  # Success
                else:
                    return [self.RESP_AUTH_FAIL]  # Auth failed
                    
            elif command[0] == self.OPEN[0] or command[0] == self.CLOSE[0]:  # Open/Close
                if self.authenticated:
                    return [self.RESP_SUCCESS]  # Success
                else:
                    return [self.RESP_NOT_ALLOWED]  # Not allowed
                    
            elif command[0] >= 0x03:  # Unknown command
                return [self.RESP_INVALID_CMD]  # Invalid command
                
            # Other responses
            return [random.choice([self.RESP_SUCCESS, self.RESP_INVALID_CMD, self.RESP_NOT_ALLOWED])]
            
        else:  # Django
            try:
                import requests  # Import here to avoid dependency issues
                serializable_input = {k: self.safe_json_serialize(v) for k, v in test_input.items()}
                response = requests.post(self.url, headers=self.headers, json=serializable_input, timeout=5)
                return response
            except Exception as e:
                print(f"Request failed: {e}")
                return None
    
    # Check if the test result is interesting (for BLE simulated)
    def is_interesting(self, response, test_input):
        if self.application == 'BLE':
            if not response:
                return True  # No response is interesting
                
            test_name = test_input.get("name", "")
            command = test_input.get("command", [])
            command_type = command[0] if command and len(command) > 0 else None
            
            # Authentication with invalid passcode should fail
            if test_name.startswith(("invalid_passcode", "short_passcode", "long_passcode")):
                if response[0] != self.RESP_AUTH_FAIL:
                    return True
                    
            # Unknown commands should be invalid
            if "unknown" in test_name.lower() or (command_type is not None and command_type >= 0x03):
                if response[0] != self.RESP_INVALID_CMD:
                    return True
                    
            # Open/close without auth should be disallowed
            if command_type in [self.OPEN[0], self.CLOSE[0]] and not self.authenticated:
                if response[0] != self.RESP_NOT_ALLOWED:
                    return True
                    
            # Unexpected response codes
            if response[0] >= 0x05:
                return True
                
            # Random chance to consider interesting (simulates fuzzing randomness)
            if random.random() < 0.05:  # 5% chance
                return True
                
            return False
            
        else:  # Django
            # Since we're not using coverage, we'll say all 500 errors are interesting
            return response and response.status_code >= 500
    
    # Main fuzzing loop - simulated for BLE
    def fuzz(self, max_iterations=10):
        print(f"[*] Starting fuzzing for {self.application} application")
        
        energy = self.assign_energy()
        iteration = 0
        
        try:
            while iteration < max_iterations and self.seed_queue:
                test_input = self.chooseNext()
                for _ in range(energy):
                    try:
                        mutated_input = self.mutate_input(test_input)
                        serializable_input = {k: self.safe_json_serialize(v) for k, v in mutated_input.items()}
                        print(f"Trying input: {json.dumps(serializable_input, indent=2)}")
                        
                        response = self.execute_test(mutated_input)
                        
                        # For BLE, check if it's interesting
                        if self.application == 'BLE' and self.is_interesting(response, mutated_input):
                            self.failure_queue.append(mutated_input)
                            self.seed_queue.append(mutated_input)
                            print(f"Found interesting BLE input: {json.dumps(serializable_input, indent=2)}")
                        
                        # For Django
                        elif self.application == 'Django':
                            # Detect crashes
                            if response and response.status_code >= 500:
                                print(f"Found crash with input: {json.dumps(serializable_input, indent=2)}")
                                self.failure_queue.append(serializable_input)
                                
                            # Check if interesting
                            if response and self.is_interesting(response, mutated_input):
                                self.seed_queue.append(mutated_input)
                                print(f"Found interesting Django input: {json.dumps(serializable_input, indent=2)}")
                    
                    except Exception as e:
                        print(f"Error during fuzzing iteration: {e}")
                
                iteration += 1
        
        except KeyboardInterrupt:
            print("\n[*] Fuzzing interrupted by user")
        except Exception as e:
            print(f"[X] Error during fuzzing: {str(e)}")
            traceback.print_exc()
        
        # Save failures to file
        self.save_failures()
        
        print("\n Coverage Report:")
        print(f"Total findings: {len(self.failure_queue)}")
        print("Failure Queue: ", self.failure_queue)
        
        return self.failure_queue
    
    # Save failures to file:
    def save_failures(self):
        if self.failure_queue:
            with open(self.failure_file, 'w') as f:
                json.dump(self.failure_queue, f, indent=2)
            print(f"Failures saved in {self.failure_file}")
    
    # Create the output dir to store the failure test cases for reproducibility:
    def create_output_dir(self):
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_dir = f"fuzzing_results_{timestamp}"
        os.makedirs(self.output_dir, exist_ok=True)
        self.failure_file = os.path.join(self.output_dir, "failures.json")
        print(f"[*] Created output directory: {self.output_dir}")