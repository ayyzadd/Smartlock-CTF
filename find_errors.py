#!/usr/bin/env python3
import sys
import asyncio
import json
import os
from BLEClient import BLEClient

DEVICE_NAME = "Smart Lock [Group 2]"

async def test_vulnerabilities():
    # Load your 99 interesting inputs
    results_dirs = [d for d in os.listdir('.') if d.startswith('fuzzing_results_')]
    if not results_dirs:
        print("No fuzzing results found!")
        return
    
    latest_dir = max(results_dirs)
    failure_file = os.path.join(latest_dir, "failures.json")
    
    with open(failure_file, 'r') as f:
        interesting_inputs = json.load(f)
    
    print(f"Loaded {len(interesting_inputs)} interesting inputs to test")
    
    # Connect to the device
    ble = BLEClient()
    ble.init_logs()
    
    print(f"[*] Connecting to {DEVICE_NAME}...")
    await ble.connect(DEVICE_NAME)
    
    # Create a file to store error codes
    error_file = "found_error_codes.txt"
    
    # Test each input
    for i, test_input in enumerate(interesting_inputs):
        print(f"\n[*] Testing input {i+1}/{len(interesting_inputs)}")
        
        # Extract command
        command = test_input["command"]
        name = test_input.get("name", "unnamed")
        
        print(f"[*] Testing: {name}")
        command_hex = " ".join([f"0x{b:02X}" for b in command])
        print(f"[*] Command: {command_hex}")
        
        # Get logs before command
        prev_logs = ble.read_logs()
        
        # Send the command
        try:
            response = await ble.write_command(command)
            
            # Get new logs
            current_logs = ble.read_logs()
            new_logs = current_logs[len(prev_logs):] if len(current_logs) > len(prev_logs) else []
            
            # Check for error codes
            for log in new_logs:
                if "[Error] Code:" in log:
                    error_code = log.split("[Error] Code:")[1].strip()
                    print(f"\n[!!!] FOUND ERROR CODE: {error_code}")
                    print(f"[!!!] Command that triggered it: {command_hex}")
                    print(f"[!!!] Test name: {name}")
                    
                    # Save to file
                    with open(error_file, "a") as f:
                        f.write(f"Error Code: {error_code}\n")
                        f.write(f"Command: {command_hex}\n")
                        f.write(f"Test: {name}\n")
                        f.write("Logs:\n")
                        for log_line in new_logs:
                            f.write(f"  {log_line}\n")
                        f.write("\n---\n\n")
            
            # Wait a bit between tests
            await asyncio.sleep(1)
            
        except Exception as e:
            print(f"[X] Error: {e}")
            
            # Try to reconnect if we lost connection
            try:
                await ble.disconnect()
                await asyncio.sleep(2)
                await ble.connect(DEVICE_NAME)
            except:
                print("[X] Could not reconnect. Exiting.")
                break
    
    # Disconnect when done
    await ble.disconnect()
    print("\nTesting complete. Check found_error_codes.txt for results.")

if __name__ == "__main__":
    try:
        asyncio.run(test_vulnerabilities())
    except KeyboardInterrupt:
        print("\nTesting interrupted by user!")