import sys
import json
import asyncio
import random
from collections import defaultdict
from BLEClient import BLEClient
from UserInterface import ShowUserInterface

DEVICE_NAME = "Smart Lock [Group 2]"
STATE = "Locked"
SEED_FILE = "Input1.json"

# Track interesting counts per seed
interesting_count = defaultdict(int)

# Load seeds from JSON
def load_seeds(filename):
    try:
        with open(filename, "r") as f:
            seeds = json.load(f)
            print(f"[+] Loaded {len(seeds)} seeds from {filename}")
            return seeds
    except Exception as e:
        print(f"[X] Failed to load seed file: {e}")
        return []

# Choose a valid next seed based on current state
def choose_next(seeds, current_state):
    candidates = [s for s in seeds if s["from_state"] == current_state or s["from_state"] == "any"]
    return random.choice(candidates) if candidates else random.choice(seeds)

# Prioritize energy based on seed interest
def assign_energy(seed):
    base = 5
    bonus = min(interesting_count[json.dumps(seed)], 7)
    return base + bonus + random.randint(0, 3)

# Mutate input with multiple strategies
def mutate_input(seed):
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

# Send command and collect BLE + log response
async def execute_test(ble, command):
    try:
        print(f"[!] --> Command:  {command}")
        res = await ble.write_command(command)
        await asyncio.sleep(0)  # No delay between commands
        logs = ble.read_logs()
        last_line = logs[-1] if logs else "[!] No logs"
        print(f"[!] <-- Response: {res}")
        return res, last_line
    except Exception as e:
        return None, f"[!] Exception: {e}"

# Determine if behavior is interesting
def is_interesting(seed, res, log_line):
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

# Fuzzing loop
async def fuzzer():
    global STATE
    seeds = load_seeds(SEED_FILE)
    ble = BLEClient()
    ble.init_logs()

    print(f"[*] Connecting to {DEVICE_NAME}...")
    try:
        await ble.connect(DEVICE_NAME)
    except Exception as e:
        print(f"[!] Initial connection failed: {e}")
        return

    try:
        for _ in range(20):
            seed = choose_next(seeds, STATE)
            energy = assign_energy(seed)
            print(f"[*] Fuzzing with energy = {energy} from state: {STATE}")
            for _ in range(energy):
                test_input = mutate_input(seed)
                print(f"\n[>] Sending: {test_input}")
                res, last_log = await execute_test(ble, test_input)
                print(f"[BLE Response]: {res}")
                print(f"[Device Log]: {last_log}")

                if is_interesting(seed, res, last_log):
                    print("[!!] Interesting behavior detected!")
                    interesting_count[json.dumps(seed)] += 1

                if "Authenticated" in last_log:
                    STATE = "Authenticated"
                elif "Unlocked" in last_log or "Lock mechanism open" in last_log:
                    STATE = "Unlocked"
                elif "Locked" in last_log or "Lock mechanism closed" in last_log:
                    STATE = "Locked"

                if "[!] Exception:" in last_log:
                    print("[*] Reconnecting after crash...")
                    try:
                        await ble.disconnect()
                    except:
                        pass
                    await asyncio.sleep(1.5)
                    try:
                        await ble.connect(DEVICE_NAME)
                    except Exception as e:
                        print(f"[X] Reconnect failed: {e}")
                        continue
    finally:
        print("\n[*] Disconnecting...")
        await ble.disconnect()
        print("[*] Final Logs:")
        for line in ble.read_logs():
            print(line)

# Entry point
if len(sys.argv) > 1 and sys.argv[1] == "--gui":
    ShowUserInterface()
else:
    try:
        asyncio.run(fuzzer())
    except KeyboardInterrupt:
        print("\nProgram exited by user")
