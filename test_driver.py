# test_driver.py
from fuzzer_basic import DjangoEndpointFuzzer

def main():
    # Initialize fuzzer with input file

    # Extract input.json
    fuzzer = DjangoEndpointFuzzer(input_file='input1.json')
    
    # Run fuzzer with limited iterations to avoid overwhelming output
    findings = fuzzer.fuzz(max_iterations=20)
    
    # Print summary
    print(f"\nFuzzing completed. Found {len(findings)} interesting inputs.")

if __name__ == "__main__":
    main()
