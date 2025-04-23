import coverage
from fuzzer2 import DjangoEndpointFuzzer

def main():
    # Initialize coverage for the Django project
    cov = coverage.Coverage(source=['.'], branch=True)
    cov.start()

    # Initialize fuzzer with input file
    fuzzer = DjangoEndpointFuzzer(input_file='input.json', application='Django')
    
    # Run the fuzzer
    failure_queue = fuzzer.fuzz(max_iterations=1000)

    # Stop and save the coverage data after fuzzing is complete
    cov.stop()
    cov.save()

    # Print the coverage report
    try:
        print("\nCoverage Report:")
        cov.report()
        cov.erase()
    except coverage.exceptions.NoDataError:
        print("Warning: No data collected by coverage!")

    # Print failures
    # print("Failures found during fuzzing:")
    # print(failure_queue)

    # Save all failures to a file (in case it's not already done)
    fuzzer.save_failures()

if __name__ == "__main__":
    main()
