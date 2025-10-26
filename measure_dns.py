# measure_dns.py
import subprocess
import re
import sys
import time

def measure_dns_performance(domain_file):
    tin = time.time()
    """
    Reads a file of domains, resolves them using dig, and prints performance stats.
    """
    try:
        with open(domain_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Domain file '{domain_file}' not found.")
        sys.exit(1)

    latencies = []
    success_count = 0
    fail_count = 0
    total_queries = len(domains)

    start_time = time.time()
    successful_resolves = []

    print(f"Starting resolution for {total_queries} domains...")
    for domain in domains:
        try:
            # Use dig with a 2-second timeout per query
            command = ['dig', '+time=2', '+tries=1', '+stats', domain]
            result = subprocess.run(command, capture_output=True, text=True, timeout=3)

            # Check dig's output for success (NOERROR)
            if "status: NOERROR" in result.stdout:
                success_count += 1
                # Find the 'Query time' in the output
                match = re.search(r'Query time: (\d+) msec', result.stdout)
                if match:
                    latencies.append(int(match.group(1)))
                successful_resolves.append(domain)
            else:
                fail_count += 1
        except subprocess.TimeoutExpired:
            fail_count += 1 # Count a command timeout as a failure

    end_time = time.time()
    total_duration = end_time - start_time

    # --- Calculate and Print Metrics ---
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    throughput = total_queries / total_duration if total_duration > 0 else 0
    tfin = time.time()
    print(successful_resolves)
    print("\n--- DNS Performance Results ---")
    print(f"Total Queries Attempted: {total_queries}")
    print(f"Successfully Resolved:    {success_count}")
    print(f"Failed to Resolve:       {fail_count}")
    print(f"Average Lookup Latency:  {avg_latency:.2f} ms")
    print(f"Average Throughput:      {throughput:.2f} queries/sec")
    print("-----------------------------")
    print(f"Time taken for running: {tfin - tin} seconds")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <domain_list_file>")
        sys.exit(1)
    measure_dns_performance(sys.argv[1])