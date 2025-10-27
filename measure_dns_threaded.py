import subprocess
import re
import sys
import time
import threading

def run_dig(domain, i, lock, latencies, successful_resolves, counts):
    """
    This function is run by each thread to resolve a single domain.
    """
    try:
        # Use dig with a 15-second timeout per query
        command = ['dig', '+time=40', '+tries=1', '+stats', domain]
        result = subprocess.run(command, capture_output=True, text=True, timeout=41)

        #  Lock before writing to shared lists
        with lock:
            if "status: NOERROR" in result.stdout:
                counts['success'] += 1
                # Find the 'Query time' in the output
                match = re.search(r'Query time: (\d+) msec', result.stdout)
                if match:
                    latencies.append(int(match.group(1)))
                successful_resolves.append(domain)
                print(f"{domain} (Query {i}) successful.")
            else:
                counts['fail'] += 1
                print(f"{domain} (Query {i}) failed.")
        # Lock is automatically released here

    except subprocess.TimeoutExpired:
        # Lock before writing to shared list
        with lock:
            counts['fail'] += 1 # Count a command timeout as a failure
            print(f"{domain} (Query {i}) timed out.")

def measure_dns_performance(domain_file):
    tin = time.time()
    """
    Reads a file of domains, resolves them using multiple threads.
    """
    try:
        with open(domain_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Domain file '{domain_file}' not found.")
        sys.exit(1)

    latencies = []
    counts = {'success': 0, 'fail': 0} 
    successful_resolves = []
    lock = threading.Lock() # The lock to protect shared variables
    threads = [] # To keep track of our threads
    
    total_queries = len(domains)
    start_time = time.time()

    print(f"Starting resolution for {total_queries} domains using threads...")
    
    for i, domain in enumerate(domains):
        # Create a new thread for each domain
        t = threading.Thread(
            target=run_dig, 
            args=(domain, i, lock, latencies, successful_resolves, counts),
            daemon=True
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join() # This blocks until the thread 't' is finished

    print("\n--- All threads complete. Calculating results... ---")
    end_time = time.time()
    total_duration = end_time - start_time

    success_count = counts['success']
    fail_count = counts['fail']

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
