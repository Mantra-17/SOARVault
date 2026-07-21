import argparse
import asyncio
import httpx
import time
import statistics
import sys
from typing import List
from ingestion.simulator import AlertSimulator

async def send_request(client: httpx.AsyncClient, url: str, payload: dict) -> float:
    """Send a single request and return the elapsed time in seconds."""
    start_time = time.perf_counter()
    try:
        response = await client.post(url, json=payload, timeout=10.0)
        # We consider both 200 (Processed) and 202 (Duplicate) as successful roundtrips
        if response.status_code not in (200, 202):
            print(f"Failed request: {response.status_code} - {response.text}")
            return -1.0
    except Exception as e:
        print(f"Request error: {e}")
        return -1.0
    end_time = time.perf_counter()
    return end_time - start_time

async def run_benchmark(num_requests: int, concurrency: int, url: str):
    """Run the benchmark with the specified number of requests and concurrency limit."""
    print(f"Starting benchmark against {url}")
    print(f"Total Requests: {num_requests}")
    print(f"Concurrency: {concurrency}")
    print("-" * 40)

    simulator = AlertSimulator()
    latencies: List[float] = []
    
    # We use a semaphore to limit concurrent in-flight requests
    semaphore = asyncio.Semaphore(concurrency)

    async def bound_request(client: httpx.AsyncClient):
        async with semaphore:
            payload = simulator.get_random_alert()
            latency = await send_request(client, url, payload)
            if latency >= 0:
                latencies.append(latency)

    overall_start = time.perf_counter()

    async with httpx.AsyncClient() as client:
        tasks = [bound_request(client) for _ in range(num_requests)]
        await asyncio.gather(*tasks)

    overall_end = time.perf_counter()
    total_time = overall_end - overall_start

    print("-" * 40)
    print("Benchmark Results:")
    if not latencies:
        print("No successful requests completed.")
        sys.exit(1)

    successful = len(latencies)
    latencies_ms = [l * 1000 for l in latencies]
    latencies_ms.sort()

    avg_ms = statistics.mean(latencies_ms)
    min_ms = latencies_ms[0]
    max_ms = latencies_ms[-1]
    
    # Calculate P95
    p95_index = int(0.95 * successful) - 1
    p95_ms = latencies_ms[max(0, p95_index)]

    print(f"Successful Requests: {successful}/{num_requests}")
    print(f"Total Wall-clock Time: {total_time:.2f} seconds")
    print(f"Throughput: {successful / total_time:.2f} requests/second")
    print("\nLatency Metrics:")
    print(f"  Average: {avg_ms:.2f} ms")
    print(f"  Min:     {min_ms:.2f} ms")
    print(f"  P95:     {p95_ms:.2f} ms")
    print(f"  Max:     {max_ms:.2f} ms")


def main():
    parser = argparse.ArgumentParser(description="SOARVault Ingestion API Benchmark Tool")
    parser.add_argument("-n", "--requests", type=int, default=100, help="Total number of requests to send")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Number of concurrent requests")
    parser.add_argument("-u", "--url", type=str, default="http://127.0.0.1:8000/webhook/alert", help="Target webhook URL")
    args = parser.parse_args()

    asyncio.run(run_benchmark(args.requests, args.concurrency, args.url))

if __name__ == "__main__":
    main()
