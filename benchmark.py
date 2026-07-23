import argparse
import asyncio
import statistics
import sys
import time
from typing import Dict, List

# Setup orchestrator directly for in-memory benchmarking
from ingestion.orchestrator import IncidentOrchestrator
from ingestion.simulator import AlertSimulator

class PipelineProfiler:
    """
    Measures the end-to-end latency of the SOAR pipeline natively
    without network overhead.
    """
    def __init__(self):
        self.orchestrator = IncidentOrchestrator()

    async def measure_end_to_end_latency(self, sample_alerts: List[Dict]) -> List[float]:
        """
        Sends a batch of alerts sequentially through the orchestrator.
        """
        latencies = []
        for alert in sample_alerts:
            # We want to measure the latency of run_full_pipeline
            start_time = time.perf_counter()
            try:
                await self.orchestrator.run_full_pipeline(alert)
                end_time = time.perf_counter()
                latencies.append(end_time - start_time)
            except Exception as e:
                print(f"Error processing alert: {e}")
                # We skip failed alerts for latency stats
        return latencies

    def generate_report(self, latencies: List[float]):
        """
        Calculates and prints the performance metrics.
        """
        print("-" * 40)
        print("End-to-End Pipeline Performance Report")
        if not latencies:
            print("No successful alerts processed.")
            sys.exit(1)

        successful = len(latencies)
        latencies_ms = [l * 1000 for l in latencies]
        latencies_ms.sort()

        avg_ms = statistics.mean(latencies_ms)
        min_ms = latencies_ms[0]
        max_ms = latencies_ms[-1]
        
        # Calculate percentiles
        p95_index = int(0.95 * successful) - 1
        p95_ms = latencies_ms[max(0, p95_index)]
        
        p99_index = int(0.99 * successful) - 1
        p99_ms = latencies_ms[max(0, p99_index)]

        print(f"Total Alerts Processed: {successful}")
        print("\nLatency Metrics:")
        print(f"  Average: {avg_ms:.2f} ms")
        print(f"  Min:     {min_ms:.2f} ms")
        print(f"  Max:     {max_ms:.2f} ms")
        print(f"  P95:     {p95_ms:.2f} ms")
        print(f"  P99:     {p99_ms:.2f} ms")
        print("-" * 40)


async def main():
    parser = argparse.ArgumentParser(description="SOARVault Pipeline Profiler")
    parser.add_argument("-n", "--requests", type=int, default=100, help="Total number of alerts to process")
    args = parser.parse_args()

    print(f"Generating {args.requests} sample alerts...")
    simulator = AlertSimulator()
    sample_alerts = [simulator.get_random_alert() for _ in range(args.requests)]

    profiler = PipelineProfiler()
    print("Running profiling...")
    latencies = await profiler.measure_end_to_end_latency(sample_alerts)
    profiler.generate_report(latencies)

if __name__ == "__main__":
    asyncio.run(main())
