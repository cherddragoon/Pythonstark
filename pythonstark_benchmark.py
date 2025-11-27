"""
PythonStark Professional Scaling Benchmark Suite

Comprehensive performance analysis with rigorous stress testing and detailed metrics.
Measures computational complexity, memory efficiency, and scalability limits.
"""

import time
import psutil
import gc
import threading
import numpy as np
import os
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass, asdict
import json
import math
import sys
from concurrent.futures import ThreadPoolExecutor
import traceback

from pythonstark import (
    generate_fibonacci_trace_secure,
    EnhancedPythonStarkProver,
    EnhancedPythonStarkVerifier,
    SecurityParameters,
    warmup_pythonstark,
)


@dataclass
class SystemMetrics:
    """System resource measurements."""
    cpu_percent: float
    memory_mb: float
    memory_peak_mb: float
    threads_active: int
    process_time: float


@dataclass
class PerformanceMetrics:
    """Computational performance measurements."""
    prove_time_sec: float
    verify_time_sec: float
    total_time_sec: float
    proof_size_bytes: int
    queries_count: int
    blowup_factor: int


@dataclass
class ComplexityMetrics:
    """Algorithmic complexity analysis."""
    n_steps: int
    n_registers: int
    field_operations: int
    hash_operations: int
    merkle_operations: int
    fri_layers: int


@dataclass
class BenchmarkResult:
    """Complete benchmark result with all metrics."""
    test_name: str
    security_bits: int
    system_metrics: SystemMetrics
    performance_metrics: PerformanceMetrics
    complexity_metrics: ComplexityMetrics
    success: bool
    error_message: str = ""


class ResourceMonitor:
    """Real-time system resource monitoring."""
    
    def __init__(self):
        self.monitoring = False
        self.metrics = []
        self.peak_memory = 0
        self.start_time = 0
        
    def start_monitoring(self):
        """Begin resource monitoring."""
        self.monitoring = True
        self.peak_memory = 0
        self.start_time = time.perf_counter()
        self.metrics = []
        
        def monitor():
            process = psutil.Process()
            while self.monitoring:
                try:
                    cpu = process.cpu_percent()
                    memory = process.memory_info().rss / 1024 / 1024
                    threads = process.num_threads()
                    proc_time = process.cpu_times().user + process.cpu_times().system
                    
                    self.peak_memory = max(self.peak_memory, memory)
                    self.metrics.append({
                        'cpu': cpu,
                        'memory': memory,
                        'threads': threads,
                        'time': proc_time
                    })
                    time.sleep(0.1)
                except:
                    break
                    
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
        
    def stop_monitoring(self) -> SystemMetrics:
        """Stop monitoring and return aggregated metrics."""
        self.monitoring = False
        self.monitor_thread.join(timeout=1.0)
        
        if not self.metrics:
            return SystemMetrics(0, 0, 0, 0, 0)
            
        avg_cpu = sum(m['cpu'] for m in self.metrics) / len(self.metrics)
        avg_memory = sum(m['memory'] for m in self.metrics) / len(self.metrics)
        avg_threads = sum(m['threads'] for m in self.metrics) / len(self.metrics)
        avg_proc_time = sum(m['time'] for m in self.metrics) / len(self.metrics)
        
        return SystemMetrics(
            cpu_percent=avg_cpu,
            memory_mb=avg_memory,
            memory_peak_mb=self.peak_memory,
            threads_active=int(avg_threads),
            process_time=avg_proc_time
        )


class PythonStarkBenchmarkSuite:
    """Professional benchmark suite for PythonStark scalability analysis."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
        self.monitor = ResourceMonitor()
        
    def warmup_system(self):
        """System warmup with comprehensive operations."""
        print("System warmup...")
        warmup_pythonstark()
        
        # Additional warmup operations
        for _ in range(10):
            _ = np.random.randint(0, 1000, size=(100, 2), dtype=np.uint64)
        gc.collect()
        
    def measure_complexity(self, trace_shape: Tuple[int, int], 
                          security_params: SecurityParameters) -> ComplexityMetrics:
        """Calculate algorithmic complexity metrics."""
        n_steps, n_registers = trace_shape
        
        # Estimate field operations
        field_ops = n_steps * n_registers * security_params.blowup_factor * 10
        field_ops += security_params.num_queries * 100  # Verification operations
        
        # Estimate hash operations
        hash_ops = n_steps * n_registers * 2  # Trace commitments
        hash_ops += security_params.num_queries * 4  # Query verification
        hash_ops += 100  # Miscellaneous operations
        
        # Estimate Merkle tree operations
        merkle_ops = n_steps * security_params.blowup_factor * 2
        merkle_ops += security_params.num_queries * 3
        
        # FRI layers estimation
        fri_layers = int(math.log2(n_steps * security_params.blowup_factor))
        
        return ComplexityMetrics(
            n_steps=n_steps,
            n_registers=n_registers,
            field_operations=field_ops,
            hash_operations=hash_ops,
            merkle_operations=merkle_ops,
            fri_layers=fri_layers
        )
    
    def run_stress_test(self, n_steps: int, security_bits: int, 
                       mask_trace: bool = True) -> BenchmarkResult:
        """Run comprehensive stress test for given parameters."""
        test_name = f"STRESS_{n_steps}steps_{security_bits}bits"
        
        try:
            # Setup
            security_params = SecurityParameters.compute_parameters(security_bits, n_steps)
            prover = EnhancedPythonStarkProver(security_params)
            verifier = EnhancedPythonStarkVerifier(security_params)
            
            # Generate trace
            trace_start = time.perf_counter()
            trace = generate_fibonacci_trace_secure(n_steps, mask=mask_trace)
            trace_time = time.perf_counter() - trace_start
            
            # Start monitoring
            self.monitor.start_monitoring()
            
            # Proof generation
            prove_start = time.perf_counter()
            proof = prover.prove(trace)
            prove_time = time.perf_counter() - prove_start
            
            # Proof serialization size
            proof_size = len(str(proof).encode())  # Approximate size
            
            # Verification (multiple runs for accuracy)
            verify_runs = 10
            verify_times = []
            for _ in range(verify_runs):
                verify_start = time.perf_counter()
                valid = verifier.verify(trace, proof)
                verify_time = time.perf_counter() - verify_start
                verify_times.append(verify_time)
            
            avg_verify_time = sum(verify_times) / len(verify_times)
            
            # Stop monitoring
            system_metrics = self.monitor.stop_monitoring()
            
            # Complexity analysis
            complexity_metrics = self.measure_complexity(
                (n_steps, trace.trace_table.shape[1]), security_params
            )
            
            # Performance metrics
            performance_metrics = PerformanceMetrics(
                prove_time_sec=prove_time,
                verify_time_sec=avg_verify_time,
                total_time_sec=prove_time + avg_verify_time + trace_time,
                proof_size_bytes=proof_size,
                queries_count=security_params.num_queries,
                blowup_factor=security_params.blowup_factor
            )
            
            if not valid:
                return BenchmarkResult(
                    test_name=test_name,
                    security_bits=security_bits,
                    system_metrics=system_metrics,
                    performance_metrics=performance_metrics,
                    complexity_metrics=complexity_metrics,
                    success=False,
                    error_message="Proof verification failed"
                )
                
            return BenchmarkResult(
                test_name=test_name,
                security_bits=security_bits,
                system_metrics=system_metrics,
                performance_metrics=performance_metrics,
                complexity_metrics=complexity_metrics,
                success=True
            )
            
        except Exception as e:
            self.monitor.stop_monitoring()
            return BenchmarkResult(
                test_name=test_name,
                security_bits=security_bits,
                system_metrics=SystemMetrics(0, 0, 0, 0, 0),
                performance_metrics=PerformanceMetrics(0, 0, 0, 0, 0, 0),
                complexity_metrics=ComplexityMetrics(0, 0, 0, 0, 0, 0),
                success=False,
                error_message=str(e)
            )
    
    def run_memory_stress_test(self, max_steps: int = 2048) -> List[BenchmarkResult]:
        """Test memory limits with increasing trace sizes."""
        print("Memory Stress Test - Finding scalability limits...")
        results = []
        
        # Exponential scaling: 2^8 to 2^11
        test_sizes = [256, 512, 1024, 2048, 4096]
        
        for n_steps in test_sizes:
            if n_steps > max_steps:
                break
                
            print(f"  Testing {n_steps} steps...")
            result = self.run_stress_test(n_steps, 128, mask_trace=True)
            results.append(result)
            
            if not result.success:
                print(f"    FAILED at {n_steps} steps: {result.error_message}")
                break
                
            # Check memory usage
            if result.system_metrics.memory_peak_mb > 2000:  # 2GB limit
                print(f"    Memory limit exceeded at {n_steps} steps")
                break
                
            print(f"    SUCCESS: {result.performance_metrics.prove_time_sec:.3f}s prove, "
                  f"{result.system_metrics.memory_peak_mb:.1f}MB peak")
                  
        return results
    
    def run_security_scaling_test(self) -> List[BenchmarkResult]:
        """Test performance across different security levels."""
        print("Security Scaling Test - Performance vs Security Level...")
        results = []
        
        security_levels = [80, 96, 128, 160, 192]
        base_steps = 512
        
        for security_bits in security_levels:
            print(f"  Testing {security_bits}-bit security...")
            result = self.run_stress_test(base_steps, security_bits, mask_trace=True)
            results.append(result)
            
            if not result.success:
                print(f"    FAILED at {security_bits} bits: {result.error_message}")
                break
                
            print(f"    SUCCESS: {result.performance_metrics.queries_count} queries, "
                  f"{result.performance_metrics.prove_time_sec:.3f}s prove")
                  
        return results
    
    def run_concurrent_stress_test(self, n_steps: int = 256, 
                                 security_bits: int = 128,
                                 max_concurrent: int = 8) -> List[BenchmarkResult]:
        """Test concurrent proof generation."""
        print(f"Concurrent Stress Test - {max_concurrent} parallel proofs...")
        results = []
        
        for n_threads in range(1, max_concurrent + 1):
            print(f"  Testing {n_threads} concurrent threads...")
            
            try:
                def worker():
                    return self.run_stress_test(n_steps, security_bits, mask_trace=True)
                
                start_time = time.perf_counter()
                
                with ThreadPoolExecutor(max_workers=n_threads) as executor:
                    futures = [executor.submit(worker) for _ in range(n_threads)]
                    thread_results = [f.result() for f in futures]
                
                total_time = time.perf_counter() - start_time
                
                # Aggregate results
                successful = [r for r in thread_results if r.success]
                if len(successful) == n_threads:
                    avg_prove_time = sum(r.performance_metrics.prove_time_sec 
                                       for r in successful) / len(successful)
                    avg_memory = sum(r.system_metrics.memory_peak_mb 
                                   for r in successful) / len(successful)
                    
                    print(f"    SUCCESS: {total_time:.3f}s total, "
                          f"{avg_prove_time:.3f}s avg per proof, "
                          f"{avg_memory:.1f}MB avg memory")
                          
                    # Create aggregated result
                    result = successful[0]
                    result.test_name = f"CONCURRENT_{n_threads}threads"
                    result.performance_metrics.prove_time_sec = avg_prove_time
                    result.performance_metrics.total_time_sec = total_time
                    results.append(result)
                else:
                    print(f"    FAILED: Only {len(successful)}/{n_threads} succeeded")
                    
            except Exception as e:
                print(f"    FAILED: {str(e)}")
                
        return results
    
    def run_timeout_stress_test(self, timeout_seconds: int = 60) -> List[BenchmarkResult]:
        """Test system behavior under time pressure."""
        print(f"Timeout Stress Test - {timeout_seconds}s time limit...")
        results = []
        
        # Very large trace that should timeout
        large_sizes = [4096, 8192, 16384]
        
        for n_steps in large_sizes:
            print(f"  Testing {n_steps} steps (timeout: {timeout_seconds}s)...")
            
            def timeout_test():
                return self.run_stress_test(n_steps, 128, mask_trace=True)
            
            start_time = time.perf_counter()
            
            try:
                # Cross-platform timeout using threading
                import threading
                result_container = {'result': None, 'exception': None, 'done': False}
                
                def worker():
                    try:
                        result_container['result'] = timeout_test()
                    except Exception as e:
                        result_container['exception'] = e
                    finally:
                        result_container['done'] = True
                
                thread = threading.Thread(target=worker)
                thread.daemon = True
                thread.start()
                
                # Wait for completion or timeout
                thread.join(timeout_seconds)
                
                if not result_container['done']:
                    print(f"    TIMEOUT: Exceeded {timeout_seconds}s limit")
                    # Create timeout result
                    results.append(BenchmarkResult(
                        test_name=f"TIMEOUT_{n_steps}steps",
                        security_bits=128,
                        system_metrics=SystemMetrics(0, 0, 0, 0, 0),
                        performance_metrics=PerformanceMetrics(0, 0, 0, 0, 0, 0),
                        complexity_metrics=ComplexityMetrics(0, 0, 0, 0, 0, 0),
                        success=False,
                        error_message=f"Timeout after {timeout_seconds}s"
                    ))
                elif result_container['exception']:
                    raise result_container['exception']
                else:
                    actual_time = time.perf_counter() - start_time
                    result = result_container['result']
                    results.append(result)
                    
                    if result.success:
                        print(f"    SUCCESS: {actual_time:.3f}s (within limit)")
                    else:
                        print(f"    FAILED: {result.error_message}")
                        
            except Exception as e:
                print(f"    ERROR: {str(e)}")
                
        return results
    
    def generate_report(self, results: List[BenchmarkResult]) -> str:
        """Generate comprehensive benchmark report."""
        report = []
        report.append("=" * 80)
        report.append("PYTHONSTARK PROFESSIONAL SCALING BENCHMARK REPORT")
        report.append("=" * 80)
        report.append("")
        
        # Summary statistics
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]
        
        report.append("EXECUTIVE SUMMARY:")
        report.append(f"  Total tests: {len(results)}")
        report.append(f"  Successful: {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
        report.append(f"  Failed: {len(failed)} ({len(failed)/len(results)*100:.1f}%)")
        report.append("")
        
        if successful:
            # Performance analysis
            prove_times = [r.performance_metrics.prove_time_sec for r in successful]
            verify_times = [r.performance_metrics.verify_time_sec for r in successful]
            memory_usage = [r.system_metrics.memory_peak_mb for r in successful]
            proof_sizes = [r.performance_metrics.proof_size_bytes for r in successful]
            
            report.append("PERFORMANCE ANALYSIS:")
            report.append(f"  Proof generation:")
            report.append(f"    Average: {np.mean(prove_times):.3f}s")
            report.append(f"    Min: {np.min(prove_times):.3f}s")
            report.append(f"    Max: {np.max(prove_times):.3f}s")
            report.append(f"    StdDev: {np.std(prove_times):.3f}s")
            report.append(f"  Verification:")
            report.append(f"    Average: {np.mean(verify_times)*1000:.3f}ms")
            report.append(f"    Min: {np.min(verify_times)*1000:.3f}ms")
            report.append(f"    Max: {np.max(verify_times)*1000:.3f}ms")
            report.append(f"    StdDev: {np.std(verify_times)*1000:.3f}ms")
            report.append(f"  Memory usage:")
            report.append(f"    Average: {np.mean(memory_usage):.1f}MB")
            report.append(f"    Peak: {np.max(memory_usage):.1f}MB")
            report.append(f"  Proof sizes:")
            report.append(f"    Average: {np.mean(proof_sizes):.0f} bytes")
            report.append(f"    Max: {np.max(proof_sizes):.0f} bytes")
            report.append("")
        
        # Complexity analysis
        if successful:
            n_steps = [r.complexity_metrics.n_steps for r in successful]
            field_ops = [r.complexity_metrics.field_operations for r in successful]
            
            report.append("COMPLEXITY ANALYSIS:")
            report.append(f"  Trace sizes tested: {min(n_steps)} to {max(n_steps)} steps")
            report.append(f"  Field operations: {min(field_ops):,} to {max(field_ops):,}")
            report.append(f"  Security levels: {set(r.security_bits for r in successful)}")
            report.append("")
        
        # Detailed results
        report.append("DETAILED RESULTS:")
        report.append("-" * 80)
        
        for result in results:
            report.append(f"\n{result.test_name}:")
            report.append(f"  Status: {'SUCCESS' if result.success else 'FAILED'}")
            
            if result.success:
                report.append(f"  Security: {result.security_bits} bits")
                report.append(f"  Performance:")
                report.append(f"    Prove time: {result.performance_metrics.prove_time_sec:.3f}s")
                report.append(f"    Verify time: {result.performance_metrics.verify_time_sec*1000:.3f}ms")
                report.append(f"    Total time: {result.performance_metrics.total_time_sec:.3f}s")
                report.append(f"    Proof size: {result.performance_metrics.proof_size_bytes:,} bytes")
                report.append(f"    Queries: {result.performance_metrics.queries_count}")
                report.append(f"    Blowup factor: {result.performance_metrics.blowup_factor}")
                report.append(f"  System:")
                # Calculate CPU percentage relative to available cores
                try:
                    cpu_cores = len(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else os.cpu_count()
                    cpu_utilization = min(result.system_metrics.cpu_percent / cpu_cores, 100.0)
                except:
                    cpu_utilization = min(result.system_metrics.cpu_percent / 4, 100.0)  # Assume 4 cores as fallback
                
                report.append(f"    CPU utilization: {cpu_utilization:.1f}%")
                report.append(f"    Memory: {result.system_metrics.memory_mb:.1f}MB avg, "
                             f"{result.system_metrics.memory_peak_mb:.1f}MB peak")
                report.append(f"    Threads: {result.system_metrics.threads_active}")
                report.append(f"  Complexity:")
                report.append(f"    Steps: {result.complexity_metrics.n_steps}")
                report.append(f"    Registers: {result.complexity_metrics.n_registers}")
                report.append(f"    Field ops: {result.complexity_metrics.field_operations:,}")
                report.append(f"    Hash ops: {result.complexity_metrics.hash_operations:,}")
                report.append(f"    Merkle ops: {result.complexity_metrics.merkle_operations:,}")
                report.append(f"    FRI layers: {result.complexity_metrics.fri_layers}")
            else:
                report.append(f"  Error: {result.error_message}")
        
        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)
        
        return "\n".join(report)
    
    def save_results_json(self, results: List[BenchmarkResult], filename: str):
        """Save results to JSON file."""
        data = []
        for result in results:
            result_dict = asdict(result)
            # Convert nested dataclasses
            result_dict['system_metrics'] = asdict(result.system_metrics)
            result_dict['performance_metrics'] = asdict(result.performance_metrics)
            result_dict['complexity_metrics'] = asdict(result.complexity_metrics)
            data.append(result_dict)
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    
    def run_comprehensive_benchmark(self) -> List[BenchmarkResult]:
        """Run complete benchmark suite with all stress tests."""
        print("Starting PythonStark Comprehensive Scaling Benchmark...")
        print("=" * 80)
        
        all_results = []
        
        # System warmup
        self.warmup_system()
        
        # Test 1: Memory scaling
        print("\n1. MEMORY SCALING TEST")
        print("-" * 40)
        memory_results = self.run_memory_stress_test(max_steps=2048)
        all_results.extend(memory_results)
        
        # Test 2: Security scaling
        print("\n2. SECURITY SCALING TEST")
        print("-" * 40)
        security_results = self.run_security_scaling_test()
        all_results.extend(security_results)
        
        # Test 3: Concurrent stress
        print("\n3. CONCURRENT STRESS TEST")
        print("-" * 40)
        concurrent_results = self.run_concurrent_stress_test(max_concurrent=4)
        all_results.extend(concurrent_results)
        
        # Test 4: Timeout stress
        print("\n4. TIMEOUT STRESS TEST")
        print("-" * 40)
        timeout_results = self.run_timeout_stress_test(timeout_seconds=30)
        all_results.extend(timeout_results)
        
        # Generate report
        print("\n5. GENERATING REPORT")
        print("-" * 40)
        report = self.generate_report(all_results)
        
        # Save results
        timestamp = int(time.time())
        report_file = f"benchmark_report_{timestamp}.txt"
        json_file = f"benchmark_results_{timestamp}.json"
        
        with open(report_file, 'w') as f:
            f.write(report)
        
        self.save_results_json(all_results, json_file)
        
        print(f"\nReport saved to: {report_file}")
        print(f"Results saved to: {json_file}")
        
        # Print summary
        successful = len([r for r in all_results if r.success])
        print(f"\nBenchmark complete: {successful}/{len(all_results)} tests successful")
        
        return all_results


def main():
    """Main benchmark execution."""
    suite = PythonStarkBenchmarkSuite()
    
    try:
        results = suite.run_comprehensive_benchmark()
        
        # Print final summary
        successful = len([r for r in results if r.success])
        total = len(results)
        
        print(f"\n{'='*80}")
        print("BENCHMARK EXECUTION COMPLETE")
        print(f"{'='*80}")
        print(f"Success Rate: {successful}/{total} ({successful/total*100:.1f}%)")
        
        if successful == total:
            print("ALL TESTS PASSED")
        else:
            print("Some tests failed - Review detailed report")
            
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
    except Exception as e:
        print(f"\nFatal error during benchmark: {str(e)}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
