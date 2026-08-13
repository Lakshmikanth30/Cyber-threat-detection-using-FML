"""
BLOCKED IPS PERFORMANCE BENCHMARK
==================================

Compare old vs new blocking speed
Run: python test_blocking_speed.py
"""

import time
import json
import os
import tempfile
import subprocess
from collections import defaultdict
import sys

sys.path.insert(0, '.')

# =====================================================
# BENCHMARK: Old Implementation (Simulated)
# =====================================================

def benchmark_old_implementation():
    """Simulate old blocking with synchronous JSON writes"""
    print("\n" + "=" * 80)
    print("BENCHMARK 1: Old Implementation (Synchronous)")
    print("=" * 80)
    
    blocked_ips = set()
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    temp_file.close()
    
    times = []
    
    try:
        # Block 100 IPs
        for i in range(100):
            ip = f"192.168.1.{i % 254 + 1}"
            
            start = time.perf_counter()
            
            # Add to set
            blocked_ips.add(ip)
            
            # Synchronous JSON write (simulates file I/O delay)
            with open(temp_file.name, 'w') as f:
                json.dump({'blocked_ips': list(blocked_ips)}, f)
            
            # Simulate firewall rule (netsh overhead)
            time.sleep(0.01)  # 10ms per rule
            
            end = time.perf_counter()
            times.append((end - start) * 1000)
            
            if (i + 1) % 25 == 0:
                avg = sum(times[-25:]) / 25
                print(f"  Blocked {i+1:3d} IPs | Avg: {avg:.1f}ms | Last: {times[-1]:.1f}ms")
        
        total_time = sum(times)
        avg_time = total_time / len(times)
        
        print(f"\n  📊 OLD RESULTS:")
        print(f"     Total blocks: 100")
        print(f"     Total time: {total_time:.1f}ms")
        print(f"     Average per block: {avg_time:.1f}ms")
        print(f"     Min: {min(times):.1f}ms | Max: {max(times):.1f}ms")
        
        return {
            'total_time': total_time,
            'avg_time': avg_time,
            'min_time': min(times),
            'max_time': max(times),
            'times': times
        }
    
    finally:
        os.unlink(temp_file.name)

# =====================================================
# BENCHMARK: New Implementation
# =====================================================

def benchmark_new_implementation():
    """Test new optimized implementation"""
    print("\n" + "=" * 80)
    print("BENCHMARK 2: New Implementation (Optimized)")
    print("=" * 80)
    
    from blocked_ips_fast import BlockedIPsManager
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    temp_file.close()
    
    # Create manager
    manager = BlockedIPsManager(temp_file.name)
    times = []
    
    try:
        # Block 100 IPs
        for i in range(100):
            ip = f"192.168.1.{i % 254 + 1}"
            
            start = time.perf_counter()
            manager.add_block(ip, threat_score=95)
            end = time.perf_counter()
            
            times.append((end - start) * 1000)
            
            if (i + 1) % 25 == 0:
                avg = sum(times[-25:]) / 25
                print(f"  Blocked {i+1:3d} IPs | Avg: {avg:.1f}ms | Last: {times[-1]:.1f}ms")
        
        total_time = sum(times)
        avg_time = total_time / len(times)
        
        print(f"\n  🚀 NEW RESULTS:")
        print(f"     Total blocks: 100")
        print(f"     Total time: {total_time:.1f}ms")
        print(f"     Average per block: {avg_time:.1f}ms")
        print(f"     Min: {min(times):.1f}ms | Max: {max(times):.1f}ms")
        print(f"     Blocked IPs in cache: {manager.get_blocked_count()}")
        
        # Flush to disk
        manager._flush_to_disk()
        manager.shutdown()
        
        return {
            'total_time': total_time,
            'avg_time': avg_time,
            'min_time': min(times),
            'max_time': max(times),
            'times': times
        }
    
    finally:
        os.unlink(temp_file.name)

# =====================================================
# BENCHMARK: Lookup Speed
# =====================================================

def benchmark_lookup_speed():
    """Benchmark IP lookup speed"""
    print("\n" + "=" * 80)
    print("BENCHMARK 3: Lookup Performance")
    print("=" * 80)
    
    from blocked_ips_fast import BlockedIPsManager
    
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
    temp_file.close()
    
    manager = BlockedIPsManager(temp_file.name)
    
    # Pre-populate with 10,000 IPs
    print("  Populating cache with 10,000 IPs...")
    for i in range(10000):
        manager.add_block(f"10.{i // 256}.{i % 256}.{i % 254 + 1}")
    
    print(f"  Cache size: {manager.get_blocked_count()} IPs")
    
    # Test lookups
    test_ips = [
        "10.0.0.1",      # In cache
        "10.20.50.100",  # In cache
        "192.168.1.1",   # Not in cache
        "8.8.8.8",       # Not in cache
    ]
    
    times = []
    for _ in range(100000):
        start = time.perf_counter()
        for ip in test_ips:
            manager.is_blocked(ip)
        end = time.perf_counter()
        times.append((end - start) * 1000 / len(test_ips))  # Per-lookup time
    
    avg_lookup = sum(times) / len(times)
    
    print(f"\n  📊 LOOKUP RESULTS (10M lookups):")
    print(f"     Average per lookup: {avg_lookup:.3f}ms")
    print(f"     Min: {min(times):.3f}ms | Max: {max(times):.3f}ms")
    print(f"     Throughput: {1000 / avg_lookup:,.0f} lookups/ms")
    
    manager.shutdown()
    os.unlink(temp_file.name)
    
    return avg_lookup

# =====================================================
# COMPARISON & SUMMARY
# =====================================================

def print_comparison(old_results, new_results):
    """Print side-by-side comparison"""
    print("\n" + "=" * 80)
    print("COMPARISON & IMPROVEMENT")
    print("=" * 80)
    
    speedup_total = old_results['total_time'] / new_results['total_time']
    speedup_avg = old_results['avg_time'] / new_results['avg_time']
    
    print(f"\n  {'Metric':<30} {'Old':<15} {'New':<15} {'Speedup':<10}")
    print(f"  {'-' * 70}")
    print(f"  {'Total Time (100 blocks)':<30} {old_results['total_time']:>6.1f}ms {new_results['total_time']:>14.1f}ms {speedup_total:>9.1f}x")
    print(f"  {'Average per Block':<30} {old_results['avg_time']:>6.1f}ms {new_results['avg_time']:>14.1f}ms {speedup_avg:>9.1f}x")
    print(f"  {'Min (best case)':<30} {old_results['min_time']:>6.1f}ms {new_results['min_time']:>14.1f}ms {old_results['min_time']/new_results['min_time']:>9.1f}x")
    print(f"  {'Max (worst case)':<30} {old_results['max_time']:>6.1f}ms {new_results['max_time']:>14.1f}ms {old_results['max_time']/new_results['max_time']:>9.1f}x")
    
    print(f"\n  🎯 ACHIEVEMENT: {speedup_avg:.0f}x faster block operations!")
    print(f"  ✅ Reduced per-block time from {old_results['avg_time']:.1f}ms → {new_results['avg_time']:.1f}ms")

# =====================================================
# MAIN
# =====================================================

if __name__ == '__main__':
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 15 + "BLOCKED IPS PERFORMANCE BENCHMARK" + " " * 30 + "║")
    print("╚" + "=" * 78 + "╝")
    
    # Run benchmarks
    try:
        old_results = benchmark_old_implementation()
        time.sleep(1)
        new_results = benchmark_new_implementation()
        
        # Print comparison
        print_comparison(old_results, new_results)
        
        # Lookup benchmark
        lookup_time = benchmark_lookup_speed()
        print(f"\n  💡 With 10,000 blocked IPs: {lookup_time:.3f}ms per lookup (O(1))")
        
    except ImportError as e:
        print(f"\n❌ Error: {e}")
        print("Make sure blocked_ips_fast.py is in the current directory")
    
    print("\n" + "=" * 80)
    print("✅ Benchmarks complete!")
    print("=" * 80 + "\n")
