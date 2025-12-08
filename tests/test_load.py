"""
Load and performance testing for EVA-Auth service.

Tests sustained load, latency under pressure, and resource utilization.
Validates Phase 3 performance requirements:
- 100 RPS sustained throughput
- <100ms p95 latency under load
- Resource limits (CPU, memory)

Requirements:
    pip install locust

Run with:
    locust -f tests/test_load.py --host http://localhost:8000 --users 100 --spawn-rate 10 --run-time 60s --headless
"""

import json
import random
import time
from typing import Dict, List

from locust import HttpUser, between, task


class EVAAuthUser(HttpUser):
    """Simulated user for EVA-Auth load testing."""
    
    wait_time = between(0.5, 2.0)  # Wait 0.5-2 seconds between requests
    
    def on_start(self):
        """Initialize user session with mock token."""
        # Generate mock token for this user
        response = self.client.post(
            "/auth/mock/token",
            params={
                "user_id": f"load-test-user-{random.randint(1000, 9999)}",
                "email": f"loadtest-{random.randint(1000, 9999)}@example.com",
                "tenant_id": "load-test-tenant",
                "roles": "eva:user",
            },
            catch_response=True,
        )
        
        if response.status_code == 200:
            data = response.json()
            self.token = data["access_token"]
            response.success()
        else:
            response.failure(f"Failed to generate token: {response.status_code}")
            self.token = None
    
    @task(10)
    def health_check(self):
        """Test health endpoint (most frequent)."""
        with self.client.get("/health", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(5)
    def readiness_check(self):
        """Test readiness endpoint."""
        with self.client.get("/ready", catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Readiness check failed: {response.status_code}")
    
    @task(3)
    def generate_token(self):
        """Test token generation endpoint."""
        with self.client.post(
            "/auth/mock/token",
            params={
                "user_id": f"user-{random.randint(1000, 9999)}",
                "email": f"test-{random.randint(1000, 9999)}@example.com",
                "tenant_id": "test-tenant",
                "roles": "eva:user",
            },
            catch_response=True,
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Token generation failed: {response.status_code}")
    
    @task(1)
    def oauth_endpoints(self):
        """Test OAuth redirect endpoints (less frequent)."""
        provider = random.choice(["b2c", "entra"])
        with self.client.get(
            f"/auth/{provider}/login",
            catch_response=True,
            allow_redirects=False,
        ) as response:
            if response.status_code in [302, 307]:
                response.success()
            else:
                response.failure(f"OAuth redirect failed: {response.status_code}")


class StressTestUser(HttpUser):
    """High-intensity stress testing user."""
    
    wait_time = between(0.1, 0.5)  # Aggressive: 0.1-0.5s between requests
    
    @task
    def rapid_fire_health(self):
        """Rapid health checks to test limits."""
        self.client.get("/health")


class SpikeTestUser(HttpUser):
    """Simulates traffic spikes."""
    
    wait_time = between(0.05, 0.2)  # Very aggressive: 0.05-0.2s
    
    @task(5)
    def health(self):
        self.client.get("/health")
    
    @task(1)
    def generate_many_tokens(self):
        """Generate many tokens rapidly."""
        for _ in range(5):
            self.client.post(
                "/auth/mock/token",
                params={
                    "user_id": f"spike-user-{random.randint(1, 10000)}",
                    "email": f"spike-{random.randint(1, 10000)}@example.com",
                    "tenant_id": "spike-tenant",
                    "roles": "eva:admin",
                },
            )


# Performance test scenarios
"""
SCENARIO 1: Normal Load (100 RPS sustained)
    locust -f tests/test_load.py --host http://localhost:8000 \\
           --users 100 --spawn-rate 10 --run-time 60s \\
           --headless --html reports/load-normal.html

SCENARIO 2: Stress Test (500+ RPS)
    locust -f tests/test_load.py --host http://localhost:8000 \\
           -u StressTestUser --users 500 --spawn-rate 50 --run-time 60s \\
           --headless --html reports/load-stress.html

SCENARIO 3: Spike Test (1000+ RPS burst)
    locust -f tests/test_load.py --host http://localhost:8000 \\
           -u SpikeTestUser --users 1000 --spawn-rate 100 --run-time 30s \\
           --headless --html reports/load-spike.html

SCENARIO 4: Endurance Test (100 RPS for 10 minutes)
    locust -f tests/test_load.py --host http://localhost:8000 \\
           --users 100 --spawn-rate 10 --run-time 600s \\
           --headless --html reports/load-endurance.html

Expected Results:
- Normal Load: p95 < 100ms, p99 < 200ms, 0% failures
- Stress Test: p95 < 500ms, p99 < 1000ms, <1% failures
- Spike Test: System recovers, <5% failures during burst
- Endurance: Stable performance over 10min, no memory leaks
"""


if __name__ == "__main__":
    print("EVA-Auth Load Testing Scenarios")
    print("=" * 50)
    print("\nInstall locust: pip install locust")
    print("\nRun scenarios with:")
    print("  locust -f tests/test_load.py --host http://localhost:8000 \\")
    print("         --users 100 --spawn-rate 10 --run-time 60s --headless")
    print("\nSee docstring for detailed scenarios.")
