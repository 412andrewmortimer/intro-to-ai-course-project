#!/usr/bin/env python3
"""
Cybersecurity AI Application

Main entry point for the cybersecurity monitoring application.
"""

import time
import random
import sys
import os

# Ensure the module path is in the Python path
module_path = os.path.abspath(os.path.join('.'))
if module_path not in sys.path:
    sys.path.append(module_path)

# Import the Agent and dependencies
from agent import Agent
from service_impact.service_dependencies import ServiceDependencies

def generate_mock_data(event_type):
    """Generate mock data for different event types for simulation"""
    # Using the same function as in the notebook
    if event_type == 'login_attempt':
        return {
            'username': random.choice(['admin', 'user1', 'guest']),
            'source_ip': f'192.168.1.{random.randint(1, 254)}' if random.random() > 0.3 else f'10.0.0.{random.randint(1, 254)}',
            'timestamp': time.time(),
            'successful': random.choice([True, False])
        }
    elif event_type == 'service_change':
        # Randomly include a known malicious commit 5% of the time
        if random.random() < 0.05:
            commit_sha = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'  # Known malicious
        else:
            commit_sha = ''.join(random.choices('abcdef1234567890', k=40))
            
        return {
            'service': random.choice(['Auth Service', 'API Gateway', 'User Service', 'unknown_service']),
            'change_type': random.choice(['code_update', 'configuration_change', 'dependency_update']),
            'commit_sha': commit_sha
        }
    else:  # network_traffic
        return {
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'protocol': random.choice(['TCP', 'UDP', 'HTTP']),
            'packet_count': random.randint(10, 1000)
        }

def main():
    """Main execution function"""
    print("Starting Cybersecurity AI Application...")
    print("Initializing agent and modules...")
    
    # Initialize service dependencies
    service_deps = ServiceDependencies()
    
    # Initialize the agent
    agent = Agent()
    
    # If the agent has a service_impact module, inject the dependencies
    if hasattr(agent, 'service_impact'):
        agent.service_impact.service_deps = service_deps
        print("Injected service dependencies into Service Impact module")
    
    print("Agent initialization complete.")
    
    # Run a test with a service change that has downstream impacts
    test_service_change = {
        'service': 'Auth Service',  # Has many downstream dependencies
        'change_type': 'configuration_change',
        'commit_sha': ''.join(random.choices('abcdef1234567890', k=40))
    }
    
    print("\n--- Testing Service Change Impact Analysis ---")
    print(f"Event data: {test_service_change}")
    action = agent.process_event('service_change', test_service_change)
    print(f"Agent response: {action}\n")
    
    # Now test with a known problematic commit
    test_malicious_change = {
        'service': 'Auth Service',
        'change_type': 'code_update',
        'commit_sha': 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'  # Known malicious
    }
    
    print("--- Testing Known Problematic Commit ---")
    print(f"Event data: {test_malicious_change}")
    action = agent.process_event('service_change', test_malicious_change)
    print(f"Agent response: {action}\n")
    
    # Run a brief simulation
    print("\nRunning brief cybersecurity monitoring simulation:")
    for i in range(5):
        print(f"\n--- Monitoring Cycle {i+1} ---")
        
        # Randomly generate an event type
        event_type = random.choice(['login_attempt', 'service_change', 'network_traffic', 'git_activity'])
        event_data = generate_mock_data(event_type)
        
        print(f"Event detected: {event_type}")
        print(f"Event data: {event_data}")
        
        # Agent perceives and acts on the event
        action = agent.process_event(event_type, event_data)
        
        print(f"Agent response: {action}")
    
    print("\nCybersecurity monitoring simulation completed.")

if __name__ == "__main__":
    main()
