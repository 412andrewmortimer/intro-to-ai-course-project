import time
import random
from agent import Agent

def main():
    print("Starting Cybersecurity AI Application...")
    print("Initializing agent and modules...")
    
    # Create and initialize the agent
    agent = Agent()
    
    # Simulate environment events and agent responses
    print("\nRunning cybersecurity monitoring simulation:")
    for i in range(50):
        print(f"\n--- Monitoring Cycle {i+1} ---")
        
        # Randomly generate an event type for simulation purposes
        event_type = random.choice(['login_attempt', 'service_change', 'network_traffic'])
        event_data = generate_mock_data(event_type)
        
        print(f"Event detected: {event_type}")
        print(f"Event data: {event_data}")
        
        # Agent perceives and acts on the event
        action = agent.process_event(event_type, event_data)
        
        print(f"Agent response: {action}")
        time.sleep(1)
    
    print("\nCybersecurity monitoring simulation completed.")

def generate_mock_data(event_type):
    """Generate mock data for different event types for simulation"""
    if event_type == 'login_attempt':
        return {
            'username': random.choice(['admin', 'user1', 'guest']),
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'timestamp': time.time(),
            'successful': random.choice([True, False])
        }
    elif event_type == 'service_change':
        return {
            'service': random.choice(['auth_service', 'api_gateway', 'user_service']),
            'change_type': random.choice(['code_update', 'configuration_change', 'dependency_update']),
            'commit_sha': ''.join(random.choices('abcdef1234567890', k=40))
        }
    else:  # network_traffic
        return {
            'source_ip': f'192.168.1.{random.randint(1, 254)}',
            'destination_ip': f'10.0.0.{random.randint(1, 254)}',
            'protocol': random.choice(['TCP', 'UDP', 'HTTP']),
            'packet_count': random.randint(10, 1000)
        }

if __name__ == "__main__":
    main()
