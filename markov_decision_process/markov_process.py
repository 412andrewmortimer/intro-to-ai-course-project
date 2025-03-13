"""
Markov Decision Process Module for Cybersecurity Response

Implements a Markov Decision Process (MDP) to determine optimal security responses
to different threat scenarios.
"""

import time
from enum import Enum, auto
import numpy as np


class State(Enum):
    """System security states"""
    NO_THREAT = auto()        # Normal operation, no detected threats
    SUSPICIOUS = auto()       # Some suspicious activity detected, but not confirmed
    ATTACK = auto()           # Active attack detected
    COMPROMISED = auto()      # System compromised


class Action(Enum):
    """Possible security actions"""
    MONITOR = auto()          # Continue normal monitoring
    INVESTIGATE = auto()      # Investigate suspicious activity
    MITIGATE = auto()         # Apply mitigation measures
    RECOVER = auto()          # Enter recovery mode


class MarkovDecisionProcess:
    """
    Implements a Markov Decision Process for cybersecurity decision making.
    Uses the principle of maximum expected utility to determine the best
    security response in different threat scenarios.
    """
    
    def __init__(self, data_storage):
        """
        Initialize the MDP with transition probabilities, rewards, and states.
        
        Args:
            data_storage: The data storage module for reading/writing analysis results
        """
        self.data_storage = data_storage
        
        # Define transition probabilities P(s'|s,a)
        # Format: {action: {current_state: {next_state: probability}}}
        self.transition_probs = {
            Action.MONITOR: {
                State.NO_THREAT: {State.NO_THREAT: 0.95, State.SUSPICIOUS: 0.05},
                State.SUSPICIOUS: {State.NO_THREAT: 0.1, State.SUSPICIOUS: 0.8, State.ATTACK: 0.1},
                State.ATTACK: {State.ATTACK: 0.8, State.COMPROMISED: 0.2},
                State.COMPROMISED: {State.COMPROMISED: 1.0},
            },
            Action.INVESTIGATE: {
                State.NO_THREAT: {State.NO_THREAT: 0.98, State.SUSPICIOUS: 0.02},
                State.SUSPICIOUS: {State.NO_THREAT: 0.4, State.SUSPICIOUS: 0.5, State.ATTACK: 0.1},
                State.ATTACK: {State.SUSPICIOUS: 0.2, State.ATTACK: 0.7, State.COMPROMISED: 0.1},
                State.COMPROMISED: {State.ATTACK: 0.1, State.COMPROMISED: 0.9},
            },
            Action.MITIGATE: {
                State.NO_THREAT: {State.NO_THREAT: 0.99, State.SUSPICIOUS: 0.01},
                State.SUSPICIOUS: {State.NO_THREAT: 0.7, State.SUSPICIOUS: 0.3},
                State.ATTACK: {State.NO_THREAT: 0.2, State.SUSPICIOUS: 0.5, State.ATTACK: 0.3},
                State.COMPROMISED: {State.ATTACK: 0.3, State.COMPROMISED: 0.7},
            },
            Action.RECOVER: {
                State.NO_THREAT: {State.NO_THREAT: 0.95, State.SUSPICIOUS: 0.05},
                State.SUSPICIOUS: {State.NO_THREAT: 0.5, State.SUSPICIOUS: 0.5},
                State.ATTACK: {State.NO_THREAT: 0.4, State.SUSPICIOUS: 0.4, State.ATTACK: 0.2},
                State.COMPROMISED: {State.NO_THREAT: 0.5, State.SUSPICIOUS: 0.3, State.ATTACK: 0.2},
            }
        }
        
        # Define rewards R(s,a,s') - rewards for taking action in state and ending in next_state
        # Format: {state: {action: reward}}
        self.rewards = {
            State.NO_THREAT: {
                Action.MONITOR: 10,        # Good to monitor when no threat
                Action.INVESTIGATE: -5,    # Waste of resources
                Action.MITIGATE: -20,      # Major waste of resources
                Action.RECOVER: -50        # Extremely disruptive when not needed
            },
            State.SUSPICIOUS: {
                Action.MONITOR: 0,         # Neutral - could be fine or miss threat
                Action.INVESTIGATE: 15,    # Good to investigate suspicious activity
                Action.MITIGATE: -5,       # Somewhat premature
                Action.RECOVER: -30        # Very premature
            },
            State.ATTACK: {
                Action.MONITOR: -30,       # Bad to just monitor during attack
                Action.INVESTIGATE: 5,     # Better but not sufficient
                Action.MITIGATE: 25,       # Good response
                Action.RECOVER: 5          # Might be premature
            },
            State.COMPROMISED: {
                Action.MONITOR: -100,      # Very bad to ignore compromise
                Action.INVESTIGATE: -20,   # Too late for just investigation
                Action.MITIGATE: 5,        # Helps but not enough
                Action.RECOVER: 50         # Best response
            }
        }
        
        # Set discount factor for future rewards (0 < gamma <= 1)
        self.gamma = 0.9
        
        # Initialize utility values for each state
        self.utilities = {state: 0 for state in State}
        
        # Compute the optimal policy using value iteration
        self.optimal_policy = self._compute_optimal_policy()
        
        print("Markov Decision Process initialized")
    
    def _compute_optimal_policy(self, max_iterations=100, epsilon=0.01):
        """
        Compute optimal policy using value iteration algorithm
        
        Args:
            max_iterations (int): Maximum number of iterations
            epsilon (float): Convergence threshold
            
        Returns:
            dict: Optimal policy mapping states to actions
        """
        # Initialize utilities
        utilities = {state: 0 for state in State}
        
        # Value iteration
        for i in range(max_iterations):
            prev_utilities = utilities.copy()
            delta = 0
            
            for state in State:
                # Calculate the expected utility for each action
                action_values = {}
                
                for action in Action:
                    # Calculate expected utility for this state-action pair
                    expected_utility = 0
                    
                    for next_state in State:
                        # Transition probability
                        prob = self.transition_probs[action][state].get(next_state, 0)
                        
                        if prob > 0:
                            # Reward for this transition
                            reward = self.rewards[state][action]
                            
                            # Expected utility contribution
                            expected_utility += prob * (reward + self.gamma * prev_utilities[next_state])
                    
                    action_values[action] = expected_utility
                
                # Find the action with maximum expected utility
                best_action = max(action_values, key=action_values.get)
                utilities[state] = action_values[best_action]
                
                # Track the maximum change in utility
                delta = max(delta, abs(utilities[state] - prev_utilities[state]))
            
            # Check for convergence
            if delta < epsilon:
                break
        
        # Compute the optimal policy based on final utilities
        optimal_policy = {}
        for state in State:
            action_values = {}
            
            for action in Action:
                expected_utility = 0
                
                for next_state in State:
                    prob = self.transition_probs[action][state].get(next_state, 0)
                    if prob > 0:
                        reward = self.rewards[state][action]
                        expected_utility += prob * (reward + self.gamma * utilities[next_state])
                
                action_values[action] = expected_utility
            
            optimal_policy[state] = max(action_values, key=action_values.get)
        
        self.utilities = utilities
        return optimal_policy
    
    def determine_current_state(self, event_data):
        """
        Determine the current system state based on event data
        
        Args:
            event_data (dict): Event data to analyze
            
        Returns:
            State: The current system state
        """
        # For network traffic analysis
        if 'protocol' in event_data and 'packet_count' in event_data:
            source_ip = event_data.get('source_ip', '')
            packet_count = event_data.get('packet_count', 0)
            protocol = event_data.get('protocol', '')
            
            # External IP with high volume might indicate attack
            if not source_ip.startswith('192.168.') and packet_count > 500:
                if protocol == 'UDP' and packet_count > 800:
                    return State.ATTACK
                return State.SUSPICIOUS
            
            # High internal traffic might be suspicious
            if packet_count > 900:
                return State.SUSPICIOUS
                
            return State.NO_THREAT
            
        # For login attempts
        elif 'username' in event_data and 'successful' in event_data:
            username = event_data.get('username', '')
            successful = event_data.get('successful', True)
            
            # Failed admin login is highly suspicious
            if username == 'admin' and not successful:
                return State.SUSPICIOUS
                
            return State.NO_THREAT
            
        # Default conservative approach
        return State.SUSPICIOUS
    
    def analyze_event(self, event_type, event_data):
        """
        Analyze an event and determine the optimal action using the MDP
        
        Args:
            event_type (str): Type of event
            event_data (dict): Event data
            
        Returns:
            tuple: (optimal_action, description)
        """
        # Determine current state from event data
        current_state = self.determine_current_state(event_data)
        
        # Get the optimal action for this state from our policy
        optimal_action = self.optimal_policy[current_state]
        
        # Calculate the expected utility of this action
        expected_utility = 0
        for next_state in State:
            prob = self.transition_probs[optimal_action][current_state].get(next_state, 0)
            if prob > 0:
                reward = self.rewards[current_state][optimal_action]
                expected_utility += prob * (reward + self.gamma * self.utilities[next_state])
                
        # Store the decision in data storage
        analysis_result = {
            'timestamp': event_data.get('timestamp', time.time()),
            'event_type': event_type,
            'current_state': current_state.name,
            'recommended_action': optimal_action.name,
            'expected_utility': expected_utility,
            'confidence': self._calculate_confidence(current_state, optimal_action)
        }
        
        self.data_storage.store('mdp_decision', analysis_result)
        
        # Generate action description
        description = self._get_action_description(optimal_action, current_state)
        
        return optimal_action.name, description
    
    def _calculate_confidence(self, state, action):
        """
        Calculate confidence level in the recommended action.

        The confidence score is determined based on the difference between the 
        expected utility of the selected action and the second-best action. 

        Confidence is normalized between 0.5 and 1.0 to reflect certainty levels.

        Args:
            state (State): Current security state.
            action (Action): Recommended security action.

        Returns:
            float: Confidence score between 0.5 and 1.0.
        """
        # Step 1: Compute the expected utility for each possible action
        action_utilities = {}
        
        for a in Action:
            utility = 0
            
            for next_state in State:
                # Transition probability P(s' | s, a)
                prob = self.transition_probs[a][state].get(next_state, 0)

                if prob > 0:
                    # Expected utility formula:
                    # U(a) = Σ P(s' | s, a) * (R(s, a) + γ * U(s'))
                    reward = self.rewards[state][a]
                    utility += prob * (reward + self.gamma * self.utilities[next_state])

            action_utilities[a] = utility

        # Step 2: Identify the best action utility
        best_utility = action_utilities[action]

        # Step 3: Find the second-best action utility
        second_best = max((u for a, u in action_utilities.items() if a != action), default=0)

        # Step 4: Compute advantage (difference between best and second-best)
        # Advantage = U(best) - U(second-best)
        advantage = best_utility - second_best

        # Step 5: Normalize the confidence score between 0.5 and 1.0
        # Formula: C = min(0.5 + Advantage / 100, 1.0)
        # Ensures that confidence remains above 0.5, but scales with utility difference.
        confidence = min(0.5 + advantage / 100, 1.0)

        # If all actions have very similar utilities, set confidence to 0.5 (uncertain decision)
        if all(abs(u - best_utility) < 1e-6 for u in action_utilities.values()):
            confidence = 0.5

        return confidence
    
    def _get_action_description(self, action, state):
        """
        Generate a human-readable description of the action
        
        Args:
            action (Action): The recommended action
            state (State): Current state
            
        Returns:
            str: Description of the action
        """
        if action == Action.MONITOR:
            return "Continue monitoring, no significant threat detected."
            
        elif action == Action.INVESTIGATE:
            if state == State.SUSPICIOUS:
                return "Investigate suspicious activity for potential threats."
            else:
                return "Further investigation recommended as a precautionary measure."
                
        elif action == Action.MITIGATE:
            if state == State.ATTACK:
                return "Mitigate ongoing attack by implementing security controls."
            else:
                return "Apply preventative security measures to address potential threat."
                
        elif action == Action.RECOVER:
            if state == State.COMPROMISED:
                return "Initiate recovery procedures to restore system integrity."
            else:
                return "Consider system restoration as a precautionary measure."
        
        return "No specific action recommended."
