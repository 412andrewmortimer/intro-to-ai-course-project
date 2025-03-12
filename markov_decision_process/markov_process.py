class MarkovDecisionProcess:
    """
    MDP implementation for optimal security response policies.
    """
    def __init__(self, data_storage):
        self.data_storage = data_storage
        
        # Define a simple policy mapping from states and risk levels to actions
        self.policies = {
            'network_anomaly': {
                'low': 'Monitor traffic',
                'medium': 'Flag for manual review',
                'high': 'Block traffic and alert security team'
            },
            'login_failure': {
                'low': 'No action needed',
                'medium': 'Require additional authentication',
                'high': 'Lock account and initiate investigation'
            },
            'service_change': {
                'low': 'Deploy changes',
                'medium': 'Run additional security tests',
                'high': 'Roll back changes and investigate'
            }
        }
    
    def get_optimal_action(self, state, risk_level):
        """
        Determine the optimal action given the current state and risk level.
        """
        # Convert numerical risk to categorical
        risk_category = 'low'
        if risk_level > 0.7:
            risk_category = 'high'
        elif risk_level > 0.3:
            risk_category = 'medium'
        
        # Get the optimal action from the policy
        if state in self.policies and risk_category in self.policies[state]:
            action = self.policies[state][risk_category]
        else:
            action = "Default: Continue monitoring"
            
        # Store the decision
        self.data_storage.store('mdp_decision', {
            'state': state,
            'risk_level': risk_level,
            'risk_category': risk_category,
            'action': action
        })
        
        return action
