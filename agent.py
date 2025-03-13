from bayesian_analysis.bayesian_ids import BayesianIDS
from bayesian_analysis.bayesian_network import BayesianNetwork
from markov_decision_process.markov_process import MarkovDecisionProcess
from service_impact.service_impact import ServiceImpactAnalyzer
from git_security.git_monitor import GitSecurityMonitor
from data_storage import DataStorage

class Agent:
    """
    Simple reflex agent that processes inputs and determines appropriate actions
    by coordinating different AI modules.
    """
    def __init__(self):
        # Initialize all modules
        self.data_storage = DataStorage()
        self.bayesian_ids = BayesianIDS(self.data_storage)
        self.bayesian_network = BayesianNetwork(self.data_storage)
        self.mdp = MarkovDecisionProcess(self.data_storage)
        self.service_impact = ServiceImpactAnalyzer(self.data_storage)
        self.git_monitor = GitSecurityMonitor(self.data_storage)
        
        print("Agent initialized with all modules")
    
    def process_event(self, event_type, event_data):
        """Process an event and determine the appropriate action"""
        # Simple reflex mapping from percepts to actions
        if event_type == 'login_attempt':
            # Use Bayesian analysis for login attempts
            attack_probability = self.bayesian_ids.analyze_login_attempt(event_data)
            
            # Also get MDP recommendation for login events
            mdp_action, mdp_description = self.mdp.analyze_event(event_type, event_data)
            
            if attack_probability > 0.7:
                return f"HIGH ALERT: Potential attack detected (confidence: {attack_probability:.2f}) - {mdp_description}"
            elif attack_probability > 0.3:
                return f"MEDIUM ALERT: Suspicious activity detected (confidence: {attack_probability:.2f}) - {mdp_description}"
            else:
                return f"LOW ALERT: Normal login activity (confidence: {1-attack_probability:.2f})"
                
        elif event_type == 'service_change':
            # Use service impact analysis for code/service changes
            self.service_impact.analyze_service_change(event_data)
            
            # Get the last stored analysis which includes the risk assessment
            analysis = self.data_storage.retrieve_latest('service_impact_analysis')
            
            if analysis and 'severity' in analysis:
                severity = analysis['severity']
                reason = analysis.get('reason', 'Unknown')
                
                if severity == 'critical':
                    return f"CRITICAL: {reason} - Immediate action required!"
                elif severity == 'high':
                    return f"HIGH IMPACT: {reason} - Action required"
                elif severity == 'medium':
                    return f"MEDIUM IMPACT: {reason} - Monitor closely"
                else:
                    return f"LOW IMPACT: {reason} - Normal procedure"
            else:
                return "Service change detected, impact unknown"
                
        elif event_type == 'network_traffic':
            # Use MDP for optimal decision making on network events
            action, description = self.mdp.analyze_event(event_type, event_data)
            
            # Also use Bayesian network for additional context
            attack_probability = self.bayesian_network.analyze_network_traffic(event_data)
            
            # Combine insights from both modules
            if attack_probability > 0.7:
                severity = "HIGH"
            elif attack_probability > 0.3:
                severity = "MEDIUM"
            else:
                severity = "LOW"
                
            return f"{severity} ALERT: Network traffic - {description} (Attack probability: {attack_probability:.2f})"
            
        elif event_type == 'git_activity':
            # Use git security monitor
            risk_level, risk_factors = self.git_monitor.analyze_git_activity(event_data)
            
            # Use MDP to help determine optimal response
            mdp_action, mdp_description = self.mdp.analyze_event(event_type, event_data)
            
            if risk_level == 'high':
                return f"HIGH RISK: Git activity - {', '.join(risk_factors[:2])} - {mdp_description}"
            elif risk_level == 'medium':
                return f"MEDIUM RISK: Git activity - {', '.join(risk_factors[:1])} - {mdp_description}"
            elif risk_level == 'low':
                return f"LOW RISK: Git activity - Normal behavior - {mdp_description}"
            else:
                return f"Git activity analyzed, risk level: {risk_level}"
        
        # Default for unknown event types
        return "Unknown event type, no action taken"
