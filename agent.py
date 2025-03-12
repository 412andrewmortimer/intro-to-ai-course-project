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
            
            if attack_probability > 0.7:
                return f"HIGH ALERT: Potential attack detected (confidence: {attack_probability:.2f})"
            elif attack_probability > 0.3:
                return f"MEDIUM ALERT: Suspicious activity detected (confidence: {attack_probability:.2f})"
            else:
                return f"LOW ALERT: Normal login activity (confidence: {1-attack_probability:.2f})"
                
        elif event_type == 'service_change':
            # Use service impact analysis for code/service changes
            impacted_services = self.service_impact.analyze_service_change(event_data)
            
            # Get the last stored analysis which includes the risk assessment
            analysis = self.data_storage.retrieve_latest('service_impact_analysis')
            commit_risk = 'unknown'
            if analysis and 'commit_risk' in analysis:
                commit_risk = analysis['commit_risk']
            
            # Respond based on risk and impact
            if commit_risk == 'high':
                return f"SECURITY ALERT: Suspicious commit detected in {event_data['service']}! Impacts {len(impacted_services)} services. Recommend immediate review."
            elif commit_risk == 'medium':
                return f"MEDIUM RISK: Potentially concerning change in {event_data['service']} affecting {len(impacted_services)} services. Review recommended."
            elif impacted_services:
                return f"SERVICE ALERT: Change in {event_data['service']} impacts {len(impacted_services)} services"
            else:
                return f"Service change in {event_data['service']} has no downstream impacts"
                
        elif event_type == 'network_traffic':
            # Use Bayesian network for complex traffic analysis
            evidence = {
                'traffic_volume': 'high' if event_data['packet_count'] > 500 else 'low',
                'protocol': event_data['protocol'],
                'internal_source': event_data['source_ip'].startswith('192.168')
            }
            
            risk_assessment = self.bayesian_network.analyze_network_traffic(evidence)
            optimal_action = self.mdp.get_optimal_action('network_anomaly', risk_assessment)
            
            return f"NETWORK ACTION: {optimal_action} (risk level: {risk_assessment:.2f})"
            
        elif event_type == 'git_activity':
            # Use Git security monitor for git-related events
            risk_level, risk_factors = self.git_monitor.analyze_git_activity(event_data)
            
            if risk_level == 'high':
                return f"GIT SECURITY ALERT: High-risk activity detected in {event_data.get('repo_name', 'repository')}! Key factors: {'; '.join(risk_factors[:2])}"
            elif risk_level == 'medium':
                return f"GIT SECURITY WARNING: Potentially suspicious activity in {event_data.get('repo_name', 'repository')}. Review recommended."
            else:
                return f"Git activity monitored in {event_data.get('repo_name', 'repository')} - no significant concerns"
            
        else:
            return "Unknown event type, no action taken"
