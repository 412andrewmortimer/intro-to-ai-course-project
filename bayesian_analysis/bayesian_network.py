class BayesianNetwork:
    """
    Extended Bayesian network model incorporating multiple security factors.
    Based on the mortimer-bayesian-network-formatted example.
    """
    def __init__(self, data_storage):
        self.data_storage = data_storage
        
        # Define conditional probability tables based on the example
        
        # Attack probability
        self.CPT_A = {'A=1': 0.02, 'A=0': 0.98}  
        
        # Traffic volume influence on alerts
        self.CPT_volume = {
            'high': {'alert=1': 0.7, 'alert=0': 0.3},
            'low': {'alert=1': 0.2, 'alert=0': 0.8}
        }
        
        # Protocol influence on alerts
        self.CPT_protocol = {
            'TCP': {'alert=1': 0.3, 'alert=0': 0.7},
            'UDP': {'alert=1': 0.4, 'alert=0': 0.6},
            'HTTP': {'alert=1': 0.2, 'alert=0': 0.8}
        }
        
        # Source IP influence
        self.CPT_source = {
            True: {'alert=1': 0.1, 'alert=0': 0.9},  # Internal source
            False: {'alert=1': 0.6, 'alert=0': 0.4}   # External source
        }
        
    def analyze_network_traffic(self, evidence):
        """
        Analyze network traffic using Bayesian network.
        Returns probability of malicious activity.
        """
        # Extract evidence
        traffic_volume = evidence.get('traffic_volume', 'low')
        protocol = evidence.get('protocol', 'TCP')
        internal_source = evidence.get('internal_source', True)
        
        # Calculate the probability using simplified Bayesian inference
        # This is a simplified calculation - a full Bayesian network would be more complex
        p_volume = self.CPT_volume[traffic_volume]['alert=1']
        p_protocol = self.CPT_protocol[protocol]['alert=1']
        p_source = self.CPT_source[internal_source]['alert=1']
        
        # Combine probabilities - simplified approach
        combined_probability = (0.4 * p_volume + 0.3 * p_protocol + 0.3 * p_source)
        
        # Store the result
        self.data_storage.store('network_analysis', {
            'traffic_volume': traffic_volume,
            'protocol': protocol,
            'internal_source': internal_source,
            'risk_probability': combined_probability
        })
        
        return combined_probability
