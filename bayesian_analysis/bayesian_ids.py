import random

class BayesianIDS:
    """
    Simple Bayesian analysis for intrusion detection systems.
    Based on the bayesian-analysis-for-intrusion-detection-system-longin-attpemts.ipynb example.
    """
    def __init__(self, data_storage):
        self.data_storage = data_storage
        
        # Define base probabilities based on the example
        self.p_attack = 0.02  # 2% probability that a request is an actual attack
        self.p_alert_given_attack = 0.90  # 90% probability of detecting an attack (true positive rate)
        self.p_alert_given_no_attack = 0.10  # 10% probability of a false positive alert
        
    def analyze_login_attempt(self, login_data):
        """
        Analyze a login attempt using Bayesian probability.
        Returns probability that the login attempt is a real attack.
        """
        # Adjust probabilities based on specific factors in the login data
        adjusted_p_attack = self.p_attack
        
        # Increase probability if the login is from an unusual source
        if login_data.get('source_ip', '').startswith('10.'):
            adjusted_p_attack *= 1.5  # External IP increases risk
            
        # Adjust for suspicious usernames
        if login_data.get('username') == 'admin':
            adjusted_p_attack *= 2  # Admin logins are higher risk targets
            
        # Adjust for failed login attempts
        if not login_data.get('successful', True):
            adjusted_p_attack *= 3  # Failed logins are more suspicious
            
        # Cap the probability at 1.0
        adjusted_p_attack = min(adjusted_p_attack, 0.95)
        
        # Calculate total probability of alert (using Law of Total Probability)
        p_alert = (self.p_alert_given_attack * adjusted_p_attack) + \
                  (self.p_alert_given_no_attack * (1 - adjusted_p_attack))
        
        # Calculate the probability of an attack given an alert (Bayes' Theorem)
        p_attack_given_alert = (self.p_alert_given_attack * adjusted_p_attack) / p_alert
        
        # Store the result in the data storage
        self.data_storage.store('login_analysis', {
            'timestamp': login_data.get('timestamp', 0),
            'username': login_data.get('username', ''),
            'source_ip': login_data.get('source_ip', ''),
            'attack_probability': p_attack_given_alert
        })
        
        return p_attack_given_alert
