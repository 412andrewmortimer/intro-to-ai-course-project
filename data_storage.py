class DataStorage:
    """
    Simple data storage layer to persist analysis results and configurations.
    """
    def __init__(self):
        # Initialize storage containers
        self.data = {
            'login_analysis': [],
            'network_analysis': [],
            'service_impact_analysis': [],
            'mdp_decision': []
        }
        
    def store(self, category, data):
        """Store data in the specified category"""
        if category in self.data:
            self.data[category].append(data)
        else:
            self.data[category] = [data]
        
    def retrieve(self, category, limit=None):
        """Retrieve data from the specified category"""
        if category not in self.data:
            return []
            
        if limit:
            return self.data[category][-limit:]
        return self.data[category]
        
    def retrieve_latest(self, category):
        """Retrieve the latest data point from the specified category"""
        items = self.retrieve(category, 1)
        if items:
            return items[0]
        return None
