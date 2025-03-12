class ServiceImpactAnalyzer:
    """
    DFS/BFS search algorithms for CI/CD pipeline optimization.
    Based on the simple-reflex-agent-DFS.ipynb example.
    """
    def __init__(self, data_storage):
        self.data_storage = data_storage
        
        # Define a service dependency tree similar to the descriptive_tree in the example
        self.service_tree = {
            "Frontend UI": {
                "Auth Service": {
                    "API Gateway": {
                        "User Service": {
                            "Profile Service": {}  
                        },
                        "Order Service": {
                            "Payment Service": {},    
                            "Inventory Service": {}   
                        },
                        "Notification Service": {
                            "Email Service": {}       
                        }
                    }
                }
            }
        }
        
        # Known suspicious patterns in commits
        self.suspicious_patterns = [
            "backdoor",
            "bypass auth",
            "disable security",
            "hardcoded password",
            "remove validation"
        ]
        
        # Mock database of known malicious commit hashes
        self.known_malicious_commits = [
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
            "9f8e7d6c5b4a9f8e7d6c5b4a9f8e7d6c5b4a9f8e"
        ]
    
    def analyze_service_change(self, change_data):
        """
        Analyze impact of service changes using DFS.
        Returns set of impacted services.
        """
        changed_service = change_data.get('service')
        commit_sha = change_data.get('commit_sha', '')
        change_type = change_data.get('change_type', '')
        
        # Check if the commit is suspicious
        commit_risk = self.analyze_commit_risk(commit_sha, change_type)
        
        # Using DFS to find the subtree of the changed service
        subtree = self.find_subtree(self.service_tree, changed_service)
        
        if subtree is None:
            return set()
            
        # Get all descendants of the changed service
        impacted_services = {changed_service}
        impacted_services.update(self.get_all_descendants(subtree))
        
        # Store the result with risk assessment
        self.data_storage.store('service_impact_analysis', {
            'changed_service': changed_service,
            'change_type': change_type,
            'commit_sha': commit_sha,
            'impacted_services': list(impacted_services),
            'commit_risk': commit_risk
        })
        
        return impacted_services
    
    def analyze_commit_risk(self, commit_sha, change_type):
        """
        Analyze commit content to determine if it's suspicious.
        Returns risk level: 'low', 'medium', or 'high'.
        
        In a real implementation, this would analyze actual commit content.
        This is a simplified demonstration.
        """
        # Check if commit is in our known malicious database
        if commit_sha in self.known_malicious_commits:
            return 'high'
        
        # For demonstration purposes, simulate finding suspicious patterns 
        # based on commit SHA characters (would be actual code analysis in real life)
        # Using first characters as a proxy for actual content analysis
        first_chars = commit_sha[:6] if commit_sha else ''
        
        # Check for suspicious patterns (simplified simulation)
        risk_score = 0
        
        # Higher risk for configuration changes
        if change_type == 'configuration_change':
            risk_score += 0.3
        
        # Simulate finding suspicious patterns based on commit characters
        for pattern in self.suspicious_patterns:
            # This is a simplified simulation - in real life we would 
            # analyze actual commit content
            if any(c in pattern for c in first_chars):
                risk_score += 0.2
        
        # Determine risk level
        if risk_score > 0.6:
            return 'high'
        elif risk_score > 0.3:
            return 'medium'
        else:
            return 'low'
        
    def find_subtree(self, tree, target_service):
        """
        Find the subtree for the target service using DFS.
        Based on find_subtree_actuator from the example.
        """
        stack = [(tree, None)]
        
        while stack:
            current, _ = stack.pop()
            
            if target_service in current:
                return current[target_service]
                
            for key, subtree in current.items():
                stack.append((subtree, key))
                
        return None
        
    def get_all_descendants(self, subtree):
        """
        Get all descendants of a subtree recursively.
        Based on get_all_descendants from the example.
        """
        nodes = set()
        
        for key, children in subtree.items():
            nodes.add(key)
            nodes.update(self.get_all_descendants(children))
            
        return nodes
