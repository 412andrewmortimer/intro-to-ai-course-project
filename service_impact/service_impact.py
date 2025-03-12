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
    
    def analyze_service_change(self, change_data):
        """
        Analyze impact of service changes using DFS.
        Returns set of impacted services.
        """
        changed_service = change_data.get('service')
        
        # Using DFS to find the subtree of the changed service
        subtree = self.find_subtree(self.service_tree, changed_service)
        
        if subtree is None:
            return set()
            
        # Get all descendants of the changed service
        impacted_services = {changed_service}
        impacted_services.update(self.get_all_descendants(subtree))
        
        # Store the result
        self.data_storage.store('service_impact_analysis', {
            'changed_service': changed_service,
            'change_type': change_data.get('change_type', ''),
            'commit_sha': change_data.get('commit_sha', ''),
            'impacted_services': list(impacted_services)
        })
        
        return impacted_services
        
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
