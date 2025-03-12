"""
Service Dependencies Module

Defines the microservice architecture graph and provides functions to analyze
downstream impacts when services change.
"""

class ServiceDependencies:
    def __init__(self):
        """
        Initialize the service dependency graph representing the microservice architecture
        """
        # Service dependency graph: {service: [services that depend on it]}
        self.dependency_graph = {
            'Auth Service': ['API Gateway', 'User Service', 'Payment Service'],
            'API Gateway': ['Web Frontend', 'Mobile App'],
            'User Service': ['API Gateway', 'Notification Service'],
            'Payment Service': ['API Gateway', 'Order Service'],
            'Database Service': ['Auth Service', 'User Service', 'Payment Service', 'Order Service'],
            'Notification Service': ['Web Frontend', 'Mobile App'],
            'Order Service': ['API Gateway', 'Web Frontend'],
            'Web Frontend': [],
            'Mobile App': [],
            'Logging Service': ['Auth Service', 'API Gateway', 'User Service', 'Payment Service',
                               'Database Service', 'Notification Service', 'Order Service'],
        }
        
        # Reverse mapping for easier lookup of what a service depends on
        self.upstream_dependencies = self._build_upstream_dependencies()
        
        # Service criticality levels (0-10 scale)
        self.service_criticality = {
            'Auth Service': 10,
            'API Gateway': 9,
            'Database Service': 10,
            'User Service': 7,
            'Payment Service': 9,
            'Order Service': 8,
            'Notification Service': 5,
            'Web Frontend': 7,
            'Mobile App': 7,
            'Logging Service': 4,
        }
        
        # Known problematic commits (would typically be loaded from a database)
        self.known_issues = {
            'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2': {
                'description': 'Known security vulnerability',
                'severity': 'critical',
                'affected_services': ['Auth Service', 'API Gateway']
            }
        }
    
    def _build_upstream_dependencies(self):
        """Build reverse dependency map (what each service depends on)"""
        upstream = {service: [] for service in self.dependency_graph}
        
        for service, dependents in self.dependency_graph.items():
            for dependent in dependents:
                if dependent in upstream:
                    upstream[dependent].append(service)
        
        return upstream
    
    def get_downstream_impacts(self, service):
        """
        Get all services that would be impacted by a change to the specified service
        
        Args:
            service (str): The service being changed
            
        Returns:
            list: List of services that depend on the changed service (directly or indirectly)
        """
        if service not in self.dependency_graph:
            return []
            
        # Use DFS to find all impacted services
        visited = set()
        
        def dfs(current_service):
            if current_service in visited:
                return
                
            visited.add(current_service)
            
            for dependent in self.dependency_graph.get(current_service, []):
                dfs(dependent)
        
        # Start DFS from the specified service
        dfs(service)
        
        # Remove the starting service from the results
        if service in visited:
            visited.remove(service)
            
        return list(visited)
    
    def get_impact_severity(self, service, commit_sha=None):
        """
        Calculate the severity of impact for a service change
        
        Args:
            service (str): The service being changed
            commit_sha (str, optional): The SHA of the commit
            
        Returns:
            dict: Impact analysis including severity level and affected services
        """
        # Check for known problematic commits
        if commit_sha and commit_sha in self.known_issues:
            issue = self.known_issues[commit_sha]
            if service in issue['affected_services']:
                return {
                    'severity': issue['severity'],
                    'reason': issue['description'],
                    'affected_services': issue['affected_services'],
                    'total_impact_score': 10  # Maximum severity for known issues
                }
        
        # Get impacted services
        impacted = self.get_downstream_impacts(service)
        
        # Calculate impact severity based on the criticality of impacted services
        impact_score = 0
        for impacted_service in impacted:
            impact_score += self.service_criticality.get(impacted_service, 5)
        
        # Normalize the score
        if impacted:
            impact_score = min(10, impact_score / len(impacted))
        
        # Determine impact severity category
        if impact_score >= 8:
            severity = 'high'
        elif impact_score >= 5:
            severity = 'medium'
        else:
            severity = 'low'
            
        return {
            'severity': severity,
            'reason': f"Change impacts {len(impacted)} downstream services",
            'affected_services': impacted,
            'total_impact_score': impact_score
        }
