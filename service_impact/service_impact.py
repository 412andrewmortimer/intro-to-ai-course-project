"""
Service Impact Analysis Module

Uses graph traversal algorithms to analyze the impact of changes to services
in a microservice architecture.
"""

import time
from service_impact.service_dependencies import ServiceDependencies

class ServiceImpactAnalyzer:
    """
    Analyzes the impact of service changes using graph algorithms.
    Determines which services will be affected by changes to a particular service.
    """
    
    def __init__(self, data_storage):
        """
        Initialize the service impact analyzer
        
        Args:
            data_storage: The data storage module for storing analysis results
        """
        self.data_storage = data_storage
        self.service_deps = ServiceDependencies()  # Default dependencies
        print("Service Impact Analyzer initialized")
    
    def analyze_service_change(self, event_data):
        """
        Analyze the impact of a service change
        
        Args:
            event_data (dict): Information about the service change
            
        Returns:
            list: Services affected by this change
        """
        service = event_data.get('service', 'unknown_service')
        commit_sha = event_data.get('commit_sha', None)
        change_type = event_data.get('change_type', 'unknown_change')
        
        # Get impact assessment
        impact_analysis = self.service_deps.get_impact_severity(service, commit_sha)
        
        # Add additional information to the analysis
        impact_analysis.update({
            'timestamp': event_data.get('timestamp', time.time()),
            'service': service,
            'change_type': change_type,
            'commit_sha': commit_sha
        })
        
        # Store the analysis in the data storage
        self.data_storage.store('service_impact_analysis', impact_analysis)
        
        # Return the impacted services
        return impact_analysis.get('affected_services', [])
