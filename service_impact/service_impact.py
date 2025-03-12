import datetime
import random

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
        
        # Replace the simple list of known malicious commits with more sophisticated detection methods
        
        # Suspicious code patterns (regex-compatible)
        self.suspicious_code_patterns = {
            'backdoor': r'(?i)(backdoor|back[\s_-]?door)',
            'auth_bypass': r'(?i)(bypass|skip|avoid)[\s_-]*(auth|authentication|authorization)',
            'hardcoded_credentials': r'(?i)(password|credential|token|key|secret)\s*=\s*["\'][^"\']{5,}["\']',
            'security_disable': r'(?i)(disable|turn[\s_-]?off|bypass)[\s_-]*(security|authentication|firewall|validation)',
            'command_injection': r'(?i)(system|exec|eval|subprocess\.call|os\.system|shell_exec)',
            'insecure_deserialize': r'(?i)(pickle\.loads|yaml\.load\([^)]*\)|marshal\.loads)',
            'sql_injection': r'(?i)(execute|executeQuery)\([^)]*\+|SELECT\s+.*\s+FROM.*\+',
        }
        
        # Metadata-based risk factors
        self.metadata_risk_factors = {
            'high_risk_files': ['security.py', 'auth.py', 'login.py', 'password.py', 'credentials.py', 'config.py'],
            'high_risk_directories': ['/security/', '/auth/', '/login/', '/admin/', '/config/'],
            'high_risk_time': [(0, 5)],  # Hours (start, end) for suspicious commit times (midnight to 5am)
            'suspicious_commit_messages': ['fix', 'update', 'change', 'quick', 'temp', 'test']
        }
        
        # Historical behavior patterns (would be built over time in a real system)
        self.developer_behavior_patterns = {}
        
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
    
    def analyze_commit_risk(self, commit_sha, change_type, commit_data=None):
        """
        Analyze commit content and metadata to determine if it's suspicious.
        Returns risk level: 'low', 'medium', or 'high'.
        
        commit_data: Optional dictionary with additional metadata like:
            - 'files_changed': list of file paths modified
            - 'author': commit author
            - 'message': commit message
            - 'time': commit timestamp
            - 'diff': actual code diff content
        """
        if commit_data is None:
            # For simulation, generate mock data based on commit_sha
            # In a real system, this would come from Git API or similar
            commit_data = self._generate_mock_commit_data(commit_sha, change_type)
        
        risk_score = 0
        risk_factors = []
        
        # 1. Content Analysis
        if 'diff' in commit_data:
            code_risk, code_factors = self._analyze_code_content(commit_data['diff'])
            risk_score += code_risk
            risk_factors.extend(code_factors)
        
        # 2. Metadata Analysis
        metadata_risk, metadata_factors = self._analyze_commit_metadata(commit_data)
        risk_score += metadata_risk
        risk_factors.extend(metadata_factors)
        
        # 3. Contextual Analysis - which files were changed and their sensitivity
        context_risk, context_factors = self._analyze_context(commit_data)
        risk_score += context_risk
        risk_factors.extend(context_factors)
        
        # 4. Behavioral Analysis (if author data available)
        if 'author' in commit_data:
            behavior_risk, behavior_factors = self._analyze_developer_behavior(commit_data)
            risk_score += behavior_risk
            risk_factors.extend(behavior_factors)
        
        # Store detailed analysis in data storage
        self.data_storage.store('commit_analysis', {
            'commit_sha': commit_sha,
            'risk_score': risk_score,
            'risk_factors': risk_factors
        })
        
        # Determine final risk level
        if risk_score > 0.7:
            return 'high'
        elif risk_score > 0.3:
            return 'medium'
        else:
            return 'low'
    
    def _analyze_code_content(self, diff_content):
        """Analyze actual code changes for suspicious patterns"""
        risk_score = 0
        risk_factors = []
        
        # Check for suspicious code patterns
        for pattern_name, regex in self.suspicious_code_patterns.items():
            import re
            # Count matches of this pattern
            matches = len(re.findall(regex, diff_content))
            if matches > 0:
                pattern_risk = min(0.3 * matches, 0.6)  # Cap at 0.6
                risk_score += pattern_risk
                risk_factors.append(f"Suspicious code pattern: {pattern_name} ({matches} instances)")
        
        return risk_score, risk_factors
    
    def _analyze_commit_metadata(self, commit_data):
        """Analyze commit metadata (author, time, message)"""
        risk_score = 0
        risk_factors = []
        
        # Check commit message for vagueness or suspicious wording
        if 'message' in commit_data:
            message = commit_data['message'].lower()
            # Check if message is very short (vague)
            if len(message) < 10:
                risk_score += 0.2
                risk_factors.append("Very short commit message")
            
            # Check for suspicious keywords in commit message
            for keyword in self.metadata_risk_factors['suspicious_commit_messages']:
                if keyword in message and len(message.split()) < 4:
                    risk_score += 0.15
                    risk_factors.append(f"Vague/suspicious commit message: '{message}'")
                    break
        
        # Check commit time if available
        if 'time' in commit_data and hasattr(commit_data['time'], 'hour'):
            hour = commit_data['time'].hour
            for start, end in self.metadata_risk_factors['high_risk_time']:
                if start <= hour < end:
                    risk_score += 0.25
                    risk_factors.append(f"Unusual commit time: {hour}:00")
        
        return risk_score, risk_factors
    
    def _analyze_context(self, commit_data):
        """Analyze which files were modified and their sensitivity"""
        risk_score = 0
        risk_factors = []
        
        if 'files_changed' in commit_data:
            high_risk_files = 0
            for file_path in commit_data['files_changed']:
                # Check if file is in high-risk category
                if any(risk_file in file_path for risk_file in self.metadata_risk_factors['high_risk_files']):
                    high_risk_files += 1
                    risk_factors.append(f"Modified sensitive file: {file_path}")
                
                # Check if file is in high-risk directory
                if any(risk_dir in file_path for risk_dir in self.metadata_risk_factors['high_risk_directories']):
                    high_risk_files += 1
                    risk_factors.append(f"Modified file in sensitive directory: {file_path}")
            
            # Calculate risk based on proportion of high-risk files
            if 'files_changed' in commit_data and len(commit_data['files_changed']) > 0:
                risk_score += min(0.5 * high_risk_files / len(commit_data['files_changed']), 0.5)
        
        return risk_score, risk_factors
    
    def _analyze_developer_behavior(self, commit_data):
        """Analyze developer behavior for anomalies"""
        risk_score = 0
        risk_factors = []
        
        author = commit_data.get('author', '')
        
        # In a real system, you would compare against historical patterns
        # Since we don't have that data, we'll just simulate it
        if author and author not in self.developer_behavior_patterns:
            risk_score += 0.15
            risk_factors.append(f"First commit from author: {author}")
        
        return risk_score, risk_factors
    
    def _generate_mock_commit_data(self, commit_sha, change_type):
        """Generate mock commit data for simulation purposes"""
        
        # Generate mock data
        mock_data = {
            'author': f"user{random.randint(1,5)}@example.com",
            'message': random.choice([
                "Fixed bug",
                "Updated documentation",
                "Added new feature",
                "Refactored code"
            ]),
            'time': datetime.datetime.now().replace(
                hour=random.randint(9, 17)
            ),
            'files_changed': []
        }
        
        # Generate appropriate files based on the service
        if change_type == 'configuration_change':
            mock_data['files_changed'] = [
                "config/settings.py",
                "deployment/env.yaml"
            ]
        else:
            mock_data['files_changed'] = [
                "services/api/endpoints.py",
                "models/data.py"
            ]
        
        # Generate mock code diff
        mock_data['diff'] = """
        +    logger.info("Processing user request")
        ...
        -    return data.process()
        +    return data.process_with_validation()
        """
            
        return mock_data
    
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
