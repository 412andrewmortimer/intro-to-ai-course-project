import datetime
import re
import random
from collections import defaultdict

class GitSecurityMonitor:
    """
    Monitors Git repositories for suspicious activity patterns beyond just commit content.
    Looks at repository-wide behavioral patterns, committer behaviors, and temporal anomalies.
    """
    def __init__(self, data_storage):
        self.data_storage = data_storage
        
        # Repository activity baselines (would be learned over time in a real system)
        self.repo_baselines = {
            'commit_frequency': {
                'daily_avg': 5.2,
                'hourly_distribution': [0.01, 0.01, 0.01, 0.01, 0.02, 0.03, 0.05, 0.08, 0.10, 
                                      0.12, 0.12, 0.11, 0.08, 0.09, 0.10, 0.08, 0.06, 0.04, 
                                      0.03, 0.02, 0.01, 0.01, 0.01, 0.01]  # 24 hours
            },
            'branch_activity': {
                'daily_branch_creation': 0.8,  # branches created per day on average
                'branch_lifetime_days': 4.5    # average time before merge or deletion
            }
        }
        
        # User activity baselines
        self.user_baselines = defaultdict(lambda: {
            'active_hours': [(9, 17)],  # typical working hours
            'avg_files_per_commit': 3.2,
            'common_file_patterns': [r'.*\.py$', r'.*\.md$', r'.*\.json$'],
            'commit_frequency': 2.4,    # commits per day
        })
        
        # Security sensitive areas in the repo
        self.sensitive_paths = [
            r'security/.*',
            r'auth/.*', 
            r'.*password.*',
            r'.*credential.*',
            r'.*config.*',
            r'.*secret.*',
            r'.*/\.env.*'
        ]
    
    def analyze_git_activity(self, git_event):
        """
        Analyze various git-related events for security issues.
        
        git_event: A dictionary containing information about a git event:
            - event_type: 'push', 'clone', 'branch_created', 'branch_deleted', etc.
            - repo_name: Name of the repository
            - user: Username performing the action
            - timestamp: When the event occurred
            - ip_address: Source IP of the event
            - commits: List of commit details if applicable
            - branch_name: Branch name if applicable
        """
        event_type = git_event.get('event_type')
        risk_score = 0
        risk_factors = []
        
        # Process different types of git events
        if event_type == 'push':
            push_risk, push_factors = self._analyze_push_event(git_event)
            risk_score += push_risk
            risk_factors.extend(push_factors)
            
        elif event_type == 'clone':
            clone_risk, clone_factors = self._analyze_clone_event(git_event)
            risk_score += clone_risk
            risk_factors.extend(clone_factors)
            
        elif event_type == 'branch':
            branch_risk, branch_factors = self._analyze_branch_event(git_event)
            risk_score += branch_risk
            risk_factors.extend(branch_factors)
        
        # Additional event types can be added
        
        # Store analysis results
        self.data_storage.store('git_activity_analysis', {
            'timestamp': git_event.get('timestamp', datetime.datetime.now().timestamp()),
            'event_type': event_type,
            'repo': git_event.get('repo_name', ''),
            'user': git_event.get('user', ''),
            'risk_score': risk_score,
            'risk_factors': risk_factors
        })
        
        # Determine risk level
        if risk_score > 0.7:
            risk_level = 'high'
        elif risk_score > 0.3:
            risk_level = 'medium'
        else:
            risk_level = 'low'
            
        return risk_level, risk_factors
    
    def _analyze_push_event(self, event):
        """Analyze a push event for suspicious patterns"""
        risk_score = 0
        risk_factors = []
        
        user = event.get('user', '')
        timestamp = event.get('timestamp', datetime.datetime.now())
        time_obj = datetime.datetime.fromtimestamp(timestamp) if isinstance(timestamp, (int, float)) else timestamp
        commits = event.get('commits', [])
        
        # Check for unusual commit time
        if not self._is_within_active_hours(user, time_obj):
            risk_score += 0.25
            risk_factors.append(f"Push outside normal working hours for user {user}")
        
        # Check for unusual number of commits in a push
        if len(commits) > 10:  # Large number of commits in a single push
            risk_score += min(0.1 * len(commits) / 10, 0.3)
            risk_factors.append(f"Unusually large push: {len(commits)} commits")
        
        # Check for sensitive files being modified
        sensitive_files_modified = []
        for commit in commits:
            files = commit.get('files_changed', [])
            for file_path in files:
                if self._is_sensitive_path(file_path):
                    sensitive_files_modified.append(file_path)
        
        if sensitive_files_modified:
            risk_score += min(0.1 * len(sensitive_files_modified), 0.4)
            risk_factors.append(f"Modified sensitive files: {', '.join(sensitive_files_modified[:5])}" + 
                              (f" and {len(sensitive_files_modified)-5} more" if len(sensitive_files_modified) > 5 else ""))
        
        # Check force-push (history rewriting)
        if event.get('force_push', False):
            risk_score += 0.3
            risk_factors.append("Force-push detected (history rewriting)")
        
        return risk_score, risk_factors
    
    def _analyze_clone_event(self, event):
        """Analyze a repository clone event for suspicious patterns"""
        risk_score = 0
        risk_factors = []
        
        user = event.get('user', '')
        ip_address = event.get('ip_address', '')
        timestamp = event.get('timestamp', datetime.datetime.now())
        time_obj = datetime.datetime.fromtimestamp(timestamp) if isinstance(timestamp, (int, float)) else timestamp
        repo = event.get('repo_name', '')
        
        # Check for cloning outside normal hours
        if not self._is_within_active_hours(user, time_obj):
            risk_score += 0.2
            risk_factors.append(f"Repository clone outside normal working hours")
        
        # Check for unusual IP (simplified example - would use geolocation in real system)
        if ip_address and not ip_address.startswith('192.168.'):
            risk_score += 0.15
            risk_factors.append(f"Repository clone from external IP: {ip_address}")
        
        # Check if first time this user is cloning this repo
        # (This would check against historical data in a real system)
        if random.random() < 0.2:  # Simulating 20% chance of first-time clone
            risk_score += 0.1
            risk_factors.append(f"First-time clone by user {user}")
        
        return risk_score, risk_factors
    
    def _analyze_branch_event(self, event):
        """Analyze branch creation/deletion events"""
        risk_score = 0
        risk_factors = []
        
        branch_name = event.get('branch_name', '')
        action = event.get('action', 'created')  # 'created' or 'deleted'
        
        # Check for suspicious branch names
        suspicious_branch_patterns = ['temp', 'test', 'fix', 'quick', 'hidden', 'private']
        if any(pattern in branch_name.lower() for pattern in suspicious_branch_patterns):
            risk_score += 0.15
            risk_factors.append(f"Suspicious branch name: {branch_name}")
        
        # Short-lived branches may indicate suspicious activity
        if action == 'deleted' and event.get('branch_age_hours', 0) < 1:
            risk_score += 0.2
            risk_factors.append(f"Very short-lived branch: {branch_name} (existed < 1 hour)")
        
        # Branches directly on sensitive paths
        if self._is_sensitive_path(branch_name):
            risk_score += 0.25
            risk_factors.append(f"Branch targets sensitive area: {branch_name}")
            
        return risk_score, risk_factors
    
    def _is_within_active_hours(self, user, time_obj):
        """Check if activity is within user's normal active hours"""
        hour = time_obj.hour
        user_active_hours = self.user_baselines[user]['active_hours']
        
        for start_hour, end_hour in user_active_hours:
            if start_hour <= hour < end_hour:
                return True
        return False
    
    def _is_sensitive_path(self, path):
        """Check if a path matches sensitive patterns"""
        for pattern in self.sensitive_paths:
            if re.match(pattern, path):
                return True
        return False
