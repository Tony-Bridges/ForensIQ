
"""
ForensIQ Comprehensive Functionality Testing Script
Tests all modules, features, and endpoints to provide detailed feedback.
"""

import requests
import json
import time
import os
from datetime import datetime
import traceback

class ForensIQTester:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'warnings': 0,
            'modules': {},
            'issues': [],
            'improvements': [],
            'missing_features': []
        }
        
    def log_result(self, module, test_name, status, message="", details=None):
        """Log test result"""
        if module not in self.test_results['modules']:
            self.test_results['modules'][module] = {
                'tests': [],
                'passed': 0,
                'failed': 0,
                'warnings': 0
            }
            
        test_result = {
            'test_name': test_name,
            'status': status,
            'message': message,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        
        self.test_results['modules'][module]['tests'].append(test_result)
        self.test_results['modules'][module][status] += 1
        self.test_results['total_tests'] += 1
        self.test_results[f'{status}_tests'] += 1
        
        print(f"[{status.upper()}] {module}: {test_name} - {message}")
        
    def test_core_application(self):
        """Test core application functionality"""
        module = "Core Application"
        
        # Test main page
        try:
            response = requests.get(f"{self.base_url}/")
            if response.status_code == 200:
                self.log_result(module, "Main Page Load", "passed", "Homepage loads successfully")
            else:
                self.log_result(module, "Main Page Load", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Main Page Load", "failed", f"Connection error: {str(e)}")
            
        # Test dashboard
        try:
            response = requests.get(f"{self.base_url}/dashboard")
            if response.status_code == 200:
                self.log_result(module, "Dashboard Access", "passed", "Dashboard loads successfully")
                if "Live Forensics Dashboard" in response.text:
                    self.log_result(module, "Dashboard Content", "passed", "Dashboard shows correct content")
                else:
                    self.log_result(module, "Dashboard Content", "warnings", "Dashboard content may be incomplete")
            else:
                self.log_result(module, "Dashboard Access", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Dashboard Access", "failed", f"Error: {str(e)}")
            
        # Test reports page
        try:
            response = requests.get(f"{self.base_url}/reports")
            if response.status_code == 200:
                self.log_result(module, "Reports Page", "passed", "Reports page accessible")
            else:
                self.log_result(module, "Reports Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Reports Page", "failed", f"Error: {str(e)}")
            
        # Test settings page
        try:
            response = requests.get(f"{self.base_url}/settings")
            if response.status_code == 200:
                self.log_result(module, "Settings Page", "passed", "Settings page accessible")
            else:
                self.log_result(module, "Settings Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Settings Page", "failed", f"Error: {str(e)}")
            
        # Test admin page
        try:
            response = requests.get(f"{self.base_url}/admin")
            if response.status_code == 200:
                self.log_result(module, "Admin Page", "passed", "Admin page accessible")
            else:
                self.log_result(module, "Admin Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Admin Page", "failed", f"Error: {str(e)}")
            
    def test_analysis_modules(self):
        """Test analysis functionality"""
        module = "Analysis Modules"
        
        # Test analysis page
        try:
            response = requests.get(f"{self.base_url}/analyze")
            if response.status_code == 200:
                self.log_result(module, "Analysis Page Load", "passed", "Analysis page loads")
            else:
                self.log_result(module, "Analysis Page Load", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Analysis Page Load", "failed", f"Error: {str(e)}")
            
        # Test AI analysis
        try:
            response = requests.get(f"{self.base_url}/ai_analysis")
            if response.status_code == 200:
                self.log_result(module, "AI Analysis Page", "passed", "AI analysis page accessible")
                
                # Test AI analysis POST
                test_data = {
                    'analysis_type': 'anomaly_detection',
                    'data_source': 'test'
                }
                post_response = requests.post(f"{self.base_url}/ai_analysis", data=test_data)
                if post_response.status_code == 200:
                    self.log_result(module, "AI Analysis Processing", "passed", "AI analysis processes requests")
                else:
                    self.log_result(module, "AI Analysis Processing", "failed", f"POST failed: {post_response.status_code}")
            else:
                self.log_result(module, "AI Analysis Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "AI Analysis", "failed", f"Error: {str(e)}")
            
    def test_device_modules(self):
        """Test device-related functionality"""
        module = "Device Modules"
        
        # Test devices page
        try:
            response = requests.get(f"{self.base_url}/devices")
            if response.status_code == 200:
                self.log_result(module, "Device Detection Page", "passed", "Device detection page loads")
            else:
                self.log_result(module, "Device Detection Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Device Detection Page", "failed", f"Error: {str(e)}")
            
        # Test mobile/IoT forensics
        try:
            response = requests.get(f"{self.base_url}/mobile_iot_forensics")
            if response.status_code == 200:
                self.log_result(module, "Mobile IoT Forensics", "passed", "Mobile/IoT forensics page accessible")
            else:
                self.log_result(module, "Mobile IoT Forensics", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Mobile IoT Forensics", "failed", f"Error: {str(e)}")
            
    def test_network_modules(self):
        """Test network analysis functionality"""
        module = "Network Analysis"
        
        # Test network scan
        try:
            response = requests.get(f"{self.base_url}/network")
            if response.status_code == 200:
                self.log_result(module, "Network Scan Page", "passed", "Network scan page loads")
            else:
                self.log_result(module, "Network Scan Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Network Scan Page", "failed", f"Error: {str(e)}")
            
        # Test network analysis
        try:
            response = requests.get(f"{self.base_url}/network_analysis")
            if response.status_code == 200:
                self.log_result(module, "Network Analysis Page", "passed", "Network analysis page accessible")
            else:
                self.log_result(module, "Network Analysis Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Network Analysis Page", "failed", f"Error: {str(e)}")
            
    def test_cloud_modules(self):
        """Test cloud forensics functionality"""
        module = "Cloud Forensics"
        
        # Test cloud forensics
        try:
            response = requests.get(f"{self.base_url}/cloud_forensics")
            if response.status_code == 200:
                self.log_result(module, "Cloud Forensics Page", "passed", "Cloud forensics page loads")
            else:
                self.log_result(module, "Cloud Forensics Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Cloud Forensics Page", "failed", f"Error: {str(e)}")
            
    def test_blockchain_modules(self):
        """Test blockchain analysis functionality"""
        module = "Blockchain Analysis"
        
        # Test blockchain analysis
        try:
            response = requests.get(f"{self.base_url}/blockchain_analysis")
            if response.status_code == 200:
                self.log_result(module, "Blockchain Analysis Page", "passed", "Blockchain analysis page loads")
            else:
                self.log_result(module, "Blockchain Analysis Page", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Blockchain Analysis Page", "failed", f"Error: {str(e)}")
            
    def test_specialized_modules(self):
        """Test specialized analysis modules"""
        module = "Specialized Modules"
        
        modules_to_test = [
            "encryption_analysis",
            "timeline_analysis", 
            "live_forensics",
            "sandbox_analysis",
            "threat_intelligence",
            "search_analysis"
        ]
        
        for module_name in modules_to_test:
            try:
                response = requests.get(f"{self.base_url}/{module_name}")
                if response.status_code == 200:
                    self.log_result(module, f"{module_name.title()} Page", "passed", f"{module_name} page accessible")
                else:
                    self.log_result(module, f"{module_name.title()} Page", "failed", f"Status code: {response.status_code}")
            except Exception as e:
                self.log_result(module, f"{module_name.title()} Page", "failed", f"Error: {str(e)}")
                
    def test_api_endpoints(self):
        """Test API functionality"""
        module = "API Endpoints"
        
        # Test report generation API
        try:
            test_data = {
                'report_type': 'comprehensive',
                'output_format': 'pdf',
                'investigation_id': 'test_001'
            }
            response = requests.post(f"{self.base_url}/api/generate-report", 
                                   json=test_data,
                                   headers={'Content-Type': 'application/json'})
            if response.status_code == 200:
                self.log_result(module, "Report Generation API", "passed", "API responds correctly")
            else:
                self.log_result(module, "Report Generation API", "failed", f"Status code: {response.status_code}")
        except Exception as e:
            self.log_result(module, "Report Generation API", "failed", f"Error: {str(e)}")
            
    def analyze_code_quality(self):
        """Analyze code quality and architecture"""
        module = "Code Quality"
        
        # Check for critical files
        critical_files = [
            'app.py', 'main.py', 'models.py', 'forensics_utils.py',
            'ai_intelligence.py', 'network_analysis.py', 'cloud_forensics.py'
        ]
        
        missing_files = []
        for file in critical_files:
            if not os.path.exists(file):
                missing_files.append(file)
                
        if not missing_files:
            self.log_result(module, "Critical Files Check", "passed", "All critical files present")
        else:
            self.log_result(module, "Critical Files Check", "failed", f"Missing files: {missing_files}")
            
        # Check template files
        template_dir = "templates"
        if os.path.exists(template_dir):
            templates = os.listdir(template_dir)
            self.log_result(module, "Templates Check", "passed", f"Found {len(templates)} template files")
        else:
            self.log_result(module, "Templates Check", "failed", "Templates directory missing")
            
    def identify_issues_and_improvements(self):
        """Identify specific issues and improvement areas"""
        
        # Critical Issues
        self.test_results['issues'].extend([
            {
                'type': 'security',
                'severity': 'high',
                'description': 'No authentication system implemented',
                'recommendation': 'Implement user authentication and authorization'
            },
            {
                'type': 'functionality',
                'severity': 'high', 
                'description': 'File upload analysis is simulated, not real',
                'recommendation': 'Implement actual file analysis using forensic libraries'
            },
            {
                'type': 'data',
                'severity': 'medium',
                'description': 'Most analysis results are mock data',
                'recommendation': 'Replace mock data with real analysis engines'
            },
            {
                'type': 'performance',
                'severity': 'medium',
                'description': 'No caching or optimization for large files',
                'recommendation': 'Implement file processing optimization and caching'
            }
        ])
        
        # Missing Features
        self.test_results['missing_features'].extend([
            'Real-time evidence chain of custody tracking',
            'Integration with external forensic tools (Autopsy, Volatility)',
            'Multi-user collaboration features',
            'Evidence encryption and secure storage',
            'Automated report scheduling',
            'Integration with SIEM systems',
            'Mobile app for field investigators',
            'Advanced search and filtering capabilities',
            'Export to standard forensic formats (E01, DD)',
            'Integration with cloud storage providers for evidence backup'
        ])
        
        # Improvements
        self.test_results['improvements'].extend([
            {
                'area': 'User Interface',
                'description': 'Add progress indicators for long-running analyses',
                'priority': 'medium'
            },
            {
                'area': 'Database',
                'description': 'Implement database indexing for better performance',
                'priority': 'high'
            },
            {
                'area': 'Error Handling',
                'description': 'Add comprehensive error handling and user feedback',
                'priority': 'high'
            },
            {
                'area': 'Documentation',
                'description': 'Add inline help and tooltips for complex features',
                'priority': 'medium'
            },
            {
                'area': 'Testing',
                'description': 'Implement automated testing suite',
                'priority': 'high'
            }
        ])
        
    def run_comprehensive_test(self):
        """Run all tests and generate report"""
        print("Starting ForensIQ Comprehensive Testing...")
        print("=" * 60)
        
        # Run all test modules
        self.test_core_application()
        self.test_analysis_modules()
        self.test_device_modules()
        self.test_network_modules()
        self.test_cloud_modules()
        self.test_blockchain_modules()
        self.test_specialized_modules()
        self.test_api_endpoints()
        self.analyze_code_quality()
        self.identify_issues_and_improvements()
        
        return self.generate_report()
        
    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("FORENSIQ COMPREHENSIVE TEST REPORT")
        print("=" * 60)
        
        # Summary
        print(f"\nTEST SUMMARY:")
        print(f"Total Tests: {self.test_results['total_tests']}")
        print(f"Passed: {self.test_results['passed_tests']}")
        print(f"Failed: {self.test_results['failed_tests']}")
        print(f"Warnings: {self.test_results['warnings_tests']}")
        print(f"Success Rate: {(self.test_results['passed_tests']/self.test_results['total_tests']*100):.1f}%")
        
        # Module Results
        print(f"\nMODULE BREAKDOWN:")
        for module, results in self.test_results['modules'].items():
            print(f"\n{module}:")
            print(f"  Passed: {results['passed']}")
            print(f"  Failed: {results['failed']}")
            print(f"  Warnings: {results['warnings']}")
            
        # Critical Issues
        print(f"\nCRITICAL ISSUES FOUND:")
        for issue in self.test_results['issues']:
            print(f"- [{issue['severity'].upper()}] {issue['type']}: {issue['description']}")
            
        # Missing Features
        print(f"\nMISSING FEATURES:")
        for feature in self.test_results['missing_features'][:10]:  # Top 10
            print(f"- {feature}")
            
        # Improvement Recommendations
        print(f"\nIMPROVEMENT RECOMMENDATIONS:")
        for improvement in self.test_results['improvements']:
            print(f"- [{improvement['priority'].upper()}] {improvement['area']}: {improvement['description']}")
            
        return self.test_results

if __name__ == "__main__":
    tester = ForensIQTester()
    results = tester.run_comprehensive_test()
    
    # Save detailed results to file
    with open('test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\nDetailed results saved to test_results.json")
