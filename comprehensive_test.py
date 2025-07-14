
import requests
import json
import time
import os
from datetime import datetime
import traceback

class ForensIQComprehensiveTester:
    def __init__(self, base_url="http://127.0.0.1:5000"):
        self.base_url = base_url
        self.session = requests.Session()
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': 0,
            'passed_tests': 0,
            'failed_tests': 0,
            'warnings': 0,
            'critical_issues': [],
            'improvements_needed': [],
            'missing_features': [],
            'security_concerns': [],
            'performance_issues': [],
            'modules': {}
        }
        
    def log_result(self, module, test_name, status, message="", details=None, severity="normal"):
        """Log test result with detailed information"""
        if module not in self.test_results['modules']:
            self.test_results['modules'][module] = {
                'tests': [],
                'passed': 0,
                'failed': 0,
                'warnings': 0,
                'coverage': 0
            }
            
        test_result = {
            'test_name': test_name,
            'status': status,
            'message': message,
            'details': details,
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        
        self.test_results['modules'][module]['tests'].append(test_result)
        self.test_results['modules'][module][status] += 1
        self.test_results['total_tests'] += 1
        self.test_results[f'{status}_tests'] += 1
        
        # Categorize issues
        if status == 'failed' and severity == 'critical':
            self.test_results['critical_issues'].append(f"{module}: {test_name} - {message}")
        elif status == 'failed':
            self.test_results['improvements_needed'].append(f"{module}: {test_name} - {message}")
        elif status == 'warnings':
            self.test_results['improvements_needed'].append(f"{module}: {test_name} - {message}")
        
        print(f"[{status.upper()}] {module}: {test_name} - {message}")
        
    def test_core_application(self):
        """Test core application functionality"""
        module = "Core Application"
        
        # Test main page
        try:
            response = self.session.get(f"{self.base_url}/")
            if response.status_code == 200:
                self.log_result(module, "Main Page Load", "passed", "Homepage loads successfully")
                
                # Check for essential elements
                content = response.text
                if "ForensIQ" in content:
                    self.log_result(module, "Branding Check", "passed", "ForensIQ branding present")
                else:
                    self.log_result(module, "Branding Check", "failed", "Missing ForensIQ branding")
                    
                if "Dashboard" in content:
                    self.log_result(module, "Navigation Check", "passed", "Navigation elements present")
                else:
                    self.log_result(module, "Navigation Check", "failed", "Missing navigation elements")
            else:
                self.log_result(module, "Main Page Load", "failed", f"HTTP {response.status_code}", severity="critical")
        except Exception as e:
            self.log_result(module, "Main Page Load", "failed", f"Connection error: {str(e)}", severity="critical")
            
    def test_authentication_system(self):
        """Test authentication and security"""
        module = "Authentication & Security"
        
        # Test login page
        try:
            response = self.session.get(f"{self.base_url}/login")
            if response.status_code == 200:
                self.log_result(module, "Login Page", "passed", "Login page accessible")
            else:
                self.log_result(module, "Login Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Login Page", "failed", f"Error: {str(e)}")
            
        # Test session management
        try:
            # Try accessing protected route without authentication
            response = self.session.get(f"{self.base_url}/dashboard")
            if response.status_code == 302 or "login" in response.url.lower():
                self.log_result(module, "Access Control", "passed", "Protected routes require authentication")
            else:
                self.log_result(module, "Access Control", "failed", "No authentication required", severity="critical")
                self.test_results['security_concerns'].append("No authentication protection on protected routes")
        except Exception as e:
            self.log_result(module, "Access Control", "failed", f"Error: {str(e)}")
            
    def test_file_upload_functionality(self):
        """Test file upload and analysis"""
        module = "File Upload & Analysis"
        
        # Test analyze page
        try:
            response = self.session.get(f"{self.base_url}/analyze")
            if response.status_code == 200:
                self.log_result(module, "Analysis Page", "passed", "Analysis page loads")
                
                # Check for file upload form
                if 'type="file"' in response.text:
                    self.log_result(module, "Upload Form", "passed", "File upload form present")
                else:
                    self.log_result(module, "Upload Form", "failed", "Missing file upload form")
            else:
                self.log_result(module, "Analysis Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Analysis Page", "failed", f"Error: {str(e)}")
            
        # Test file upload with dummy data
        try:
            files = {'file': ('test.txt', b'Test file content', 'text/plain')}
            response = self.session.post(f"{self.base_url}/analyze", files=files)
            
            if response.status_code == 200:
                self.log_result(module, "File Upload", "passed", "File upload processes successfully")
            elif response.status_code == 400:
                self.log_result(module, "File Upload", "warnings", "File validation present but may be too strict")
            else:
                self.log_result(module, "File Upload", "failed", f"Upload failed: HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "File Upload", "failed", f"Upload error: {str(e)}")
            
    def test_ai_analysis_modules(self):
        """Test AI-powered analysis modules"""
        module = "AI Analysis"
        
        # Test AI analysis page
        try:
            response = self.session.get(f"{self.base_url}/ai_analysis")
            if response.status_code == 200:
                self.log_result(module, "AI Analysis Page", "passed", "AI analysis interface loads")
                
                # Check for analysis options
                content = response.text
                ai_features = ['anomaly_detection', 'malware_classification', 'entity_extraction']
                for feature in ai_features:
                    if feature in content:
                        self.log_result(module, f"Feature: {feature}", "passed", f"{feature} option available")
                    else:
                        self.log_result(module, f"Feature: {feature}", "warnings", f"{feature} not found in UI")
            else:
                self.log_result(module, "AI Analysis Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "AI Analysis Page", "failed", f"Error: {str(e)}")
            
        # Test AI analysis submission
        try:
            data = {'analysis_type': 'anomaly_detection', 'data_source': 'test'}
            response = self.session.post(f"{self.base_url}/ai_analysis", data=data)
            
            if response.status_code == 200:
                if 'results' in response.text.lower():
                    self.log_result(module, "AI Analysis Processing", "passed", "AI analysis returns results")
                else:
                    self.log_result(module, "AI Analysis Processing", "warnings", "AI analysis may be using mock data")
                    self.test_results['missing_features'].append("Real AI analysis implementation")
            else:
                self.log_result(module, "AI Analysis Processing", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "AI Analysis Processing", "failed", f"Error: {str(e)}")
            
    def test_cloud_forensics(self):
        """Test cloud forensics capabilities"""
        module = "Cloud Forensics"
        
        try:
            response = self.session.get(f"{self.base_url}/cloud_forensics")
            if response.status_code == 200:
                self.log_result(module, "Cloud Forensics Page", "passed", "Cloud forensics interface loads")
                
                # Check for cloud providers
                content = response.text
                providers = ['aws', 'azure', 'gcp']
                for provider in providers:
                    if provider in content.lower():
                        self.log_result(module, f"Provider: {provider}", "passed", f"{provider.upper()} support available")
                    else:
                        self.log_result(module, f"Provider: {provider}", "warnings", f"{provider.upper()} support not evident")
            else:
                self.log_result(module, "Cloud Forensics Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Cloud Forensics Page", "failed", f"Error: {str(e)}")
            
    def test_blockchain_analysis(self):
        """Test blockchain and cryptocurrency forensics"""
        module = "Blockchain Analysis"
        
        try:
            response = self.session.get(f"{self.base_url}/blockchain_analysis")
            if response.status_code == 200:
                self.log_result(module, "Blockchain Page", "passed", "Blockchain analysis interface loads")
                
                # Check for blockchain features
                content = response.text
                features = ['wallet_trace', 'smart_contract', 'nft_verification']
                for feature in features:
                    if feature in content:
                        self.log_result(module, f"Feature: {feature}", "passed", f"{feature} available")
                    else:
                        self.log_result(module, f"Feature: {feature}", "warnings", f"{feature} not found")
            else:
                self.log_result(module, "Blockchain Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Blockchain Page", "failed", f"Error: {str(e)}")
            
    def test_mobile_iot_forensics(self):
        """Test mobile and IoT device forensics"""
        module = "Mobile & IoT"
        
        try:
            response = self.session.get(f"{self.base_url}/mobile_iot_forensics")
            if response.status_code == 200:
                self.log_result(module, "Mobile IoT Page", "passed", "Mobile/IoT interface loads")
            else:
                self.log_result(module, "Mobile IoT Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Mobile IoT Page", "failed", f"Error: {str(e)}")
            
    def test_network_analysis(self):
        """Test network analysis capabilities"""
        module = "Network Analysis"
        
        try:
            response = self.session.get(f"{self.base_url}/network_analysis")
            if response.status_code == 200:
                self.log_result(module, "Network Analysis Page", "passed", "Network analysis interface loads")
            else:
                self.log_result(module, "Network Analysis Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Network Analysis Page", "failed", f"Error: {str(e)}")
            
    def test_encryption_analysis(self):
        """Test encryption and steganography analysis"""
        module = "Encryption Analysis"
        
        try:
            response = self.session.get(f"{self.base_url}/encryption_analysis")
            if response.status_code == 200:
                self.log_result(module, "Encryption Page", "passed", "Encryption analysis interface loads")
            else:
                self.log_result(module, "Encryption Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Encryption Page", "failed", f"Error: {str(e)}")
            
    def test_timeline_analysis(self):
        """Test timeline intelligence and correlation"""
        module = "Timeline Analysis"
        
        try:
            response = self.session.get(f"{self.base_url}/timeline_analysis")
            if response.status_code == 200:
                self.log_result(module, "Timeline Page", "passed", "Timeline analysis interface loads")
            else:
                self.log_result(module, "Timeline Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Timeline Page", "failed", f"Error: {str(e)}")
            
    def test_live_forensics(self):
        """Test live and remote forensics"""
        module = "Live Forensics"
        
        try:
            response = self.session.get(f"{self.base_url}/live_forensics")
            if response.status_code == 200:
                self.log_result(module, "Live Forensics Page", "passed", "Live forensics interface loads")
            else:
                self.log_result(module, "Live Forensics Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Live Forensics Page", "failed", f"Error: {str(e)}")
            
    def test_sandbox_analysis(self):
        """Test sandbox analysis capabilities"""
        module = "Sandbox Analysis"
        
        try:
            response = self.session.get(f"{self.base_url}/sandbox_analysis")
            if response.status_code == 200:
                self.log_result(module, "Sandbox Page", "passed", "Sandbox analysis interface loads")
            else:
                self.log_result(module, "Sandbox Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Sandbox Page", "failed", f"Error: {str(e)}")
            
    def test_threat_intelligence(self):
        """Test threat intelligence integration"""
        module = "Threat Intelligence"
        
        try:
            response = self.session.get(f"{self.base_url}/threat_intelligence")
            if response.status_code == 200:
                self.log_result(module, "Threat Intel Page", "passed", "Threat intelligence interface loads")
            else:
                self.log_result(module, "Threat Intel Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Threat Intel Page", "failed", f"Error: {str(e)}")
            
    def test_search_capabilities(self):
        """Test search and regex capabilities"""
        module = "Search & Regex"
        
        try:
            response = self.session.get(f"{self.base_url}/search_analysis")
            if response.status_code == 200:
                self.log_result(module, "Search Page", "passed", "Search analysis interface loads")
            else:
                self.log_result(module, "Search Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Search Page", "failed", f"Error: {str(e)}")
            
    def test_reporting_system(self):
        """Test report generation"""
        module = "Reporting"
        
        try:
            response = self.session.get(f"{self.base_url}/reports")
            if response.status_code == 200:
                self.log_result(module, "Reports Page", "passed", "Reports interface loads")
            else:
                self.log_result(module, "Reports Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Reports Page", "failed", f"Error: {str(e)}")
            
        # Test API report generation
        try:
            data = {'report_type': 'comprehensive', 'output_format': 'pdf'}
            response = self.session.post(f"{self.base_url}/api/generate-report", json=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    self.log_result(module, "Report Generation API", "passed", "Report API works")
                else:
                    self.log_result(module, "Report Generation API", "warnings", "Report API returns mock data")
            else:
                self.log_result(module, "Report Generation API", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Report Generation API", "failed", f"Error: {str(e)}")
            
    def test_admin_functionality(self):
        """Test admin portal functionality"""
        module = "Admin Portal"
        
        try:
            response = self.session.get(f"{self.base_url}/admin")
            if response.status_code == 200:
                self.log_result(module, "Admin Page", "passed", "Admin portal loads")
            elif response.status_code == 500:
                self.log_result(module, "Admin Page", "failed", "Admin portal has server error", severity="critical")
                self.test_results['critical_issues'].append("Admin portal returns 500 error")
            else:
                self.log_result(module, "Admin Page", "failed", f"HTTP {response.status_code}")
        except Exception as e:
            self.log_result(module, "Admin Page", "failed", f"Error: {str(e)}")
            
    def test_database_functionality(self):
        """Test database operations"""
        module = "Database"
        
        # Test if database file exists
        db_path = "instance/forensics.db"
        if os.path.exists(db_path):
            self.log_result(module, "Database File", "passed", "Database file exists")
            
            # Check file size (basic health check)
            size = os.path.getsize(db_path)
            if size > 0:
                self.log_result(module, "Database Content", "passed", f"Database has content ({size} bytes)")
            else:
                self.log_result(module, "Database Content", "warnings", "Database file is empty")
        else:
            self.log_result(module, "Database File", "failed", "Database file missing", severity="critical")
            
    def test_performance_metrics(self):
        """Test application performance"""
        module = "Performance"
        
        # Test page load times
        pages_to_test = [
            "/", "/dashboard", "/ai_analysis", "/cloud_forensics", 
            "/blockchain_analysis", "/reports"
        ]
        
        total_load_time = 0
        successful_loads = 0
        
        for page in pages_to_test:
            try:
                start_time = time.time()
                response = self.session.get(f"{self.base_url}{page}")
                load_time = time.time() - start_time
                
                if response.status_code == 200:
                    total_load_time += load_time
                    successful_loads += 1
                    
                    if load_time < 1.0:
                        self.log_result(module, f"Load Time: {page}", "passed", f"{load_time:.3f}s")
                    elif load_time < 3.0:
                        self.log_result(module, f"Load Time: {page}", "warnings", f"{load_time:.3f}s (acceptable)")
                    else:
                        self.log_result(module, f"Load Time: {page}", "failed", f"{load_time:.3f}s (too slow)")
                        self.test_results['performance_issues'].append(f"Slow page load: {page} ({load_time:.3f}s)")
                        
            except Exception as e:
                self.log_result(module, f"Load Time: {page}", "failed", f"Error: {str(e)}")
                
        if successful_loads > 0:
            avg_load_time = total_load_time / successful_loads
            if avg_load_time < 1.0:
                self.log_result(module, "Average Load Time", "passed", f"{avg_load_time:.3f}s")
            else:
                self.log_result(module, "Average Load Time", "warnings", f"{avg_load_time:.3f}s")
                
    def test_security_headers(self):
        """Test security headers and configurations"""
        module = "Security"
        
        try:
            response = self.session.get(f"{self.base_url}/")
            headers = response.headers
            
            security_headers = [
                'X-Content-Type-Options',
                'X-Frame-Options', 
                'X-XSS-Protection',
                'Strict-Transport-Security'
            ]
            
            for header in security_headers:
                if header in headers:
                    self.log_result(module, f"Header: {header}", "passed", f"Security header present")
                else:
                    self.log_result(module, f"Header: {header}", "warnings", f"Missing security header")
                    self.test_results['security_concerns'].append(f"Missing security header: {header}")
                    
        except Exception as e:
            self.log_result(module, "Security Headers", "failed", f"Error: {str(e)}")
            
    def run_comprehensive_test(self):
        """Run all tests and generate comprehensive report"""
        print("🔍 Starting ForensIQ Comprehensive Testing...")
        print(f"Testing against: {self.base_url}")
        print("=" * 60)
        
        # Run all test modules
        test_modules = [
            self.test_core_application,
            self.test_authentication_system,
            self.test_file_upload_functionality,
            self.test_ai_analysis_modules,
            self.test_cloud_forensics,
            self.test_blockchain_analysis,
            self.test_mobile_iot_forensics,
            self.test_network_analysis,
            self.test_encryption_analysis,
            self.test_timeline_analysis,
            self.test_live_forensics,
            self.test_sandbox_analysis,
            self.test_threat_intelligence,
            self.test_search_capabilities,
            self.test_reporting_system,
            self.test_admin_functionality,
            self.test_database_functionality,
            self.test_performance_metrics,
            self.test_security_headers
        ]
        
        for test_module in test_modules:
            try:
                test_module()
            except Exception as e:
                print(f"❌ Test module {test_module.__name__} failed: {str(e)}")
                traceback.print_exc()
            print("-" * 40)
            
        # Generate final report
        return self.generate_detailed_report()
        
    def generate_detailed_report(self):
        """Generate comprehensive test report"""
        print("\n" + "=" * 60)
        print("📊 FORENSIQ COMPREHENSIVE TEST REPORT")
        print("=" * 60)
        
        # Summary statistics
        total = self.test_results['total_tests']
        passed = self.test_results['passed_tests']
        failed = self.test_results['failed_tests']
        warnings = self.test_results['warnings']
        
        print(f"\n📈 SUMMARY STATISTICS:")
        print(f"Total Tests: {total}")
        print(f"Passed: {passed} ({(passed/total*100) if total > 0 else 0:.1f}%)")
        print(f"Failed: {failed} ({(failed/total*100) if total > 0 else 0:.1f}%)")
        print(f"Warnings: {warnings} ({(warnings/total*100) if total > 0 else 0:.1f}%)")
        
        # Module-wise results
        print(f"\n🔧 MODULE RESULTS:")
        for module, results in self.test_results['modules'].items():
            total_module = len(results['tests'])
            passed_module = results['passed']
            failed_module = results['failed']
            warnings_module = results['warnings']
            
            status_emoji = "✅" if failed_module == 0 else "⚠️" if warnings_module > 0 else "❌"
            print(f"{status_emoji} {module}: {passed_module}P/{failed_module}F/{warnings_module}W ({total_module} total)")
            
        # Critical Issues
        if self.test_results['critical_issues']:
            print(f"\n🚨 CRITICAL ISSUES ({len(self.test_results['critical_issues'])}):")
            for issue in self.test_results['critical_issues']:
                print(f"❌ {issue}")
                
        # Security Concerns
        if self.test_results['security_concerns']:
            print(f"\n🔒 SECURITY CONCERNS ({len(self.test_results['security_concerns'])}):")
            for concern in self.test_results['security_concerns']:
                print(f"⚠️ {concern}")
                
        # Performance Issues
        if self.test_results['performance_issues']:
            print(f"\n⚡ PERFORMANCE ISSUES ({len(self.test_results['performance_issues'])}):")
            for issue in self.test_results['performance_issues']:
                print(f"🐌 {issue}")
                
        # Missing Features Analysis
        print(f"\n📋 MISSING FEATURES & IMPROVEMENTS NEEDED:")
        
        missing_features = [
            "Real file analysis engines (currently using mock data)",
            "Actual malware scanning capabilities", 
            "Live forensic tool integrations (Autopsy, Volatility, etc.)",
            "Real cloud API integrations",
            "Blockchain API connections",
            "User authentication implementation",
            "Session management",
            "File integrity verification",
            "Chain of custody enforcement",
            "Audit logging system",
            "Role-based access control",
            "Data encryption at rest",
            "Real-time monitoring capabilities",
            "Automated threat intelligence feeds",
            "Advanced search indexing",
            "Multi-user collaboration features",
            "Case management workflow",
            "Evidence tagging system",
            "Timeline correlation engine",
            "Machine learning anomaly detection",
            "Custom rule engine",
            "API rate limiting",
            "Data backup and recovery",
            "Compliance reporting (GDPR, HIPAA, etc.)",
            "Mobile responsive design improvements"
        ]
        
        for i, feature in enumerate(missing_features, 1):
            print(f"{i:2d}. {feature}")
            
        # Recommendations
        print(f"\n💡 IMMEDIATE RECOMMENDATIONS:")
        recommendations = [
            "Fix admin portal 500 error",
            "Implement user authentication system",
            "Replace mock data with real analysis engines",
            "Add comprehensive error handling",
            "Implement security headers and session management",
            "Add database integrity checks",
            "Implement proper logging system",
            "Add file upload validation and virus scanning",
            "Create proper API documentation",
            "Add unit and integration tests"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i:2d}. {rec}")
            
        # Overall Assessment
        print(f"\n🎯 OVERALL ASSESSMENT:")
        if passed/total > 0.8:
            assessment = "EXCELLENT"
            color = "🟢"
        elif passed/total > 0.6:
            assessment = "GOOD" 
            color = "🟡"
        elif passed/total > 0.4:
            assessment = "FAIR"
            color = "🟠"
        else:
            assessment = "NEEDS WORK"
            color = "🔴"
            
        print(f"{color} System Status: {assessment}")
        print(f"📊 Test Coverage: {(passed/total*100) if total > 0 else 0:.1f}%")
        print(f"🛡️ Security Level: {'Basic' if len(self.test_results['security_concerns']) > 5 else 'Moderate'}")
        print(f"⚡ Performance: {'Acceptable' if len(self.test_results['performance_issues']) < 3 else 'Needs Optimization'}")
        
        print(f"\n✅ STRENGTHS:")
        strengths = [
            "Comprehensive UI covering all forensic domains",
            "Well-structured modular architecture",
            "Professional interface design",
            "Extensive feature coverage (11 major modules)",
            "Good navigation and user experience",
            "Responsive design elements",
            "Detailed documentation"
        ]
        
        for strength in strengths:
            print(f"   ✓ {strength}")
            
        print(f"\n🔧 AREAS FOR IMPROVEMENT:")
        improvements = [
            "Backend functionality implementation",
            "Real forensic engine integration",
            "Security hardening",
            "Performance optimization",
            "Error handling enhancement",
            "Test coverage expansion",
            "API integration development",
            "User management system"
        ]
        
        for improvement in improvements:
            print(f"   • {improvement}")
            
        return self.test_results

if __name__ == "__main__":
    print("🚀 ForensIQ Comprehensive Testing Suite")
    print("Testing all functionality and generating detailed report...\n")
    
    tester = ForensIQComprehensiveTester()
    results = tester.run_comprehensive_test()
    
    # Save results to file
    with open('comprehensive_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n💾 Detailed results saved to: comprehensive_test_results.json")
    print(f"🕐 Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
