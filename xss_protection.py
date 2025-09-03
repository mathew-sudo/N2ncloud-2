"""
XSS Protection Module
Advanced Cross-Site Scripting (XSS) detection and prevention
"""

import re
import html
import urllib.parse
import threading
import time
import logging
import json
from datetime import datetime

class XSSProtection:
    """Advanced XSS detection and prevention system"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.XSSProtection")
        self.active = True
        self.detected_threats = []
        self.xss_patterns = {}
        self.blocked_payloads = set()
        self.request_log = []
        
        # Initialize XSS detection patterns
        self.initialize_xss_patterns()
    
    def run(self):
        """Main XSS protection loop"""
        while self.active:
            try:
                # Monitor web traffic for XSS attempts
                self.monitor_web_traffic()
                
                # Scan log files for XSS attempts
                self.scan_web_logs()
                
                # Update XSS patterns from threat intelligence
                self.update_xss_patterns()
                
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"XSS Protection error: {e}")
                time.sleep(15)
    
    def initialize_xss_patterns(self):
        """Initialize XSS detection patterns"""
        self.xss_patterns = {
            # Classic XSS patterns
            'script_tags': [
                r'<script[^>]*>.*?</script>',
                r'<script[^>]*>',
                r'</script>',
                r'javascript:',
                r'vbscript:',
                r'data:text/html'
            ],
            
            # Event handler XSS
            'event_handlers': [
                r'on\w+\s*=',
                r'onload\s*=',
                r'onerror\s*=',
                r'onclick\s*=',
                r'onmouseover\s*=',
                r'onfocus\s*=',
                r'onblur\s*=',
                r'onchange\s*='
            ],
            
            # HTML injection patterns
            'html_injection': [
                r'<iframe[^>]*>',
                r'<object[^>]*>',
                r'<embed[^>]*>',
                r'<form[^>]*>',
                r'<input[^>]*>',
                r'<img[^>]*onerror',
                r'<svg[^>]*onload'
            ],
            
            # CSS injection patterns
            'css_injection': [
                r'expression\s*\(',
                r'@import',
                r'javascript:',
                r'vbscript:',
                r'behavior\s*:',
                r'-moz-binding'
            ],
            
            # URL-based XSS
            'url_xss': [
                r'data:text/html,',
                r'data:application/javascript,',
                r'javascript:',
                r'vbscript:',
                r'livescript:',
                r'mocha:'
            ],
            
            # DOM-based XSS patterns
            'dom_xss': [
                r'document\.write',
                r'document\.writeln',
                r'innerHTML',
                r'outerHTML',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\(',
                r'Function\s*\(',
                r'execScript'
            ],
            
            # Advanced XSS bypass techniques
            'bypass_techniques': [
                r'&#x[0-9a-f]+;',      # Hex encoding
                r'&#[0-9]+;',          # Decimal encoding
                r'%[0-9a-f]{2}',       # URL encoding
                r'\\u[0-9a-f]{4}',     # Unicode encoding
                r'String\.fromCharCode',
                r'unescape\s*\(',
                r'decodeURI\s*\(',
                r'atob\s*\('           # Base64 decode
            ],
            
            # Filter evasion
            'filter_evasion': [
                r'<script\s+',         # Whitespace in tags
                r'<\s*script',
                r'script\s*>',
                r'<script/[^>]*>',     # Self-closing script tags
                r'<script\x00',        # Null byte injection
                r'<script\x0d',        # Carriage return
                r'<script\x0a'         # Line feed
            ]
        }
    
    def monitor_web_traffic(self):
        """Monitor web traffic for XSS attempts"""
        try:
            # This would typically hook into web server logs or network traffic
            # For this implementation, we'll simulate by checking common web log locations
            web_log_paths = [
                '/var/log/nginx/access.log',
                '/var/log/apache2/access.log',
                '/var/log/httpd/access_log'
            ]
            
            for log_path in web_log_paths:
                if os.path.exists(log_path):
                    self.analyze_web_log(log_path)
                    
        except Exception as e:
            self.logger.error(f"Web traffic monitoring error: {e}")
    
    def analyze_web_log(self, log_path):
        """Analyze web log file for XSS attempts"""
        try:
            # Read recent log entries
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Check last 100 lines for XSS attempts
            recent_lines = lines[-100:] if len(lines) > 100 else lines
            
            for line in recent_lines:
                if self.contains_xss_attempt(line):
                    self.handle_xss_detection(line, log_path)
                    
        except Exception as e:
            self.logger.error(f"Web log analysis error for {log_path}: {e}")
    
    def contains_xss_attempt(self, log_line):
        """Check if log line contains XSS attempt"""
        try:
            # URL decode the line first
            decoded_line = urllib.parse.unquote(log_line)
            decoded_line_lower = decoded_line.lower()
            
            # Check against all XSS patterns
            for category, patterns in self.xss_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, decoded_line_lower, re.IGNORECASE | re.DOTALL):
                        return True
            
            # Check for common XSS payloads
            xss_payloads = [
                '<script>alert(',
                'javascript:alert(',
                'onerror=alert(',
                'onload=alert(',
                'src=javascript:',
                'href=javascript:',
                'expression(alert(',
                'vbscript:msgbox',
                '<img src=x onerror=',
                '<svg onload=',
                'document.cookie',
                'document.location',
                'window.location'
            ]
            
            for payload in xss_payloads:
                if payload in decoded_line_lower:
                    return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"XSS detection error: {e}")
            return False
    
    def handle_xss_detection(self, log_line, source):
        """Handle detected XSS attempt"""
        try:
            # Extract IP address from log line
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_line)
            source_ip = ip_match.group(1) if ip_match else 'unknown'
            
            # Extract user agent
            ua_match = re.search(r'"([^"]*User-Agent[^"]*)"', log_line)
            user_agent = ua_match.group(1) if ua_match else 'unknown'
            
            # Extract the malicious payload
            payload = self.extract_xss_payload(log_line)
            
            self.logger.warning(f"XSS ATTEMPT DETECTED from {source_ip}")
            self.logger.warning(f"Payload: {payload[:200]}...")  # Truncate long payloads
            
            self.detected_threats.append({
                'type': 'xss_attempt',
                'severity': 'HIGH',
                'source_ip': source_ip,
                'user_agent': user_agent,
                'payload': payload,
                'log_source': source,
                'timestamp': time.time()
            })
            
            # Add payload to blocked list
            self.blocked_payloads.add(payload[:100])  # Store first 100 chars
            
            # Take protective action
            self.block_xss_source(source_ip)
            
        except Exception as e:
            self.logger.error(f"XSS handling error: {e}")
    
    def extract_xss_payload(self, log_line):
        """Extract XSS payload from log line"""
        try:
            # Look for common request patterns
            patterns = [
                r'GET\s+([^\s]+)',
                r'POST\s+([^\s]+)',
                r'\?([^"\s]+)',
                r'&([^"\s&]+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, log_line)
                if match:
                    potential_payload = urllib.parse.unquote(match.group(1))
                    if self.contains_xss_attempt(potential_payload):
                        return potential_payload
            
            # If no specific pattern matches, return decoded line
            return urllib.parse.unquote(log_line)
            
        except Exception:
            return log_line
    
    def block_xss_source(self, source_ip):
        """Block source IP that attempted XSS"""
        try:
            if source_ip and source_ip != 'unknown':
                # Add to iptables firewall
                subprocess.run([
                    'iptables', '-A', 'INPUT', '-s', source_ip, '-j', 'DROP'
                ], capture_output=True)
                
                self.logger.info(f"Blocked XSS source IP: {source_ip}")
                
        except Exception as e:
            self.logger.error(f"IP blocking error for {source_ip}: {e}")
    
    def scan_web_logs(self):
        """Scan web logs for XSS patterns"""
        try:
            # Check application logs that might contain XSS attempts
            app_log_paths = [
                '/var/log/syslog',
                '/var/log/messages',
                '/var/log/auth.log'
            ]
            
            for log_path in app_log_paths:
                if os.path.exists(log_path):
                    self.scan_log_for_xss(log_path)
                    
        except Exception as e:
            self.logger.error(f"Log scanning error: {e}")
    
    def scan_log_for_xss(self, log_path):
        """Scan specific log file for XSS indicators"""
        try:
            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Check recent entries
            recent_lines = lines[-50:] if len(lines) > 50 else lines
            
            for line in recent_lines:
                # Look for web application errors that might indicate XSS
                if any(term in line.lower() for term in [
                    'xss', 'cross-site scripting', 'script injection',
                    'html injection', 'javascript injection'
                ]):
                    self.detected_threats.append({
                        'type': 'xss_indicator_in_logs',
                        'severity': 'MEDIUM',
                        'details': f'XSS indicator found in {log_path}',
                        'log_line': line.strip()
                    })
                    
        except Exception as e:
            self.logger.error(f"Log scan error for {log_path}: {e}")
    
    def update_xss_patterns(self):
        """Update XSS patterns from threat intelligence"""
        try:
            # This would typically fetch from threat intelligence feeds
            # For now, we'll add some additional patterns based on recent threats
            
            new_patterns = {
                'modern_xss': [
                    r'fetch\s*\(',
                    r'XMLHttpRequest',
                    r'postMessage\s*\(',
                    r'localStorage\.',
                    r'sessionStorage\.',
                    r'importScripts\s*\(',
                    r'Worker\s*\(',
                    r'SharedWorker\s*\('
                ],
                
                'framework_xss': [
                    r'\{\{.*\}\}',          # Angular-style injection
                    r'\$\{.*\}',            # Template literal injection
                    r'v-html\s*=',          # Vue.js XSS
                    r'dangerouslySetInnerHTML',  # React XSS
                    r'\[innerHTML\]'        # Angular property binding
                ]
            }
            
            # Add new patterns to existing ones
            for category, patterns in new_patterns.items():
                if category not in self.xss_patterns:
                    self.xss_patterns[category] = []
                self.xss_patterns[category].extend(patterns)
                
        except Exception as e:
            self.logger.error(f"Pattern update error: {e}")
    
    def validate_input(self, user_input):
        """Validate user input for XSS attempts"""
        try:
            if not user_input:
                return True, user_input
            
            # Check for XSS patterns
            if self.contains_xss_attempt(user_input):
                self.logger.warning(f"XSS attempt blocked in input validation: {user_input[:100]}")
                return False, "Input contains potentially malicious content"
            
            # Sanitize the input
            sanitized_input = self.sanitize_input(user_input)
            
            return True, sanitized_input
            
        except Exception as e:
            self.logger.error(f"Input validation error: {e}")
            return False, "Input validation failed"
    
    def sanitize_input(self, user_input):
        """Sanitize user input to prevent XSS"""
        try:
            # HTML escape
            sanitized = html.escape(user_input, quote=True)
            
            # Remove or escape potentially dangerous patterns
            dangerous_patterns = [
                (r'javascript:', 'javascript_'),
                (r'vbscript:', 'vbscript_'),
                (r'on\w+\s*=', ''),
                (r'<script[^>]*>', ''),
                (r'</script>', ''),
                (r'<iframe[^>]*>', ''),
                (r'<object[^>]*>', ''),
                (r'<embed[^>]*>', '')
            ]
            
            for pattern, replacement in dangerous_patterns:
                sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)
            
            return sanitized
            
        except Exception as e:
            self.logger.error(f"Input sanitization error: {e}")
            return ""
    
    def generate_csp_header(self):
        """Generate Content Security Policy header"""
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: https:",
            "font-src 'self' data:",
            "connect-src 'self'",
            "media-src 'self'",
            "object-src 'none'",
            "frame-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "upgrade-insecure-requests"
        ]
        
        return "; ".join(csp_directives)
    
    def create_xss_protection_headers(self):
        """Create XSS protection HTTP headers"""
        return {
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Content-Security-Policy': self.generate_csp_header(),
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
    
    def check_reflected_xss(self, request_params, response_content):
        """Check for reflected XSS vulnerabilities"""
        try:
            # Check if any request parameters are reflected in response
            for param_name, param_value in request_params.items():
                if param_value and param_value in response_content:
                    # Check if the reflected content could be XSS
                    if self.contains_xss_attempt(param_value):
                        self.detected_threats.append({
                            'type': 'reflected_xss_vulnerability',
                            'severity': 'CRITICAL',
                            'parameter': param_name,
                            'payload': param_value,
                            'details': 'User input reflected without proper sanitization'
                        })
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Reflected XSS check error: {e}")
            return False
    
    def check_stored_xss(self, stored_content):
        """Check stored content for XSS payloads"""
        try:
            if self.contains_xss_attempt(stored_content):
                self.detected_threats.append({
                    'type': 'stored_xss_found',
                    'severity': 'CRITICAL',
                    'details': 'Stored XSS payload detected in content',
                    'payload': stored_content[:200]
                })
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Stored XSS check error: {e}")
            return False
    
    def generate_xss_report(self):
        """Generate XSS protection report"""
        try:
            recent_threats = [t for t in self.detected_threats 
                            if time.time() - t.get('timestamp', 0) < 3600]  # Last hour
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'total_threats_detected': len(self.detected_threats),
                'recent_threats': len(recent_threats),
                'blocked_payloads': len(self.blocked_payloads),
                'threat_breakdown': {},
                'top_attack_sources': {},
                'protection_status': 'ACTIVE'
            }
            
            # Threat breakdown by type
            for threat in recent_threats:
                threat_type = threat.get('type', 'unknown')
                report['threat_breakdown'][threat_type] = report['threat_breakdown'].get(threat_type, 0) + 1
            
            # Top attack sources
            source_counts = {}
            for threat in recent_threats:
                source_ip = threat.get('source_ip', 'unknown')
                source_counts[source_ip] = source_counts.get(source_ip, 0) + 1
            
            report['top_attack_sources'] = dict(sorted(source_counts.items(), 
                                                     key=lambda x: x[1], reverse=True)[:10])
            
            return report
            
        except Exception as e:
            self.logger.error(f"XSS report generation error: {e}")
            return {}
    
    def get_detected_threats(self):
        """Return and clear detected threats"""
        threats = self.detected_threats.copy()
        self.detected_threats.clear()
        return threats
    
    def is_xss_payload_blocked(self, payload):
        """Check if XSS payload is in blocked list"""
        payload_prefix = payload[:100] if len(payload) > 100 else payload
        return payload_prefix in self.blocked_payloads
    
    def add_custom_xss_pattern(self, pattern, category='custom'):
        """Add custom XSS detection pattern"""
        try:
            if category not in self.xss_patterns:
                self.xss_patterns[category] = []
            
            self.xss_patterns[category].append(pattern)
            self.logger.info(f"Added custom XSS pattern: {pattern}")
            
        except Exception as e:
            self.logger.error(f"Custom pattern addition error: {e}")
    
    def get_protection_status(self):
        """Get current XSS protection status"""
        return {
            'active': self.active,
            'patterns_loaded': sum(len(patterns) for patterns in self.xss_patterns.values()),
            'blocked_payloads': len(self.blocked_payloads),
            'threats_detected': len(self.detected_threats),
            'last_update': time.time()
        }