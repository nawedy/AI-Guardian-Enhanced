import sublime
import sublime_plugin
import json
import threading
import time
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, List, Optional, Any

class AIGuardianService:
    """Service class for communicating with AI Guardian backend"""
    
    def __init__(self):
        self.api_base_url = self.get_setting('api_url', 'http://localhost:5004/api/ide')
        self.timeout = self.get_setting('timeout', 30)
        
    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get plugin setting"""
        settings = sublime.load_settings('AIGuardian.sublime-settings')
        return settings.get(key, default)
    
    def scan_code(self, code: str, language: str, filename: str) -> Optional[Dict]:
        """Scan code for vulnerabilities"""
        try:
            data = {
                'code': code,
                'language': language,
                'filename': filename
            }
            
            return self._make_request('/scan', data)
            
        except Exception as e:
            print(f"AI Guardian: Error scanning code - {e}")
            return None
    
    def submit_feedback(self, vulnerability_id: str, feedback: str, context: str) -> bool:
        """Submit feedback for adaptive learning"""
        try:
            data = {
                'user_id': 'sublime_user',
                'vulnerability_id': vulnerability_id,
                'feedback': feedback,
                'context': context
            }
            
            result = self._make_request('/feedback', data)
            return result is not None
            
        except Exception as e:
            print(f"AI Guardian: Error submitting feedback - {e}")
            return False
    
    def get_status(self) -> Optional[Dict]:
        """Get service status"""
        try:
            return self._make_request('/status', {})
        except Exception as e:
            print(f"AI Guardian: Error getting status - {e}")
            return None
    
    def _make_request(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Make HTTP request to AI Guardian API"""
        url = self.api_base_url + endpoint
        
        json_data = json.dumps(data).encode('utf-8')
        
        req = urllib.request.Request(
            url,
            data=json_data,
            headers={'Content-Type': 'application/json'}
        )
        
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                if response.status == 200:
                    return json.loads(response.read().decode('utf-8'))
                else:
                    print(f"AI Guardian: HTTP {response.status} - {response.read().decode('utf-8')}")
                    return None
                    
        except urllib.error.URLError as e:
            print(f"AI Guardian: Network error - {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"AI Guardian: JSON decode error - {e}")
            return None

class AIGuardianScanCommand(sublime_plugin.TextCommand):
    """Command to scan current file"""
    
    def run(self, edit):
        # Get current file content
        content = self.view.substr(sublime.Region(0, self.view.size()))
        filename = self.view.file_name() or 'untitled'
        language = self._detect_language()
        
        # Show scanning message
        self.view.set_status('ai_guardian', 'AI Guardian: Scanning...')
        
        # Perform scan in background thread
        threading.Thread(
            target=self._scan_async,
            args=(content, language, filename)
        ).start()
    
    def _scan_async(self, content: str, language: str, filename: str):
        """Perform scan asynchronously"""
        service = AIGuardianService()
        result = service.scan_code(content, language, filename)
        
        # Update UI on main thread
        sublime.set_timeout(
            lambda: self._handle_scan_result(result),
            0
        )
    
    def _handle_scan_result(self, result: Optional[Dict]):
        """Handle scan result"""
        self.view.erase_status('ai_guardian')
        
        if result is None:
            sublime.error_message('AI Guardian: Scan failed. Check console for details.')
            return
        
        # Clear existing annotations
        self._clear_annotations()
        
        # Add vulnerability annotations
        vulnerabilities = result.get('vulnerabilities', [])
        compliance_violations = []
        
        if result.get('compliance'):
            compliance_violations = result['compliance'].get('violations', [])
        
        total_issues = len(vulnerabilities) + len(compliance_violations)
        
        if total_issues == 0:
            sublime.message_dialog('AI Guardian: No security issues found!')
            return
        
        # Create annotations for vulnerabilities
        for vuln in vulnerabilities:
            self._add_vulnerability_annotation(vuln)
        
        # Create annotations for compliance violations
        for violation in compliance_violations:
            self._add_compliance_annotation(violation)
        
        # Show summary
        scan_time = result.get('scan_time', 0)
        message = f"AI Guardian: Found {len(vulnerabilities)} vulnerabilities and {len(compliance_violations)} compliance violations (scan time: {scan_time:.2f}s)"
        sublime.status_message(message)
        
        # Show detailed results in output panel
        self._show_detailed_results(result)
    
    def _detect_language(self) -> str:
        """Detect programming language from file extension or syntax"""
        syntax = self.view.settings().get('syntax', '')
        
        if 'Python' in syntax:
            return 'python'
        elif 'Java' in syntax:
            return 'java'
        elif 'JavaScript' in syntax or 'TypeScript' in syntax:
            return 'javascript'
        elif 'C#' in syntax:
            return 'csharp'
        elif 'Go' in syntax:
            return 'go'
        elif 'Rust' in syntax:
            return 'rust'
        elif 'PHP' in syntax:
            return 'php'
        elif 'Ruby' in syntax:
            return 'ruby'
        elif 'Swift' in syntax:
            return 'swift'
        elif 'Kotlin' in syntax:
            return 'kotlin'
        else:
            return 'text'
    
    def _clear_annotations(self):
        """Clear existing vulnerability annotations"""
        self.view.erase_regions('ai_guardian_vulnerabilities')
        self.view.erase_regions('ai_guardian_compliance')
    
    def _add_vulnerability_annotation(self, vuln: Dict):
        """Add annotation for vulnerability"""
        line = vuln.get('line', 1) - 1  # Convert to 0-based
        if line < 0:
            line = 0
        
        # Get line region
        line_region = self.view.line(self.view.text_point(line, 0))
        
        # Create region list for this severity
        severity = vuln.get('severity', 'medium').lower()
        region_key = f'ai_guardian_vuln_{severity}'
        
        existing_regions = self.view.get_regions(region_key)
        existing_regions.append(line_region)
        
        # Set region with appropriate styling
        scope = self._get_vulnerability_scope(severity)
        flags = sublime.DRAW_SQUIGGLY_UNDERLINE | sublime.DRAW_NO_FILL | sublime.DRAW_NO_OUTLINE
        
        self.view.add_regions(
            region_key,
            existing_regions,
            scope,
            flags=flags
        )
    
    def _add_compliance_annotation(self, violation: Dict):
        """Add annotation for compliance violation"""
        line = violation.get('line', 1) - 1  # Convert to 0-based
        if line < 0:
            line = 0
        
        # Get line region
        line_region = self.view.line(self.view.text_point(line, 0))
        
        # Add to compliance regions
        existing_regions = self.view.get_regions('ai_guardian_compliance')
        existing_regions.append(line_region)
        
        self.view.add_regions(
            'ai_guardian_compliance',
            existing_regions,
            'markup.warning',
            flags=sublime.DRAW_STIPPLED_UNDERLINE | sublime.DRAW_NO_FILL | sublime.DRAW_NO_OUTLINE
        )
    
    def _get_vulnerability_scope(self, severity: str) -> str:
        """Get color scope for vulnerability severity"""
        if severity in ['critical', 'high']:
            return 'markup.error'
        elif severity == 'medium':
            return 'markup.warning'
        else:
            return 'markup.info'
    
    def _show_detailed_results(self, result: Dict):
        """Show detailed results in output panel"""
        window = self.view.window()
        if not window:
            return
        
        # Get or create output panel
        panel = window.create_output_panel('ai_guardian_results')
        panel.set_syntax_file('Packages/Text/Plain text.tmLanguage')
        
        # Build results text
        output_lines = []
        output_lines.append('=== AI Guardian Security Scan Results ===')
        output_lines.append(f"Scan ID: {result.get('scan_id', 'N/A')}")
        output_lines.append(f"Timestamp: {result.get('timestamp', 'N/A')}")
        output_lines.append(f"Scan Time: {result.get('scan_time', 0):.2f} seconds")
        output_lines.append('')
        
        # Vulnerabilities
        vulnerabilities = result.get('vulnerabilities', [])
        if vulnerabilities:
            output_lines.append(f'VULNERABILITIES ({len(vulnerabilities)} found):')
            output_lines.append('-' * 50)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                output_lines.append(f"{i}. {vuln.get('name', 'Unknown')} [{vuln.get('severity', 'unknown').upper()}]")
                output_lines.append(f"   Line: {vuln.get('line', 'N/A')}")
                output_lines.append(f"   Confidence: {vuln.get('confidence', 0):.2f}")
                output_lines.append(f"   Description: {vuln.get('description', 'N/A')}")
                if vuln.get('fix_suggestion'):
                    output_lines.append(f"   Fix: {vuln['fix_suggestion']}")
                output_lines.append('')
        
        # Compliance violations
        compliance = result.get('compliance', {})
        violations = compliance.get('violations', [])
        if violations:
            output_lines.append(f'COMPLIANCE VIOLATIONS ({len(violations)} found):')
            output_lines.append('-' * 50)
            
            for i, violation in enumerate(violations, 1):
                output_lines.append(f"{i}. [{violation.get('regulation', 'Unknown')}] {violation.get('name', 'Unknown')}")
                output_lines.append(f"   Line: {violation.get('line', 'N/A')}")
                output_lines.append(f"   Severity: {violation.get('severity', 'unknown').upper()}")
                output_lines.append(f"   Description: {violation.get('description', 'N/A')}")
                if violation.get('fix_suggestion'):
                    output_lines.append(f"   Fix: {violation['fix_suggestion']}")
                output_lines.append('')
            
            risk_score = compliance.get('risk_score', 0)
            output_lines.append(f'Overall Risk Score: {risk_score:.1f}/10')
        
        # Write to panel
        panel.run_command('append', {'characters': '\n'.join(output_lines)})
        
        # Show panel
        window.run_command('show_panel', {'panel': 'output.ai_guardian_results'})

class AIGuardianStatusCommand(sublime_plugin.ApplicationCommand):
    """Command to check AI Guardian service status"""
    
    def run(self):
        threading.Thread(target=self._check_status_async).start()
    
    def _check_status_async(self):
        """Check status asynchronously"""
        service = AIGuardianService()
        status = service.get_status()
        
        sublime.set_timeout(
            lambda: self._show_status(status),
            0
        )
    
    def _show_status(self, status: Optional[Dict]):
        """Show status result"""
        if status is None:
            sublime.error_message('AI Guardian: Service is not available. Please check your configuration.')
        else:
            ai_status = status.get('ai_guardian_status', 'unknown')
            version = status.get('version', 'unknown')
            timestamp = status.get('timestamp', 'unknown')
            
            message = f"AI Guardian Status: {ai_status}\nVersion: {version}\nLast Check: {timestamp}"
            sublime.message_dialog(message)

class AIGuardianConfigureCommand(sublime_plugin.ApplicationCommand):
    """Command to open AI Guardian settings"""
    
    def run(self):
        sublime.run_command('open_file', {
            'file': '${packages}/User/AIGuardian.sublime-settings'
        })

class AIGuardianEventListener(sublime_plugin.EventListener):
    """Event listener for real-time scanning"""
    
    def __init__(self):
        self.scan_delay = 2.0  # Delay in seconds before scanning
        self.pending_scans = {}  # Track pending scans by view id
    
    def on_modified_async(self, view):
        """Handle file modification for real-time scanning"""
        settings = sublime.load_settings('AIGuardian.sublime-settings')
        if not settings.get('real_time_scanning', False):
            return
        
        # Cancel any pending scan for this view
        view_id = view.id()
        if view_id in self.pending_scans:
            self.pending_scans[view_id].cancel()
        
        # Schedule new scan
        timer = threading.Timer(
            self.scan_delay,
            self._perform_real_time_scan,
            args=(view,)
        )
        timer.start()
        self.pending_scans[view_id] = timer
    
    def on_close(self, view):
        """Clean up when view is closed"""
        view_id = view.id()
        if view_id in self.pending_scans:
            self.pending_scans[view_id].cancel()
            del self.pending_scans[view_id]
    
    def _perform_real_time_scan(self, view):
        """Perform real-time scan"""
        if not view.is_valid():
            return
        
        # Remove from pending scans
        view_id = view.id()
        if view_id in self.pending_scans:
            del self.pending_scans[view_id]
        
        # Trigger scan command
        view.run_command('ai_guardian_scan')

# Plugin lifecycle
def plugin_loaded():
    """Called when plugin is loaded"""
    print("AI Guardian plugin loaded")

def plugin_unloaded():
    """Called when plugin is unloaded"""
    print("AI Guardian plugin unloaded")

