"""
AI Guardian Jupyter Extension
Real-time security scanning for Jupyter Notebooks and Google Colab
"""

import os
import sys
import json
import time
import asyncio
import threading
from typing import Dict, List, Optional, Any, Union
from datetime import datetime

import requests
import websocket
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

from IPython.core.magic import Magics, magics_class, line_magic, cell_magic
from IPython.core.magic_arguments import argument, magic_arguments, parse_argline
from IPython.display import display, HTML, Javascript, Markdown
from IPython import get_ipython
import ipywidgets as widgets
from ipywidgets import interact, interactive, fixed, interact_manual

__version__ = "3.0.0"
__author__ = "OmniPanel AI Team"

class AIGuardianConfig:
    """Configuration management for AI Guardian Jupyter extension"""
    
    def __init__(self):
        self.api_url = os.getenv('AI_GUARDIAN_API_URL', 'http://localhost:5002')
        self.ws_url = os.getenv('AI_GUARDIAN_WS_URL', 'ws://localhost:8765')
        self.cloud_api_url = os.getenv('AI_GUARDIAN_CLOUD_API', 'https://api.ai-guardian.cloud')
        self.auto_scan = True
        self.scan_on_execute = True
        self.show_inline_warnings = True
        self.enable_real_time = False
        self.colab_mode = self._detect_colab()
        self.scan_history = []
        
    def _detect_colab(self) -> bool:
        """Detect if running in Google Colab"""
        try:
            import google.colab
            return True
        except ImportError:
            return False
    
    def update(self, **kwargs):
        """Update configuration parameters"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

class VulnerabilityAnalyzer:
    """Analyze and visualize vulnerability data"""
    
    def __init__(self, config: AIGuardianConfig):
        self.config = config
        
    def create_vulnerability_dashboard(self, vulnerabilities: List[Dict]) -> widgets.VBox:
        """Create interactive dashboard for vulnerabilities"""
        if not vulnerabilities:
            return widgets.HTML("<h3>✅ No vulnerabilities found!</h3>")
        
        # Summary statistics
        df = pd.DataFrame(vulnerabilities)
        severity_counts = df['severity'].value_counts()
        
        # Create widgets
        summary_html = self._create_summary_html(severity_counts, len(vulnerabilities))
        chart_widget = self._create_severity_chart(severity_counts)
        details_widget = self._create_details_table(df)
        
        # Combine widgets
        dashboard = widgets.VBox([
            widgets.HTML("<h2>🛡️ AI Guardian Security Report</h2>"),
            summary_html,
            chart_widget,
            details_widget
        ])
        
        return dashboard
    
    def _create_summary_html(self, severity_counts: pd.Series, total: int) -> widgets.HTML:
        """Create summary HTML widget"""
        critical = severity_counts.get('critical', 0)
        high = severity_counts.get('high', 0)
        medium = severity_counts.get('medium', 0)
        low = severity_counts.get('low', 0)
        
        html = f"""
        <div style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin: 10px 0;">
            <h3>📊 Vulnerability Summary</h3>
            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                <div style="background: #dc3545; color: white; padding: 10px; border-radius: 5px; min-width: 120px; text-align: center;">
                    <strong>🔴 Critical</strong><br>{critical}
                </div>
                <div style="background: #fd7e14; color: white; padding: 10px; border-radius: 5px; min-width: 120px; text-align: center;">
                    <strong>🟠 High</strong><br>{high}
                </div>
                <div style="background: #ffc107; color: black; padding: 10px; border-radius: 5px; min-width: 120px; text-align: center;">
                    <strong>🟡 Medium</strong><br>{medium}
                </div>
                <div style="background: #0dcaf0; color: black; padding: 10px; border-radius: 5px; min-width: 120px; text-align: center;">
                    <strong>🔵 Low</strong><br>{low}
                </div>
                <div style="background: #6c757d; color: white; padding: 10px; border-radius: 5px; min-width: 120px; text-align: center;">
                    <strong>📈 Total</strong><br>{total}
                </div>
            </div>
        </div>
        """
        return widgets.HTML(html)
    
    def _create_severity_chart(self, severity_counts: pd.Series) -> widgets.Output:
        """Create severity distribution chart"""
        output = widgets.Output()
        
        with output:
            # Create plotly chart
            colors = {
                'critical': '#dc3545',
                'high': '#fd7e14', 
                'medium': '#ffc107',
                'low': '#0dcaf0'
            }
            
            fig = go.Figure(data=[
                go.Bar(
                    x=severity_counts.index,
                    y=severity_counts.values,
                    marker_color=[colors.get(sev, '#6c757d') for sev in severity_counts.index],
                    text=severity_counts.values,
                    textposition='auto',
                )
            ])
            
            fig.update_layout(
                title="Vulnerability Distribution by Severity",
                xaxis_title="Severity Level",
                yaxis_title="Count",
                height=400,
                showlegend=False
            )
            
            fig.show()
        
        return output
    
    def _create_details_table(self, df: pd.DataFrame) -> widgets.Output:
        """Create detailed vulnerability table"""
        output = widgets.Output()
        
        with output:
            # Display top 10 most critical vulnerabilities
            display_df = df.head(10)[['type', 'severity', 'line', 'description', 'cwe']]
            display_df = display_df.sort_values('severity', key=lambda x: x.map({
                'critical': 4, 'high': 3, 'medium': 2, 'low': 1
            }), ascending=False)
            
            print("🔍 Top Vulnerabilities (showing first 10):")
            display(display_df)
        
        return output

class AIGuardianScanner:
    """Core scanning functionality"""
    
    def __init__(self, config: AIGuardianConfig):
        self.config = config
        self.session = requests.Session()
        self.ws_connection = None
        self.analyzer = VulnerabilityAnalyzer(config)
        
    def scan_code(self, code: str, language: str = 'python', filename: str = 'notebook_cell') -> Dict:
        """Scan code for vulnerabilities"""
        try:
            # Try local API first
            api_url = self.config.api_url
            response = self._make_scan_request(api_url, code, language, filename)
            
            if response is None and self.config.colab_mode:
                # Fallback to cloud API for Colab
                api_url = self.config.cloud_api_url
                response = self._make_scan_request(api_url, code, language, filename)
            
            if response is None:
                return {
                    'vulnerabilities': [],
                    'error': 'Unable to connect to AI Guardian API',
                    'scan_time': time.time()
                }
            
            result = response.json()
            result['scan_time'] = time.time()
            result['api_used'] = api_url
            
            # Store in history
            self.config.scan_history.append({
                'timestamp': datetime.now(),
                'vulnerabilities_count': len(result.get('vulnerabilities', [])),
                'language': language,
                'filename': filename
            })
            
            return result
            
        except Exception as e:
            return {
                'vulnerabilities': [],
                'error': str(e),
                'scan_time': time.time()
            }
    
    def _make_scan_request(self, api_url: str, code: str, language: str, filename: str) -> Optional[requests.Response]:
        """Make scan request to API"""
        try:
            response = self.session.post(
                f"{api_url}/api/scan",
                json={
                    'code': code,
                    'language': language,
                    'filename': filename
                },
                timeout=30
            )
            
            if response.status_code == 200:
                return response
            else:
                print(f"API returned status {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None
    
    def scan_notebook_cells(self, notebook_path: Optional[str] = None) -> Dict:
        """Scan all cells in current notebook"""
        try:
            ip = get_ipython()
            if not ip:
                return {'error': 'Not running in IPython environment'}
            
            # Get all code cells
            cells = []
            if hasattr(ip, 'user_ns'):
                # Try to get notebook cells from history
                history = list(ip.history_manager.get_range())
                for session, line_num, source in history[-50:]:  # Last 50 entries
                    if source.strip():
                        cells.append({
                            'source': source,
                            'cell_type': 'code',
                            'execution_count': line_num
                        })
            
            if not cells:
                return {'error': 'No code cells found'}
            
            # Scan each cell
            all_vulnerabilities = []
            cell_results = []
            
            for i, cell in enumerate(cells):
                if cell['cell_type'] == 'code' and cell['source'].strip():
                    result = self.scan_code(
                        cell['source'], 
                        'python', 
                        f'cell_{cell.get("execution_count", i)}'
                    )
                    
                    vulnerabilities = result.get('vulnerabilities', [])
                    if vulnerabilities:
                        for vuln in vulnerabilities:
                            vuln['cell_number'] = cell.get('execution_count', i)
                        all_vulnerabilities.extend(vulnerabilities)
                    
                    cell_results.append({
                        'cell_number': cell.get('execution_count', i),
                        'vulnerabilities_count': len(vulnerabilities),
                        'has_critical': any(v['severity'] == 'critical' for v in vulnerabilities)
                    })
            
            return {
                'total_cells_scanned': len(cells),
                'total_vulnerabilities': len(all_vulnerabilities),
                'vulnerabilities': all_vulnerabilities,
                'cell_results': cell_results,
                'scan_time': time.time()
            }
            
        except Exception as e:
            return {'error': str(e)}

@magics_class
class AIGuardianMagics(Magics):
    """IPython magic commands for AI Guardian"""
    
    def __init__(self, shell):
        super().__init__(shell)
        self.config = AIGuardianConfig()
        self.scanner = AIGuardianScanner(self.config)
        self._setup_auto_scan()
    
    def _setup_auto_scan(self):
        """Setup automatic scanning on cell execution"""
        if self.config.scan_on_execute:
            # Register post-execute hook
            self.shell.events.register('post_execute', self._post_execute_hook)
    
    def _post_execute_hook(self):
        """Hook called after cell execution"""
        if self.config.auto_scan:
            # Get the last executed cell
            history = list(self.shell.history_manager.get_range(output=False))
            if history:
                _, _, source = history[-1]
                if source.strip() and not source.startswith('%'):
                    # Scan in background to avoid blocking
                    threading.Thread(
                        target=self._background_scan,
                        args=(source,),
                        daemon=True
                    ).start()
    
    def _background_scan(self, code: str):
        """Perform background scan"""
        try:
            result = self.scanner.scan_code(code)
            vulnerabilities = result.get('vulnerabilities', [])
            
            if vulnerabilities and self.config.show_inline_warnings:
                # Show warning for critical/high vulnerabilities
                critical_high = [v for v in vulnerabilities if v['severity'] in ['critical', 'high']]
                if critical_high:
                    print(f"⚠️  AI Guardian: Found {len(critical_high)} critical/high severity vulnerabilities in last cell")
        except Exception as e:
            pass  # Silent fail for background scanning
    
    @line_magic
    @magic_arguments()
    @argument('--language', '-l', default='python', help='Programming language')
    @argument('--show-dashboard', '-d', action='store_true', help='Show interactive dashboard')
    @argument('--export', '-e', help='Export results to file')
    def ai_guardian_scan(self, line):
        """Scan the last executed cell for vulnerabilities"""
        args = parse_argline(self.ai_guardian_scan, line)
        
        # Get last executed cell
        history = list(self.shell.history_manager.get_range(output=False))
        if not history:
            print("❌ No code history found")
            return
        
        _, _, source = history[-1]
        if not source.strip():
            print("❌ No code to scan")
            return
        
        print("🔍 AI Guardian: Scanning code for vulnerabilities...")
        result = self.scanner.scan_code(source, args.language)
        
        if 'error' in result:
            print(f"❌ Scan failed: {result['error']}")
            return
        
        vulnerabilities = result.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print("✅ No vulnerabilities found!")
            return
        
        print(f"⚠️  Found {len(vulnerabilities)} vulnerabilities")
        
        if args.show_dashboard:
            dashboard = self.scanner.analyzer.create_vulnerability_dashboard(vulnerabilities)
            display(dashboard)
        else:
            self._display_simple_results(vulnerabilities)
        
        if args.export:
            self._export_results(vulnerabilities, args.export)
    
    @cell_magic
    @magic_arguments()
    @argument('--language', '-l', default='python', help='Programming language')
    @argument('--show-dashboard', '-d', action='store_true', help='Show interactive dashboard')
    def ai_guardian_scan_cell(self, line, cell):
        """Scan the current cell for vulnerabilities"""
        args = parse_argline(self.ai_guardian_scan_cell, line)
        
        print("🔍 AI Guardian: Scanning cell for vulnerabilities...")
        result = self.scanner.scan_code(cell, args.language, 'current_cell')
        
        if 'error' in result:
            print(f"❌ Scan failed: {result['error']}")
            return
        
        vulnerabilities = result.get('vulnerabilities', [])
        
        if not vulnerabilities:
            print("✅ No vulnerabilities found!")
            return
        
        print(f"⚠️  Found {len(vulnerabilities)} vulnerabilities")
        
        if args.show_dashboard:
            dashboard = self.scanner.analyzer.create_vulnerability_dashboard(vulnerabilities)
            display(dashboard)
        else:
            self._display_simple_results(vulnerabilities)
    
    @line_magic
    def ai_guardian_scan_notebook(self, line):
        """Scan all cells in the notebook"""
        print("🔍 AI Guardian: Scanning entire notebook...")
        result = self.scanner.scan_notebook_cells()
        
        if 'error' in result:
            print(f"❌ Scan failed: {result['error']}")
            return
        
        total_cells = result.get('total_cells_scanned', 0)
        total_vulns = result.get('total_vulnerabilities', 0)
        vulnerabilities = result.get('vulnerabilities', [])
        
        print(f"📊 Scanned {total_cells} cells, found {total_vulns} vulnerabilities")
        
        if vulnerabilities:
            dashboard = self.scanner.analyzer.create_vulnerability_dashboard(vulnerabilities)
            display(dashboard)
        else:
            print("✅ No vulnerabilities found in notebook!")
    
    @line_magic
    @magic_arguments()
    @argument('--enable', action='store_true', help='Enable auto-scan')
    @argument('--disable', action='store_true', help='Disable auto-scan')
    @argument('--status', action='store_true', help='Show current status')
    def ai_guardian_config(self, line):
        """Configure AI Guardian settings"""
        args = parse_argline(self.ai_guardian_config, line)
        
        if args.enable:
            self.config.auto_scan = True
            print("✅ Auto-scan enabled")
        elif args.disable:
            self.config.auto_scan = False
            print("❌ Auto-scan disabled")
        elif args.status:
            self._show_status()
        else:
            self._show_config_widget()
    
    @line_magic
    def ai_guardian_dashboard(self, line):
        """Show AI Guardian dashboard"""
        dashboard = self._create_main_dashboard()
        display(dashboard)
    
    @line_magic
    def ai_guardian_history(self, line):
        """Show scan history"""
        if not self.config.scan_history:
            print("📊 No scan history available")
            return
        
        df = pd.DataFrame(self.config.scan_history)
        
        # Create history visualization
        fig = px.line(
            df, 
            x='timestamp', 
            y='vulnerabilities_count',
            title='Vulnerability Detection Over Time',
            labels={'vulnerabilities_count': 'Vulnerabilities Found', 'timestamp': 'Time'}
        )
        fig.show()
        
        print(f"📈 Total scans performed: {len(self.config.scan_history)}")
        print(f"🔍 Average vulnerabilities per scan: {df['vulnerabilities_count'].mean():.1f}")
    
    def _display_simple_results(self, vulnerabilities: List[Dict]):
        """Display simple text results"""
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        print("\n📊 Summary:")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}[severity]
                print(f"  {emoji} {severity.capitalize()}: {count}")
        
        print("\n🔍 Details:")
        for i, vuln in enumerate(vulnerabilities[:5], 1):
            print(f"  {i}. Line {vuln['line']}: {vuln['type']} ({vuln['severity']})")
            print(f"     {vuln['description']}")
        
        if len(vulnerabilities) > 5:
            print(f"     ... and {len(vulnerabilities) - 5} more")
    
    def _show_status(self):
        """Show current configuration status"""
        print("🛡️ AI Guardian Status:")
        print(f"  Auto-scan: {'✅ Enabled' if self.config.auto_scan else '❌ Disabled'}")
        print(f"  Scan on execute: {'✅ Enabled' if self.config.scan_on_execute else '❌ Disabled'}")
        print(f"  Inline warnings: {'✅ Enabled' if self.config.show_inline_warnings else '❌ Disabled'}")
        print(f"  Google Colab mode: {'✅ Detected' if self.config.colab_mode else '❌ Not detected'}")
        print(f"  API URL: {self.config.api_url}")
        print(f"  Total scans: {len(self.config.scan_history)}")
    
    def _show_config_widget(self):
        """Show interactive configuration widget"""
        auto_scan_widget = widgets.Checkbox(
            value=self.config.auto_scan,
            description='Auto-scan on cell execution',
            style={'description_width': 'initial'}
        )
        
        inline_warnings_widget = widgets.Checkbox(
            value=self.config.show_inline_warnings,
            description='Show inline warnings',
            style={'description_width': 'initial'}
        )
        
        api_url_widget = widgets.Text(
            value=self.config.api_url,
            description='API URL:',
            style={'description_width': 'initial'}
        )
        
        def update_config(change):
            self.config.auto_scan = auto_scan_widget.value
            self.config.show_inline_warnings = inline_warnings_widget.value
            self.config.api_url = api_url_widget.value
        
        auto_scan_widget.observe(update_config, names='value')
        inline_warnings_widget.observe(update_config, names='value')
        api_url_widget.observe(update_config, names='value')
        
        config_widget = widgets.VBox([
            widgets.HTML("<h3>🛡️ AI Guardian Configuration</h3>"),
            auto_scan_widget,
            inline_warnings_widget,
            api_url_widget,
            widgets.HTML("<p><em>Changes are applied automatically</em></p>")
        ])
        
        display(config_widget)
    
    def _create_main_dashboard(self):
        """Create main dashboard widget"""
        # Status summary
        status_html = f"""
        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; margin: 10px 0;">
            <h2>🛡️ AI Guardian for Jupyter</h2>
            <p>Real-time security scanning for your notebook</p>
            <div style="display: flex; gap: 20px; margin-top: 15px;">
                <div>📊 Total Scans: {len(self.config.scan_history)}</div>
                <div>🔍 Auto-scan: {'✅' if self.config.auto_scan else '❌'}</div>
                <div>☁️ Colab Mode: {'✅' if self.config.colab_mode else '❌'}</div>
            </div>
        </div>
        """
        
        # Quick action buttons
        scan_button = widgets.Button(
            description="🔍 Scan Last Cell",
            button_style='primary',
            layout=widgets.Layout(width='200px')
        )
        
        notebook_button = widgets.Button(
            description="📓 Scan Notebook",
            button_style='info',
            layout=widgets.Layout(width='200px')
        )
        
        config_button = widgets.Button(
            description="⚙️ Settings",
            button_style='warning',
            layout=widgets.Layout(width='200px')
        )
        
        def on_scan_click(b):
            self.ai_guardian_scan('')
        
        def on_notebook_click(b):
            self.ai_guardian_scan_notebook('')
        
        def on_config_click(b):
            self._show_config_widget()
        
        scan_button.on_click(on_scan_click)
        notebook_button.on_click(on_notebook_click)
        config_button.on_click(on_config_click)
        
        buttons = widgets.HBox([scan_button, notebook_button, config_button])
        
        # Recent activity
        recent_html = "<h3>📈 Recent Activity</h3>"
        if self.config.scan_history:
            recent_scans = self.config.scan_history[-5:]
            recent_html += "<ul>"
            for scan in recent_scans:
                timestamp = scan['timestamp'].strftime('%H:%M:%S')
                count = scan['vulnerabilities_count']
                recent_html += f"<li>{timestamp}: {count} vulnerabilities found</li>"
            recent_html += "</ul>"
        else:
            recent_html += "<p>No recent scans</p>"
        
        dashboard = widgets.VBox([
            widgets.HTML(status_html),
            buttons,
            widgets.HTML(recent_html)
        ])
        
        return dashboard
    
    def _export_results(self, vulnerabilities: List[Dict], filename: str):
        """Export results to file"""
        try:
            df = pd.DataFrame(vulnerabilities)
            
            if filename.endswith('.csv'):
                df.to_csv(filename, index=False)
            elif filename.endswith('.json'):
                with open(filename, 'w') as f:
                    json.dump(vulnerabilities, f, indent=2)
            else:
                # Default to CSV
                filename += '.csv'
                df.to_csv(filename, index=False)
            
            print(f"✅ Results exported to {filename}")
        except Exception as e:
            print(f"❌ Export failed: {e}")

def load_ipython_extension(ipython):
    """Load the AI Guardian extension"""
    ipython.register_magic_functions(AIGuardianMagics)
    
    # Show welcome message
    welcome_html = """
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px; border-radius: 8px; margin: 10px 0;">
        <h3>🛡️ AI Guardian for Jupyter Loaded Successfully!</h3>
        <p>Available magic commands:</p>
        <ul>
            <li><code>%ai_guardian_scan</code> - Scan last executed cell</li>
            <li><code>%%ai_guardian_scan_cell</code> - Scan current cell</li>
            <li><code>%ai_guardian_scan_notebook</code> - Scan entire notebook</li>
            <li><code>%ai_guardian_config</code> - Configure settings</li>
            <li><code>%ai_guardian_dashboard</code> - Show dashboard</li>
            <li><code>%ai_guardian_history</code> - Show scan history</li>
        </ul>
        <p>Type <code>%ai_guardian_dashboard</code> to get started!</p>
    </div>
    """
    
    display(HTML(welcome_html))

def unload_ipython_extension(ipython):
    """Unload the AI Guardian extension"""
    pass

# Auto-load in Colab
try:
    import google.colab
    # Auto-load extension in Colab
    ip = get_ipython()
    if ip:
        load_ipython_extension(ip)
except ImportError:
    pass

