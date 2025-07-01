" AI Guardian Security Plugin for Vim/Neovim
" Version: 3.0.0
" Description: Real-time security scanning and vulnerability detection

if exists('g:ai_guardian_loaded')
    finish
endif
let g:ai_guardian_loaded = 1

" Configuration variables
if !exists('g:ai_guardian_api_url')
    let g:ai_guardian_api_url = 'http://localhost:5002'
endif

if !exists('g:ai_guardian_ws_url')
    let g:ai_guardian_ws_url = 'ws://localhost:8765'
endif

if !exists('g:ai_guardian_auto_scan')
    let g:ai_guardian_auto_scan = 0
endif

if !exists('g:ai_guardian_scan_on_save')
    let g:ai_guardian_scan_on_save = 1
endif

if !exists('g:ai_guardian_show_signs')
    let g:ai_guardian_show_signs = 1
endif

if !exists('g:ai_guardian_highlight_vulnerabilities')
    let g:ai_guardian_highlight_vulnerabilities = 1
endif

" Initialize Python integration
python3 << EOF
import vim
import json
import requests
import threading
import time
import os
import sys
from urllib.parse import urlparse

class AIGuardianVim:
    def __init__(self):
        self.api_url = vim.eval('g:ai_guardian_api_url')
        self.ws_url = vim.eval('g:ai_guardian_ws_url')
        self.auto_scan = int(vim.eval('g:ai_guardian_auto_scan'))
        self.scan_on_save = int(vim.eval('g:ai_guardian_scan_on_save'))
        self.show_signs = int(vim.eval('g:ai_guardian_show_signs'))
        self.highlight_vulnerabilities = int(vim.eval('g:ai_guardian_highlight_vulnerabilities'))
        self.vulnerabilities = {}
        self.sign_id_counter = 1000
        
    def get_language_from_filename(self, filename):
        """Detect programming language from filename"""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.cs': 'csharp',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby',
            '.swift': 'swift',
            '.kt': 'kotlin',
            '.cpp': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.hpp': 'cpp'
        }
        _, ext = os.path.splitext(filename.lower())
        return ext_map.get(ext, 'unknown')
    
    def scan_current_buffer(self):
        """Scan the current buffer for vulnerabilities"""
        try:
            # Get current buffer content
            buffer_content = '\n'.join(vim.current.buffer)
            filename = vim.current.buffer.name or 'untitled'
            language = self.get_language_from_filename(filename)
            
            if language == 'unknown':
                self.show_message("AI Guardian: Unsupported file type", "WarningMsg")
                return
            
            # Prepare scan request
            scan_data = {
                'code': buffer_content,
                'language': language,
                'filename': os.path.basename(filename)
            }
            
            self.show_message("AI Guardian: Scanning for vulnerabilities...", "MoreMsg")
            
            # Send scan request
            response = requests.post(
                f"{self.api_url}/api/scan",
                json=scan_data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                self.process_scan_results(result, filename)
            else:
                self.show_message(f"AI Guardian: Scan failed (HTTP {response.status_code})", "ErrorMsg")
                
        except requests.exceptions.RequestException as e:
            self.show_message(f"AI Guardian: Connection error - {str(e)}", "ErrorMsg")
        except Exception as e:
            self.show_message(f"AI Guardian: Error - {str(e)}", "ErrorMsg")
    
    def process_scan_results(self, result, filename):
        """Process and display scan results"""
        vulnerabilities = result.get('vulnerabilities', [])
        
        # Clear previous results for this file
        self.clear_signs(filename)
        self.clear_highlights(filename)
        
        if not vulnerabilities:
            self.show_message("AI Guardian: No vulnerabilities found ✓", "MoreMsg")
            return
        
        # Store vulnerabilities for this file
        self.vulnerabilities[filename] = vulnerabilities
        
        # Count vulnerabilities by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Display summary
        total = len(vulnerabilities)
        summary = f"AI Guardian: Found {total} vulnerabilities - "
        summary += f"Critical: {severity_counts['critical']}, "
        summary += f"High: {severity_counts['high']}, "
        summary += f"Medium: {severity_counts['medium']}, "
        summary += f"Low: {severity_counts['low']}"
        
        self.show_message(summary, "WarningMsg")
        
        # Show signs and highlights
        if self.show_signs:
            self.add_signs(vulnerabilities, filename)
        
        if self.highlight_vulnerabilities:
            self.add_highlights(vulnerabilities)
    
    def add_signs(self, vulnerabilities, filename):
        """Add signs for vulnerabilities"""
        for vuln in vulnerabilities:
            line_num = vuln.get('line', 1)
            severity = vuln.get('severity', 'low').lower()
            
            sign_name = f"AIGuardian{severity.capitalize()}"
            sign_id = self.sign_id_counter
            self.sign_id_counter += 1
            
            vim.command(f"sign place {sign_id} line={line_num} name={sign_name} buffer={vim.current.buffer.number}")
    
    def add_highlights(self, vulnerabilities):
        """Add syntax highlighting for vulnerabilities"""
        for vuln in vulnerabilities:
            line_num = vuln.get('line', 1)
            severity = vuln.get('severity', 'low').lower()
            
            # Create match for the line
            match_group = f"AIGuardian{severity.capitalize()}Line"
            vim.command(f"call matchadd('{match_group}', '\\%{line_num}l')")
    
    def clear_signs(self, filename):
        """Clear all AI Guardian signs"""
        vim.command("sign unplace * buffer=" + str(vim.current.buffer.number))
    
    def clear_highlights(self, filename):
        """Clear all AI Guardian highlights"""
        vim.command("call clearmatches()")
    
    def show_vulnerability_details(self):
        """Show detailed information about vulnerabilities at cursor"""
        current_line = vim.current.window.cursor[0]
        filename = vim.current.buffer.name or 'untitled'
        
        if filename not in self.vulnerabilities:
            self.show_message("AI Guardian: No scan results for this file", "WarningMsg")
            return
        
        # Find vulnerabilities at current line
        line_vulns = [v for v in self.vulnerabilities[filename] if v.get('line') == current_line]
        
        if not line_vulns:
            self.show_message("AI Guardian: No vulnerabilities at current line", "MoreMsg")
            return
        
        # Create detailed view
        details = []
        for vuln in line_vulns:
            details.append(f"Type: {vuln.get('type', 'Unknown')}")
            details.append(f"Severity: {vuln.get('severity', 'Unknown')}")
            details.append(f"Description: {vuln.get('description', 'No description')}")
            details.append(f"CWE: {vuln.get('cwe', 'N/A')}")
            if vuln.get('recommendation'):
                details.append(f"Recommendation: {vuln.get('recommendation')}")
            details.append("-" * 50)
        
        # Open details in new buffer
        vim.command("new")
        vim.command("setlocal buftype=nofile")
        vim.command("setlocal bufhidden=wipe")
        vim.command("setlocal noswapfile")
        vim.command("file AI_Guardian_Details")
        
        vim.current.buffer[:] = details
        vim.command("setlocal readonly")
    
    def scan_project(self):
        """Scan entire project for vulnerabilities"""
        try:
            # Get project root (current working directory)
            project_root = vim.eval("getcwd()")
            
            self.show_message("AI Guardian: Scanning project...", "MoreMsg")
            
            # Find all supported files
            supported_extensions = ['.py', '.js', '.ts', '.java', '.cs', '.go', '.rs', '.php', '.rb', '.swift', '.kt']
            files_to_scan = []
            
            for root, dirs, files in os.walk(project_root):
                # Skip common directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'target', 'build']]
                
                for file in files:
                    if any(file.endswith(ext) for ext in supported_extensions):
                        files_to_scan.append(os.path.join(root, file))
            
            if not files_to_scan:
                self.show_message("AI Guardian: No supported files found in project", "WarningMsg")
                return
            
            # Limit to first 50 files for performance
            files_to_scan = files_to_scan[:50]
            
            total_vulnerabilities = 0
            files_with_issues = 0
            
            for file_path in files_to_scan:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    language = self.get_language_from_filename(file_path)
                    if language == 'unknown':
                        continue
                    
                    scan_data = {
                        'code': content,
                        'language': language,
                        'filename': os.path.basename(file_path)
                    }
                    
                    response = requests.post(
                        f"{self.api_url}/api/scan",
                        json=scan_data,
                        timeout=10
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        vulnerabilities = result.get('vulnerabilities', [])
                        if vulnerabilities:
                            total_vulnerabilities += len(vulnerabilities)
                            files_with_issues += 1
                            
                except Exception as e:
                    continue
            
            summary = f"AI Guardian: Project scan complete - {total_vulnerabilities} vulnerabilities found in {files_with_issues} files"
            self.show_message(summary, "WarningMsg" if total_vulnerabilities > 0 else "MoreMsg")
            
        except Exception as e:
            self.show_message(f"AI Guardian: Project scan error - {str(e)}", "ErrorMsg")
    
    def toggle_auto_scan(self):
        """Toggle automatic scanning"""
        self.auto_scan = 1 - self.auto_scan
        vim.command(f"let g:ai_guardian_auto_scan = {self.auto_scan}")
        
        status = "enabled" if self.auto_scan else "disabled"
        self.show_message(f"AI Guardian: Auto-scan {status}", "MoreMsg")
    
    def show_message(self, message, highlight_group="None"):
        """Display message to user"""
        vim.command(f"echohl {highlight_group}")
        vim.command(f"echo '{message}'")
        vim.command("echohl None")

# Create global instance
ai_guardian = AIGuardianVim()
EOF

" Define sign types for different severity levels
sign define AIGuardianCritical text=🔴 texthl=ErrorMsg
sign define AIGuardianHigh text=🟠 texthl=WarningMsg  
sign define AIGuardianMedium text=🟡 texthl=MoreMsg
sign define AIGuardianLow text=🔵 texthl=Comment

" Define highlight groups for vulnerability lines
highlight AIGuardianCriticalLine ctermbg=52 guibg=#5f0000
highlight AIGuardianHighLine ctermbg=58 guibg=#5f5f00
highlight AIGuardianMediumLine ctermbg=22 guibg=#005f00
highlight AIGuardianLowLine ctermbg=17 guibg=#00005f

" Define commands
command! AIGuardianScan python3 ai_guardian.scan_current_buffer()
command! AIGuardianScanProject python3 ai_guardian.scan_project()
command! AIGuardianDetails python3 ai_guardian.show_vulnerability_details()
command! AIGuardianToggleAutoScan python3 ai_guardian.toggle_auto_scan()
command! AIGuardianClear python3 ai_guardian.clear_signs(vim.current.buffer.name); ai_guardian.clear_highlights(vim.current.buffer.name)

" Define key mappings
nnoremap <leader>gs :AIGuardianScan<CR>
nnoremap <leader>gp :AIGuardianScanProject<CR>
nnoremap <leader>gd :AIGuardianDetails<CR>
nnoremap <leader>gt :AIGuardianToggleAutoScan<CR>
nnoremap <leader>gc :AIGuardianClear<CR>

" Auto-commands
augroup AIGuardian
    autocmd!
    if g:ai_guardian_scan_on_save
        autocmd BufWritePost *.py,*.js,*.ts,*.java,*.cs,*.go,*.rs,*.php,*.rb,*.swift,*.kt python3 ai_guardian.scan_current_buffer()
    endif
    
    " Auto-scan on buffer changes (if enabled)
    autocmd TextChanged,TextChangedI *.py,*.js,*.ts,*.java,*.cs,*.go,*.rs,*.php,*.rb,*.swift,*.kt 
        \ if g:ai_guardian_auto_scan | 
        \   call timer_start(2000, {-> execute('python3 ai_guardian.scan_current_buffer()')}) | 
        \ endif
augroup END

" Status line integration
function! AIGuardianStatus()
    let filename = expand('%:p')
    if has_key(g:, 'ai_guardian_vulnerabilities') && has_key(g:ai_guardian_vulnerabilities, filename)
        let count = len(g:ai_guardian_vulnerabilities[filename])
        return count > 0 ? printf('[🛡️ %d]', count) : '[🛡️ ✓]'
    endif
    return '[🛡️]'
endfunction

" Add to statusline if not already present
if &statusline !~ 'AIGuardianStatus'
    set statusline+=%{AIGuardianStatus()}
endif

echo "AI Guardian plugin loaded successfully! Use :AIGuardianScan to start scanning."

