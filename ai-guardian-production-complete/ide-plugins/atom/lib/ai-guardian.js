const { CompositeDisposable, Disposable } = require('atom');
const axios = require('axios');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');

class AIGuardianAtom {
  constructor() {
    this.subscriptions = null;
    this.statusBarTile = null;
    this.realTimeEnabled = false;
    this.wsConnection = null;
    this.apiBaseUrl = 'http://localhost:5002'; // API Gateway
    this.wsUrl = 'ws://localhost:8765'; // WebSocket for real-time
    this.linterProvider = null;
  }

  activate(state) {
    this.subscriptions = new CompositeDisposable();

    // Register commands
    this.subscriptions.add(
      atom.commands.add('atom-workspace', {
        'ai-guardian:scan-file': () => this.scanCurrentFile(),
        'ai-guardian:scan-project': () => this.scanProject(),
        'ai-guardian:toggle-real-time': () => this.toggleRealTime(),
        'ai-guardian:show-settings': () => this.showSettings()
      })
    );

    // Initialize linter provider
    this.linterProvider = {
      name: 'AI Guardian',
      grammarScopes: ['*'],
      scope: 'file',
      lintsOnChange: true,
      lint: (textEditor) => this.lintFile(textEditor)
    };

    // Setup real-time monitoring
    this.setupRealTimeMonitoring();

    console.log('AI Guardian Atom package activated');
  }

  deactivate() {
    if (this.subscriptions) {
      this.subscriptions.dispose();
    }
    if (this.wsConnection) {
      this.wsConnection.close();
    }
    if (this.statusBarTile) {
      this.statusBarTile.destroy();
    }
  }

  serialize() {
    return {
      realTimeEnabled: this.realTimeEnabled
    };
  }

  provideLinter() {
    return this.linterProvider;
  }

  consumeStatusBar(statusBar) {
    this.statusBar = statusBar;
    this.updateStatusBar();
  }

  async scanCurrentFile() {
    const editor = atom.workspace.getActiveTextEditor();
    if (!editor) {
      atom.notifications.addWarning('No active editor found');
      return;
    }

    const filePath = editor.getPath();
    const content = editor.getText();
    
    if (!filePath) {
      atom.notifications.addWarning('Please save the file before scanning');
      return;
    }

    try {
      atom.notifications.addInfo('AI Guardian: Scanning file...', { dismissable: true });
      
      const response = await axios.post(`${this.apiBaseUrl}/api/scan`, {
        code: content,
        language: this.getLanguageFromPath(filePath),
        filename: path.basename(filePath)
      });

      const results = response.data;
      this.displayScanResults(results, filePath);
      
    } catch (error) {
      console.error('Scan error:', error);
      atom.notifications.addError(`AI Guardian scan failed: ${error.message}`);
    }
  }

  async scanProject() {
    const projectPaths = atom.project.getPaths();
    if (!projectPaths.length) {
      atom.notifications.addWarning('No project found');
      return;
    }

    try {
      atom.notifications.addInfo('AI Guardian: Scanning project...', { dismissable: true });
      
      const files = this.getProjectFiles(projectPaths[0]);
      const scanPromises = files.map(file => this.scanFileForProject(file));
      
      const results = await Promise.all(scanPromises);
      const allVulnerabilities = results.flat();
      
      this.displayProjectScanResults(allVulnerabilities);
      
    } catch (error) {
      console.error('Project scan error:', error);
      atom.notifications.addError(`AI Guardian project scan failed: ${error.message}`);
    }
  }

  async scanFileForProject(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const response = await axios.post(`${this.apiBaseUrl}/api/scan`, {
        code: content,
        language: this.getLanguageFromPath(filePath),
        filename: path.basename(filePath)
      });
      
      return response.data.vulnerabilities.map(vuln => ({
        ...vuln,
        file: filePath
      }));
    } catch (error) {
      console.error(`Error scanning ${filePath}:`, error);
      return [];
    }
  }

  getProjectFiles(projectPath) {
    const files = [];
    const supportedExtensions = ['.py', '.js', '.ts', '.java', '.cs', '.go', '.rs', '.php', '.rb', '.swift', '.kt'];
    
    const walkDir = (dir) => {
      const items = fs.readdirSync(dir);
      items.forEach(item => {
        const fullPath = path.join(dir, item);
        const stat = fs.statSync(fullPath);
        
        if (stat.isDirectory() && !item.startsWith('.') && item !== 'node_modules') {
          walkDir(fullPath);
        } else if (stat.isFile() && supportedExtensions.some(ext => item.endsWith(ext))) {
          files.push(fullPath);
        }
      });
    };
    
    walkDir(projectPath);
    return files.slice(0, 100); // Limit to 100 files for performance
  }

  toggleRealTime() {
    this.realTimeEnabled = !this.realTimeEnabled;
    
    if (this.realTimeEnabled) {
      this.startRealTimeMonitoring();
      atom.notifications.addSuccess('AI Guardian: Real-time monitoring enabled');
    } else {
      this.stopRealTimeMonitoring();
      atom.notifications.addInfo('AI Guardian: Real-time monitoring disabled');
    }
    
    this.updateStatusBar();
  }

  setupRealTimeMonitoring() {
    // Monitor file changes
    atom.workspace.observeTextEditors((editor) => {
      if (this.realTimeEnabled) {
        const disposable = editor.onDidStopChanging(() => {
          if (this.realTimeEnabled) {
            this.debouncedScan(editor);
          }
        });
        this.subscriptions.add(disposable);
      }
    });
  }

  debouncedScan = this.debounce((editor) => {
    this.lintFile(editor);
  }, 1000);

  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  }

  startRealTimeMonitoring() {
    try {
      this.wsConnection = new WebSocket(this.wsUrl);
      
      this.wsConnection.on('open', () => {
        console.log('AI Guardian WebSocket connected');
      });
      
      this.wsConnection.on('message', (data) => {
        const message = JSON.parse(data);
        this.handleRealTimeUpdate(message);
      });
      
      this.wsConnection.on('error', (error) => {
        console.error('WebSocket error:', error);
      });
      
    } catch (error) {
      console.error('Failed to connect to AI Guardian WebSocket:', error);
    }
  }

  stopRealTimeMonitoring() {
    if (this.wsConnection) {
      this.wsConnection.close();
      this.wsConnection = null;
    }
  }

  handleRealTimeUpdate(message) {
    if (message.type === 'vulnerability_detected') {
      atom.notifications.addWarning(
        `AI Guardian: New vulnerability detected in ${message.file}`,
        { 
          detail: message.description,
          dismissable: true 
        }
      );
    }
  }

  async lintFile(textEditor) {
    if (!this.realTimeEnabled) return [];
    
    const filePath = textEditor.getPath();
    const content = textEditor.getText();
    
    if (!filePath) return [];

    try {
      const response = await axios.post(`${this.apiBaseUrl}/api/scan`, {
        code: content,
        language: this.getLanguageFromPath(filePath),
        filename: path.basename(filePath)
      });

      const results = response.data;
      return this.convertToLinterMessages(results.vulnerabilities, textEditor);
      
    } catch (error) {
      console.error('Linter scan error:', error);
      return [];
    }
  }

  convertToLinterMessages(vulnerabilities, textEditor) {
    return vulnerabilities.map(vuln => ({
      severity: this.getSeverityLevel(vuln.severity),
      location: {
        file: textEditor.getPath(),
        position: [
          [vuln.line - 1, 0],
          [vuln.line - 1, textEditor.lineTextForBufferRow(vuln.line - 1).length]
        ]
      },
      excerpt: `${vuln.type}: ${vuln.description}`,
      description: `
        **Vulnerability:** ${vuln.type}
        **Severity:** ${vuln.severity}
        **Description:** ${vuln.description}
        **Recommendation:** ${vuln.recommendation || 'Review and fix this vulnerability'}
        **CWE:** ${vuln.cwe || 'N/A'}
      `
    }));
  }

  getSeverityLevel(severity) {
    const severityMap = {
      'critical': 'error',
      'high': 'error',
      'medium': 'warning',
      'low': 'info'
    };
    return severityMap[severity.toLowerCase()] || 'info';
  }

  displayScanResults(results, filePath) {
    const vulnerabilities = results.vulnerabilities || [];
    
    if (vulnerabilities.length === 0) {
      atom.notifications.addSuccess(`AI Guardian: No vulnerabilities found in ${path.basename(filePath)}`);
      return;
    }

    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = vulnerabilities.filter(v => v.severity === 'medium').length;
    const lowCount = vulnerabilities.filter(v => v.severity === 'low').length;

    const summary = `Found ${vulnerabilities.length} vulnerabilities: ${criticalCount} critical, ${highCount} high, ${mediumCount} medium, ${lowCount} low`;
    
    atom.notifications.addWarning(`AI Guardian: ${summary}`, {
      detail: vulnerabilities.slice(0, 5).map(v => 
        `Line ${v.line}: ${v.type} - ${v.description}`
      ).join('\n'),
      dismissable: true
    });
  }

  displayProjectScanResults(vulnerabilities) {
    if (vulnerabilities.length === 0) {
      atom.notifications.addSuccess('AI Guardian: No vulnerabilities found in project');
      return;
    }

    const fileCount = new Set(vulnerabilities.map(v => v.file)).size;
    const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.severity === 'high').length;

    const summary = `Found ${vulnerabilities.length} vulnerabilities across ${fileCount} files`;
    
    atom.notifications.addWarning(`AI Guardian: ${summary}`, {
      detail: `${criticalCount} critical, ${highCount} high severity issues found`,
      dismissable: true
    });
  }

  getLanguageFromPath(filePath) {
    const ext = path.extname(filePath).toLowerCase();
    const languageMap = {
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
      '.kt': 'kotlin'
    };
    return languageMap[ext] || 'unknown';
  }

  updateStatusBar() {
    if (!this.statusBar) return;

    if (this.statusBarTile) {
      this.statusBarTile.destroy();
    }

    const element = document.createElement('div');
    element.className = 'ai-guardian-status inline-block';
    element.innerHTML = `
      <span class="icon icon-shield"></span>
      AI Guardian ${this.realTimeEnabled ? '(Active)' : '(Inactive)'}
    `;
    element.style.color = this.realTimeEnabled ? '#4CAF50' : '#757575';
    element.onclick = () => this.toggleRealTime();
    element.title = 'Click to toggle AI Guardian real-time monitoring';

    this.statusBarTile = this.statusBar.addRightTile({
      item: element,
      priority: 100
    });
  }

  showSettings() {
    atom.workspace.open('atom://config/packages/ai-guardian-atom');
  }
}

module.exports = new AIGuardianAtom();

