import * as vscode from 'vscode';
import axios from 'axios';
import * as WebSocket from 'ws';
import * as path from 'path';

interface Vulnerability {
    type: string;
    severity: string;
    description: string;
    line: number;
    column?: number;
    cwe?: string;
    recommendation?: string;
    confidence: number;
}

interface ScanResult {
    vulnerabilities: Vulnerability[];
    scan_time: number;
    file_hash: string;
    language: string;
}

export class AIGuardianCodespaces {
    private context: vscode.ExtensionContext;
    private diagnosticCollection: vscode.DiagnosticCollection;
    private statusBarItem: vscode.StatusBarItem;
    private websocket: WebSocket | null = null;
    private isRealTimeEnabled: boolean = false;
    private vulnerabilityProvider: VulnerabilityTreeProvider;
    private decorationTypes: Map<string, vscode.TextEditorDecorationType>;
    private scanTimers: Map<string, NodeJS.Timeout> = new Map();

    constructor(context: vscode.ExtensionContext) {
        this.context = context;
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('ai-guardian');
        this.vulnerabilityProvider = new VulnerabilityTreeProvider();
        this.decorationTypes = new Map();
        
        this.setupDecorationTypes();
        this.setupStatusBar();
        this.registerCommands();
        this.setupEventListeners();
        this.initializeCodespaceMode();
    }

    private setupDecorationTypes() {
        this.decorationTypes.set('critical', vscode.window.createTextEditorDecorationType({
            backgroundColor: new vscode.ThemeColor('errorBackground'),
            border: '1px solid red',
            borderRadius: '3px',
            after: {
                contentText: ' 🔴 Critical',
                color: 'red',
                fontWeight: 'bold'
            }
        }));

        this.decorationTypes.set('high', vscode.window.createTextEditorDecorationType({
            backgroundColor: new vscode.ThemeColor('warningBackground'),
            border: '1px solid orange',
            borderRadius: '3px',
            after: {
                contentText: ' 🟠 High',
                color: 'orange',
                fontWeight: 'bold'
            }
        }));

        this.decorationTypes.set('medium', vscode.window.createTextEditorDecorationType({
            backgroundColor: new vscode.ThemeColor('infoBackground'),
            border: '1px solid yellow',
            borderRadius: '3px',
            after: {
                contentText: ' 🟡 Medium',
                color: 'yellow'
            }
        }));

        this.decorationTypes.set('low', vscode.window.createTextEditorDecorationType({
            backgroundColor: new vscode.ThemeColor('editorInfo.background'),
            border: '1px solid blue',
            borderRadius: '3px',
            after: {
                contentText: ' 🔵 Low',
                color: 'blue'
            }
        }));
    }

    private setupStatusBar() {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.statusBarItem.command = 'ai-guardian.toggleRealTime';
        this.updateStatusBar();
        this.statusBarItem.show();
    }

    private registerCommands() {
        const commands = [
            vscode.commands.registerCommand('ai-guardian.scanFile', () => this.scanCurrentFile()),
            vscode.commands.registerCommand('ai-guardian.scanWorkspace', () => this.scanWorkspace()),
            vscode.commands.registerCommand('ai-guardian.toggleRealTime', () => this.toggleRealTimeScanning()),
            vscode.commands.registerCommand('ai-guardian.showDashboard', () => this.showDashboard()),
            vscode.commands.registerCommand('ai-guardian.configureSettings', () => this.configureSettings()),
            vscode.commands.registerCommand('ai-guardian.clearResults', () => this.clearResults())
        ];

        commands.forEach(command => this.context.subscriptions.push(command));

        // Register tree view
        vscode.window.registerTreeDataProvider('ai-guardian-vulnerabilities', this.vulnerabilityProvider);
    }

    private setupEventListeners() {
        // File save listener
        vscode.workspace.onDidSaveTextDocument((document) => {
            const config = vscode.workspace.getConfiguration('ai-guardian');
            if (config.get('scanOnSave')) {
                this.scanDocument(document);
            }
        });

        // File change listener for auto-scan
        vscode.workspace.onDidChangeTextDocument((event) => {
            const config = vscode.workspace.getConfiguration('ai-guardian');
            if (config.get('autoScan') && this.isRealTimeEnabled) {
                this.debouncedScan(event.document);
            }
        });

        // Active editor change
        vscode.window.onDidChangeActiveTextEditor((editor) => {
            if (editor) {
                this.updateDecorations(editor);
            }
        });
    }

    private async initializeCodespaceMode() {
        const config = vscode.workspace.getConfiguration('ai-guardian');
        const codespaceMode = config.get('codespaceMode');

        if (codespaceMode) {
            // Check if we're running in a Codespace
            const isCodespace = process.env.CODESPACES === 'true';
            
            if (isCodespace) {
                vscode.window.showInformationMessage(
                    'AI Guardian: Codespace mode enabled. Optimizing for cloud environment...'
                );
                
                // Setup cloud-specific configurations
                await this.setupCloudMode();
            }
        }

        // Try to connect to local API first, fallback to cloud
        await this.connectToAPI();
    }

    private async setupCloudMode() {
        // Configure for Codespace environment
        const config = vscode.workspace.getConfiguration('ai-guardian');
        
        // Use port forwarding for local API if available
        const forwardedPort = process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN;
        if (forwardedPort) {
            const apiUrl = `https://${forwardedPort.replace('{{port}}', '5002')}`;
            await config.update('apiUrl', apiUrl, vscode.ConfigurationTarget.Workspace);
        }
    }

    private async connectToAPI() {
        const config = vscode.workspace.getConfiguration('ai-guardian');
        const localApiUrl = config.get<string>('apiUrl');
        const cloudApiUrl = config.get<string>('cloudApiEndpoint');

        try {
            // Try local API first
            await axios.get(`${localApiUrl}/api/health`, { timeout: 5000 });
            vscode.window.showInformationMessage('AI Guardian: Connected to local API');
        } catch (error) {
            try {
                // Fallback to cloud API
                await axios.get(`${cloudApiUrl}/api/health`, { timeout: 10000 });
                await config.update('apiUrl', cloudApiUrl, vscode.ConfigurationTarget.Workspace);
                vscode.window.showInformationMessage('AI Guardian: Connected to cloud API');
            } catch (cloudError) {
                vscode.window.showWarningMessage(
                    'AI Guardian: Unable to connect to API. Some features may be limited.'
                );
            }
        }
    }

    private debouncedScan(document: vscode.TextDocument) {
        const uri = document.uri.toString();
        
        // Clear existing timer
        if (this.scanTimers.has(uri)) {
            clearTimeout(this.scanTimers.get(uri)!);
        }

        // Set new timer
        const timer = setTimeout(() => {
            this.scanDocument(document);
            this.scanTimers.delete(uri);
        }, 2000);

        this.scanTimers.set(uri, timer);
    }

    private async scanCurrentFile() {
        const activeEditor = vscode.window.activeTextEditor;
        if (!activeEditor) {
            vscode.window.showWarningMessage('No active editor found');
            return;
        }

        await this.scanDocument(activeEditor.document);
    }

    private async scanDocument(document: vscode.TextDocument) {
        if (!this.isSupportedLanguage(document.languageId)) {
            return;
        }

        const config = vscode.workspace.getConfiguration('ai-guardian');
        const apiUrl = config.get<string>('apiUrl');

        try {
            vscode.window.withProgress({
                location: vscode.ProgressLocation.Notification,
                title: "AI Guardian: Scanning for vulnerabilities...",
                cancellable: false
            }, async () => {
                const response = await axios.post(`${apiUrl}/api/scan`, {
                    code: document.getText(),
                    language: this.getLanguageFromId(document.languageId),
                    filename: path.basename(document.fileName)
                });

                const result: ScanResult = response.data;
                await this.processScanResults(document, result);
            });

        } catch (error) {
            vscode.window.showErrorMessage(`AI Guardian scan failed: ${error}`);
        }
    }

    private async processScanResults(document: vscode.TextDocument, result: ScanResult) {
        const vulnerabilities = result.vulnerabilities;
        
        // Clear previous diagnostics
        this.diagnosticCollection.delete(document.uri);

        if (vulnerabilities.length === 0) {
            vscode.window.showInformationMessage(
                `AI Guardian: No vulnerabilities found in ${path.basename(document.fileName)} ✅`
            );
            return;
        }

        // Create diagnostics
        const diagnostics: vscode.Diagnostic[] = vulnerabilities.map(vuln => {
            const line = Math.max(0, vuln.line - 1);
            const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
            
            const diagnostic = new vscode.Diagnostic(
                range,
                `${vuln.type}: ${vuln.description}`,
                this.getSeverityLevel(vuln.severity)
            );

            diagnostic.source = 'AI Guardian';
            diagnostic.code = vuln.cwe || 'Unknown';
            
            return diagnostic;
        });

        this.diagnosticCollection.set(document.uri, diagnostics);

        // Update decorations
        const activeEditor = vscode.window.activeTextEditor;
        if (activeEditor && activeEditor.document.uri.toString() === document.uri.toString()) {
            this.updateDecorations(activeEditor, vulnerabilities);
        }

        // Update tree view
        this.vulnerabilityProvider.updateVulnerabilities(document.uri, vulnerabilities);
        vscode.commands.executeCommand('setContext', 'ai-guardian:hasVulnerabilities', true);

        // Show summary
        const counts = this.countVulnerabilitiesBySeverity(vulnerabilities);
        vscode.window.showWarningMessage(
            `AI Guardian: Found ${vulnerabilities.length} vulnerabilities - ` +
            `Critical: ${counts.critical}, High: ${counts.high}, Medium: ${counts.medium}, Low: ${counts.low}`
        );
    }

    private updateDecorations(editor: vscode.TextEditor, vulnerabilities?: Vulnerability[]) {
        if (!vulnerabilities) {
            // Get vulnerabilities from tree provider
            vulnerabilities = this.vulnerabilityProvider.getVulnerabilities(editor.document.uri);
        }

        if (!vulnerabilities) return;

        const config = vscode.workspace.getConfiguration('ai-guardian');
        if (!config.get('showInlineDecorations')) return;

        // Group vulnerabilities by severity
        const decorationsByType = new Map<string, vscode.DecorationOptions[]>();

        vulnerabilities.forEach(vuln => {
            const severity = vuln.severity.toLowerCase();
            if (!decorationsByType.has(severity)) {
                decorationsByType.set(severity, []);
            }

            const line = Math.max(0, vuln.line - 1);
            const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
            
            decorationsByType.get(severity)!.push({
                range,
                hoverMessage: new vscode.MarkdownString(
                    `**${vuln.type}** (${vuln.severity})\n\n` +
                    `${vuln.description}\n\n` +
                    `${vuln.recommendation ? `**Recommendation:** ${vuln.recommendation}\n\n` : ''}` +
                    `**CWE:** ${vuln.cwe || 'N/A'}`
                )
            });
        });

        // Apply decorations
        decorationsByType.forEach((decorations, severity) => {
            const decorationType = this.decorationTypes.get(severity);
            if (decorationType) {
                editor.setDecorations(decorationType, decorations);
            }
        });
    }

    private async scanWorkspace() {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showWarningMessage('No workspace folder found');
            return;
        }

        const config = vscode.workspace.getConfiguration('ai-guardian');
        const apiUrl = config.get<string>('apiUrl');

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: "AI Guardian: Scanning workspace...",
            cancellable: true
        }, async (progress, token) => {
            const files = await vscode.workspace.findFiles(
                '**/*.{py,js,ts,java,cs,go,rs,php,rb,swift,kt}',
                '**/node_modules/**'
            );

            let totalVulnerabilities = 0;
            let filesWithIssues = 0;
            const maxFiles = Math.min(files.length, 100); // Limit for performance

            for (let i = 0; i < maxFiles; i++) {
                if (token.isCancellationRequested) break;

                const file = files[i];
                progress.report({
                    increment: (100 / maxFiles),
                    message: `Scanning ${path.basename(file.fsPath)}...`
                });

                try {
                    const document = await vscode.workspace.openTextDocument(file);
                    const response = await axios.post(`${apiUrl}/api/scan`, {
                        code: document.getText(),
                        language: this.getLanguageFromId(document.languageId),
                        filename: path.basename(document.fileName)
                    });

                    const result: ScanResult = response.data;
                    if (result.vulnerabilities.length > 0) {
                        totalVulnerabilities += result.vulnerabilities.length;
                        filesWithIssues++;
                        
                        // Store results for later viewing
                        this.vulnerabilityProvider.updateVulnerabilities(file, result.vulnerabilities);
                    }
                } catch (error) {
                    console.error(`Error scanning ${file.fsPath}:`, error);
                }
            }

            vscode.window.showInformationMessage(
                `AI Guardian: Workspace scan complete - ${totalVulnerabilities} vulnerabilities found in ${filesWithIssues} files`
            );
        });
    }

    private toggleRealTimeScanning() {
        this.isRealTimeEnabled = !this.isRealTimeEnabled;
        
        if (this.isRealTimeEnabled) {
            this.startWebSocketConnection();
            vscode.window.showInformationMessage('AI Guardian: Real-time scanning enabled');
        } else {
            this.stopWebSocketConnection();
            vscode.window.showInformationMessage('AI Guardian: Real-time scanning disabled');
        }

        this.updateStatusBar();
    }

    private startWebSocketConnection() {
        const config = vscode.workspace.getConfiguration('ai-guardian');
        const wsUrl = config.get<string>('websocketUrl');

        try {
            this.websocket = new WebSocket(wsUrl!);
            
            this.websocket.on('open', () => {
                console.log('AI Guardian WebSocket connected');
            });

            this.websocket.on('message', (data) => {
                const message = JSON.parse(data.toString());
                this.handleWebSocketMessage(message);
            });

            this.websocket.on('error', (error) => {
                console.error('WebSocket error:', error);
            });

        } catch (error) {
            vscode.window.showErrorMessage(`Failed to connect to AI Guardian WebSocket: ${error}`);
        }
    }

    private stopWebSocketConnection() {
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
    }

    private handleWebSocketMessage(message: any) {
        if (message.type === 'vulnerability_detected') {
            vscode.window.showWarningMessage(
                `AI Guardian: New vulnerability detected in ${message.file}`,
                'View Details'
            ).then(selection => {
                if (selection === 'View Details') {
                    vscode.workspace.openTextDocument(message.file).then(doc => {
                        vscode.window.showTextDocument(doc);
                    });
                }
            });
        }
    }

    private showDashboard() {
        // Create webview for dashboard
        const panel = vscode.window.createWebviewPanel(
            'ai-guardian-dashboard',
            'AI Guardian Dashboard',
            vscode.ViewColumn.One,
            {
                enableScripts: true,
                retainContextWhenHidden: true
            }
        );

        panel.webview.html = this.getDashboardHtml();
    }

    private getDashboardHtml(): string {
        return `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>AI Guardian Dashboard</title>
            <style>
                body { font-family: var(--vscode-font-family); padding: 20px; }
                .header { border-bottom: 1px solid var(--vscode-panel-border); padding-bottom: 10px; }
                .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
                .stat-card { padding: 15px; border: 1px solid var(--vscode-panel-border); border-radius: 5px; }
                .critical { border-left: 4px solid #ff4444; }
                .high { border-left: 4px solid #ff8800; }
                .medium { border-left: 4px solid #ffaa00; }
                .low { border-left: 4px solid #0088ff; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ AI Guardian Security Dashboard</h1>
                <p>Real-time security monitoring for GitHub Codespaces</p>
            </div>
            
            <div class="stats">
                <div class="stat-card critical">
                    <h3>Critical Vulnerabilities</h3>
                    <div id="critical-count">Loading...</div>
                </div>
                <div class="stat-card high">
                    <h3>High Severity</h3>
                    <div id="high-count">Loading...</div>
                </div>
                <div class="stat-card medium">
                    <h3>Medium Severity</h3>
                    <div id="medium-count">Loading...</div>
                </div>
                <div class="stat-card low">
                    <h3>Low Severity</h3>
                    <div id="low-count">Loading...</div>
                </div>
            </div>

            <div class="section">
                <h2>Recent Scans</h2>
                <div id="recent-scans">No recent scans available</div>
            </div>

            <script>
                // Dashboard functionality would be implemented here
                // This is a basic template for the Codespaces environment
            </script>
        </body>
        </html>
        `;
    }

    private configureSettings() {
        vscode.commands.executeCommand('workbench.action.openSettings', 'ai-guardian');
    }

    private clearResults() {
        this.diagnosticCollection.clear();
        this.vulnerabilityProvider.clear();
        vscode.commands.executeCommand('setContext', 'ai-guardian:hasVulnerabilities', false);
        
        // Clear decorations from all editors
        vscode.window.visibleTextEditors.forEach(editor => {
            this.decorationTypes.forEach(decorationType => {
                editor.setDecorations(decorationType, []);
            });
        });

        vscode.window.showInformationMessage('AI Guardian: All results cleared');
    }

    private updateStatusBar() {
        this.statusBarItem.text = `🛡️ AI Guardian ${this.isRealTimeEnabled ? '(Active)' : '(Inactive)'}`;
        this.statusBarItem.tooltip = 'Click to toggle AI Guardian real-time scanning';
        this.statusBarItem.backgroundColor = this.isRealTimeEnabled ? 
            new vscode.ThemeColor('statusBarItem.prominentBackground') : undefined;
    }

    private isSupportedLanguage(languageId: string): boolean {
        const supportedLanguages = [
            'python', 'javascript', 'typescript', 'java', 'csharp', 
            'go', 'rust', 'php', 'ruby', 'swift', 'kotlin'
        ];
        return supportedLanguages.includes(languageId);
    }

    private getLanguageFromId(languageId: string): string {
        const languageMap: { [key: string]: string } = {
            'python': 'python',
            'javascript': 'javascript',
            'typescript': 'typescript',
            'java': 'java',
            'csharp': 'csharp',
            'go': 'go',
            'rust': 'rust',
            'php': 'php',
            'ruby': 'ruby',
            'swift': 'swift',
            'kotlin': 'kotlin'
        };
        return languageMap[languageId] || 'unknown';
    }

    private getSeverityLevel(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toLowerCase()) {
            case 'critical':
            case 'high':
                return vscode.DiagnosticSeverity.Error;
            case 'medium':
                return vscode.DiagnosticSeverity.Warning;
            case 'low':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    private countVulnerabilitiesBySeverity(vulnerabilities: Vulnerability[]) {
        return vulnerabilities.reduce((counts, vuln) => {
            const severity = vuln.severity.toLowerCase();
            counts[severity] = (counts[severity] || 0) + 1;
            return counts;
        }, {} as { [key: string]: number });
    }

    dispose() {
        this.diagnosticCollection.dispose();
        this.statusBarItem.dispose();
        this.stopWebSocketConnection();
        this.decorationTypes.forEach(decorationType => decorationType.dispose());
        this.scanTimers.forEach(timer => clearTimeout(timer));
    }
}

class VulnerabilityTreeProvider implements vscode.TreeDataProvider<VulnerabilityItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<VulnerabilityItem | undefined | null | void> = new vscode.EventEmitter<VulnerabilityItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<VulnerabilityItem | undefined | null | void> = this._onDidChangeTreeData.event;

    private vulnerabilities: Map<string, Vulnerability[]> = new Map();

    updateVulnerabilities(uri: vscode.Uri, vulnerabilities: Vulnerability[]) {
        this.vulnerabilities.set(uri.toString(), vulnerabilities);
        this._onDidChangeTreeData.fire();
    }

    getVulnerabilities(uri: vscode.Uri): Vulnerability[] | undefined {
        return this.vulnerabilities.get(uri.toString());
    }

    clear() {
        this.vulnerabilities.clear();
        this._onDidChangeTreeData.fire();
    }

    getTreeItem(element: VulnerabilityItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: VulnerabilityItem): Thenable<VulnerabilityItem[]> {
        if (!element) {
            // Return file nodes
            const fileItems: VulnerabilityItem[] = [];
            this.vulnerabilities.forEach((vulns, uri) => {
                const parsedUri = vscode.Uri.parse(uri);
                fileItems.push(new VulnerabilityItem(
                    path.basename(parsedUri.fsPath),
                    vscode.TreeItemCollapsibleState.Expanded,
                    'file',
                    parsedUri
                ));
            });
            return Promise.resolve(fileItems);
        } else if (element.type === 'file') {
            // Return vulnerability nodes for this file
            const vulns = this.vulnerabilities.get(element.uri!.toString()) || [];
            return Promise.resolve(vulns.map(vuln => 
                new VulnerabilityItem(
                    `${vuln.type} (Line ${vuln.line})`,
                    vscode.TreeItemCollapsibleState.None,
                    'vulnerability',
                    element.uri,
                    vuln
                )
            ));
        }
        return Promise.resolve([]);
    }
}

class VulnerabilityItem extends vscode.TreeItem {
    constructor(
        public readonly label: string,
        public readonly collapsibleState: vscode.TreeItemCollapsibleState,
        public readonly type: 'file' | 'vulnerability',
        public readonly uri?: vscode.Uri,
        public readonly vulnerability?: Vulnerability
    ) {
        super(label, collapsibleState);
        
        if (type === 'vulnerability' && vulnerability) {
            this.tooltip = vulnerability.description;
            this.description = vulnerability.severity;
            this.iconPath = new vscode.ThemeIcon(
                vulnerability.severity === 'critical' ? 'error' :
                vulnerability.severity === 'high' ? 'warning' :
                vulnerability.severity === 'medium' ? 'info' : 'circle-outline'
            );
            
            this.command = {
                command: 'vscode.open',
                title: 'Open File',
                arguments: [uri, { selection: new vscode.Range(vulnerability.line - 1, 0, vulnerability.line - 1, 0) }]
            };
        } else if (type === 'file') {
            this.iconPath = vscode.ThemeIcon.File;
            this.contextValue = 'file';
        }
    }
}

export function activate(context: vscode.ExtensionContext) {
    const aiGuardian = new AIGuardianCodespaces(context);
    context.subscriptions.push(aiGuardian);
    
    vscode.window.showInformationMessage(
        'AI Guardian for GitHub Codespaces is now active! 🛡️'
    );
}

export function deactivate() {
    // Cleanup is handled by the dispose methods
}

