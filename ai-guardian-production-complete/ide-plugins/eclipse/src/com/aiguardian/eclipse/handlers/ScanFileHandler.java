package com.aiguardian.eclipse.handlers;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;

import org.eclipse.core.commands.AbstractHandler;
import org.eclipse.core.commands.ExecutionEvent;
import org.eclipse.core.commands.ExecutionException;
import org.eclipse.core.resources.IFile;
import org.eclipse.core.resources.IMarker;
import org.eclipse.core.resources.IResource;
import org.eclipse.core.runtime.CoreException;
import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.core.runtime.jobs.Job;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.jface.viewers.ISelection;
import org.eclipse.jface.viewers.IStructuredSelection;
import org.eclipse.ui.handlers.HandlerUtil;

import com.aiguardian.eclipse.AIGuardianService;
import com.aiguardian.eclipse.Activator;
import com.aiguardian.eclipse.AIGuardianService.ScanResult;

/**
 * Handler for scanning individual files
 */
public class ScanFileHandler extends AbstractHandler {

    @Override
    public Object execute(ExecutionEvent event) throws ExecutionException {
        ISelection selection = HandlerUtil.getActiveWorkbenchWindow(event).getActivePage().getSelection();
        
        if (selection instanceof IStructuredSelection) {
            IStructuredSelection structuredSelection = (IStructuredSelection) selection;
            Object firstElement = structuredSelection.getFirstElement();
            
            if (firstElement instanceof IFile) {
                IFile file = (IFile) firstElement;
                scanFile(file);
            }
        }
        
        return null;
    }
    
    private void scanFile(IFile file) {
        Job scanJob = new Job("AI Guardian - Scanning " + file.getName()) {
            @Override
            protected IStatus run(IProgressMonitor monitor) {
                monitor.beginTask("Scanning file for vulnerabilities...", IProgressMonitor.UNKNOWN);
                
                try {
                    // Read file content
                    String content = readFileContent(file);
                    String language = detectLanguage(file);
                    
                    // Clear existing markers
                    clearMarkers(file);
                    
                    // Perform scan
                    CompletableFuture<ScanResult> scanFuture = AIGuardianService.getInstance()
                            .scanCode(content, language, file.getName());
                    
                    ScanResult result = scanFuture.get();
                    
                    // Create markers for vulnerabilities
                    createVulnerabilityMarkers(file, result);
                    
                    // Show completion message
                    showScanCompletionMessage(file, result);
                    
                } catch (Exception e) {
                    return new Status(IStatus.ERROR, Activator.PLUGIN_ID, 
                            "Error scanning file: " + e.getMessage(), e);
                } finally {
                    monitor.done();
                }
                
                return Status.OK_STATUS;
            }
        };
        
        scanJob.setUser(true);
        scanJob.schedule();
    }
    
    private String readFileContent(IFile file) throws IOException, CoreException {
        StringBuilder content = new StringBuilder();
        try (InputStream inputStream = file.getContents();
             BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
    
    private String detectLanguage(IFile file) {
        String extension = file.getFileExtension();
        if (extension == null) {
            return "text";
        }
        
        switch (extension.toLowerCase()) {
            case "java":
                return "java";
            case "py":
                return "python";
            case "js":
            case "ts":
                return "javascript";
            case "cs":
                return "csharp";
            case "go":
                return "go";
            case "rs":
                return "rust";
            case "php":
                return "php";
            case "rb":
                return "ruby";
            case "swift":
                return "swift";
            case "kt":
            case "kts":
                return "kotlin";
            default:
                return "text";
        }
    }
    
    private void clearMarkers(IFile file) throws CoreException {
        file.deleteMarkers("com.aiguardian.eclipse.markers.vulnerability", false, IResource.DEPTH_ZERO);
    }
    
    private void createVulnerabilityMarkers(IFile file, ScanResult result) throws CoreException {
        for (ScanResult.Vulnerability vuln : result.vulnerabilities) {
            IMarker marker = file.createMarker("com.aiguardian.eclipse.markers.vulnerability");
            
            marker.setAttribute(IMarker.MESSAGE, vuln.name + ": " + vuln.description);
            marker.setAttribute(IMarker.LINE_NUMBER, vuln.line);
            marker.setAttribute("vulnerabilityType", vuln.id);
            marker.setAttribute("confidence", vuln.confidence);
            marker.setAttribute("fixSuggestion", vuln.fix_suggestion);
            
            // Set severity based on vulnerability severity
            int severity;
            switch (vuln.severity.toUpperCase()) {
                case "CRITICAL":
                    severity = IMarker.SEVERITY_ERROR;
                    break;
                case "HIGH":
                    severity = IMarker.SEVERITY_ERROR;
                    break;
                case "MEDIUM":
                    severity = IMarker.SEVERITY_WARNING;
                    break;
                case "LOW":
                    severity = IMarker.SEVERITY_INFO;
                    break;
                default:
                    severity = IMarker.SEVERITY_WARNING;
            }
            marker.setAttribute(IMarker.SEVERITY, severity);
        }
        
        // Create markers for compliance violations
        if (result.compliance != null) {
            for (ScanResult.ComplianceResult.ComplianceViolation violation : result.compliance.violations) {
                IMarker marker = file.createMarker("com.aiguardian.eclipse.markers.vulnerability");
                
                marker.setAttribute(IMarker.MESSAGE, 
                        "[" + violation.regulation + "] " + violation.name + ": " + violation.description);
                marker.setAttribute(IMarker.LINE_NUMBER, violation.line);
                marker.setAttribute("vulnerabilityType", violation.id);
                marker.setAttribute("confidence", 1.0);
                marker.setAttribute("fixSuggestion", violation.fix_suggestion);
                marker.setAttribute(IMarker.SEVERITY, IMarker.SEVERITY_WARNING);
            }
        }
    }
    
    private void showScanCompletionMessage(IFile file, ScanResult result) {
        int vulnerabilityCount = result.vulnerabilities.size();
        int complianceViolations = result.compliance != null ? result.compliance.violations.size() : 0;
        
        String message = String.format(
                "Scan completed for %s\n\nFound:\n- %d vulnerabilities\n- %d compliance violations\n\nScan time: %.2f seconds",
                file.getName(), vulnerabilityCount, complianceViolations, result.scan_time);
        
        MessageDialog.openInformation(null, "AI Guardian - Scan Complete", message);
    }
}

