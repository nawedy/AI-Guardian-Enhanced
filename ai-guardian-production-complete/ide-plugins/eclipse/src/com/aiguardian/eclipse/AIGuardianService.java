package com.aiguardian.eclipse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.eclipse.core.runtime.IStatus;
import org.eclipse.core.runtime.Status;
import org.eclipse.ui.statushandlers.StatusManager;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

/**
 * Service class for communicating with AI Guardian backend
 */
public class AIGuardianService {
    
    private static AIGuardianService instance;
    private CloseableHttpClient httpClient;
    private ExecutorService executorService;
    private Gson gson;
    private String apiBaseUrl;
    
    private AIGuardianService() {
        this.gson = new Gson();
        this.executorService = Executors.newFixedThreadPool(4);
    }
    
    public static synchronized AIGuardianService getInstance() {
        if (instance == null) {
            instance = new AIGuardianService();
        }
        return instance;
    }
    
    public void initialize() {
        this.httpClient = HttpClients.createDefault();
        this.apiBaseUrl = getPreferenceStore().getString("ai.guardian.api.url");
        if (apiBaseUrl.isEmpty()) {
            apiBaseUrl = "http://localhost:5004/api/ide";
        }
    }
    
    public void shutdown() {
        try {
            if (httpClient != null) {
                httpClient.close();
            }
            if (executorService != null) {
                executorService.shutdown();
            }
        } catch (IOException e) {
            logError("Error shutting down AI Guardian service", e);
        }
    }
    
    /**
     * Scan code asynchronously
     */
    public CompletableFuture<ScanResult> scanCode(String code, String language, String filename) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                JsonObject request = new JsonObject();
                request.addProperty("code", code);
                request.addProperty("language", language);
                request.addProperty("filename", filename);
                
                HttpPost post = new HttpPost(apiBaseUrl + "/scan");
                post.setHeader("Content-Type", "application/json");
                post.setEntity(new StringEntity(gson.toJson(request), StandardCharsets.UTF_8));
                
                try (CloseableHttpResponse response = httpClient.execute(post)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        return gson.fromJson(responseBody, ScanResult.class);
                    } else {
                        throw new RuntimeException("Scan failed: " + responseBody);
                    }
                }
            } catch (Exception e) {
                logError("Error scanning code", e);
                throw new RuntimeException(e);
            }
        }, executorService);
    }
    
    /**
     * Submit feedback for adaptive learning
     */
    public CompletableFuture<Void> submitFeedback(String vulnerabilityId, String feedback, String context) {
        return CompletableFuture.runAsync(() -> {
            try {
                JsonObject request = new JsonObject();
                request.addProperty("user_id", "eclipse_user");
                request.addProperty("vulnerability_id", vulnerabilityId);
                request.addProperty("feedback", feedback);
                request.addProperty("context", context);
                
                HttpPost post = new HttpPost(apiBaseUrl + "/feedback");
                post.setHeader("Content-Type", "application/json");
                post.setEntity(new StringEntity(gson.toJson(request), StandardCharsets.UTF_8));
                
                try (CloseableHttpResponse response = httpClient.execute(post)) {
                    if (response.getStatusLine().getStatusCode() != 200) {
                        String responseBody = EntityUtils.toString(response.getEntity());
                        throw new RuntimeException("Feedback submission failed: " + responseBody);
                    }
                }
            } catch (Exception e) {
                logError("Error submitting feedback", e);
                throw new RuntimeException(e);
            }
        }, executorService);
    }
    
    /**
     * Get service status
     */
    public CompletableFuture<ServiceStatus> getStatus() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpPost post = new HttpPost(apiBaseUrl + "/status");
                
                try (CloseableHttpResponse response = httpClient.execute(post)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        return gson.fromJson(responseBody, ServiceStatus.class);
                    } else {
                        throw new RuntimeException("Status check failed: " + responseBody);
                    }
                }
            } catch (Exception e) {
                logError("Error checking service status", e);
                throw new RuntimeException(e);
            }
        }, executorService);
    }
    
    private void logError(String message, Throwable throwable) {
        IStatus status = new Status(IStatus.ERROR, Activator.PLUGIN_ID, message, throwable);
        StatusManager.getManager().handle(status, StatusManager.LOG);
    }
    
    private org.eclipse.jface.preference.IPreferenceStore getPreferenceStore() {
        return Activator.getDefault().getPreferenceStore();
    }
    
    // Data classes for JSON serialization
    public static class ScanResult {
        public String scan_id;
        public String timestamp;
        public List<Vulnerability> vulnerabilities = new ArrayList<>();
        public ComplianceResult compliance;
        public double scan_time;
        
        public static class Vulnerability {
            public String id;
            public String name;
            public String severity;
            public double confidence;
            public int line;
            public int column;
            public String description;
            public String fix_suggestion;
        }
        
        public static class ComplianceResult {
            public List<ComplianceViolation> violations = new ArrayList<>();
            public double risk_score;
            
            public static class ComplianceViolation {
                public String id;
                public String regulation;
                public String name;
                public String severity;
                public String description;
                public int line;
                public String fix_suggestion;
            }
        }
    }
    
    public static class ServiceStatus {
        public String ai_guardian_status;
        public String timestamp;
        public String version;
    }
}

