package com.aiguardian.netbeans.services;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.Preferences;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.openide.util.NbPreferences;

/**
 * Main service class for AI Guardian NetBeans integration
 */
public class AIGuardianService {
    
    private static final Logger logger = Logger.getLogger(AIGuardianService.class.getName());
    private static AIGuardianService instance;
    
    private CloseableHttpClient httpClient;
    private ExecutorService executorService;
    private Gson gson;
    private String apiBaseUrl;
    
    private AIGuardianService() {
        this.gson = new Gson();
        this.executorService = Executors.newFixedThreadPool(4);
        initialize();
    }
    
    public static synchronized AIGuardianService getInstance() {
        if (instance == null) {
            instance = new AIGuardianService();
        }
        return instance;
    }
    
    private void initialize() {
        this.httpClient = HttpClients.createDefault();
        
        Preferences prefs = NbPreferences.forModule(AIGuardianService.class);
        this.apiBaseUrl = prefs.get("ai.guardian.api.url", "http://localhost:5004/api/ide");
        
        logger.info("AI Guardian Service initialized with API URL: " + apiBaseUrl);
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
            logger.log(Level.SEVERE, "Error shutting down AI Guardian service", e);
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
                logger.log(Level.SEVERE, "Error scanning code", e);
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
                request.addProperty("user_id", "netbeans_user");
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
                logger.log(Level.SEVERE, "Error submitting feedback", e);
                throw new RuntimeException(e);
            }
        }, executorService);
    }
    
    /**
     * Get service configuration
     */
    public CompletableFuture<ConfigResult> getConfiguration() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpPost post = new HttpPost(apiBaseUrl + "/config");
                
                try (CloseableHttpResponse response = httpClient.execute(post)) {
                    String responseBody = EntityUtils.toString(response.getEntity());
                    
                    if (response.getStatusLine().getStatusCode() == 200) {
                        return gson.fromJson(responseBody, ConfigResult.class);
                    } else {
                        throw new RuntimeException("Config retrieval failed: " + responseBody);
                    }
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error getting configuration", e);
                throw new RuntimeException(e);
            }
        }, executorService);
    }
    
    /**
     * Update API base URL
     */
    public void updateApiUrl(String newUrl) {
        this.apiBaseUrl = newUrl;
        Preferences prefs = NbPreferences.forModule(AIGuardianService.class);
        prefs.put("ai.guardian.api.url", newUrl);
        logger.info("Updated API URL to: " + newUrl);
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
    
    public static class ConfigResult {
        public String version;
        public List<String> supported_languages;
        public List<String> supported_regulations;
        public boolean adaptive_learning_enabled;
        public boolean real_time_scanning_enabled;
    }
}

