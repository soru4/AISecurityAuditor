package com.auditor;

import java.util.List;

import dev.langchain4j.model.chat.ChatLanguageModel;

import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import java.time.Duration;
/**
 * 
 * AIReportService
 * AI report service sends all of our scan findings to an external AI model. 
 */
public class AIReportService {

    private final ChatLanguageModel model;
    /**
     * Sets up the AI model and provider based on user selection. 
     * @param provider
     * @param modelName
     * @param apiKey
     * @param ollamaUrl
     */
    public AIReportService(String provider, String modelName, String apiKey, String ollamaUrl) {
        if (ollamaUrl == null || ollamaUrl.isEmpty()) {
            ollamaUrl = "http://localhost:11434";
        }
        switch (provider.toLowerCase()) {
            case "openai": {
                validateApiKey(apiKey, "OpenAI");
                String selectedModel = (modelName != null) ? modelName : "gpt-4o-mini";
                model = OpenAiChatModel.builder()
                        .apiKey(apiKey)
                        .modelName(selectedModel)
                        .temperature(0.0)
                        .maxTokens(8192*4)
                        .timeout(Duration.ofSeconds(240))
                        .build();
                break;
            }
            case "gemini": {
                validateApiKey(apiKey, "Gemini");
                String selectedModel = (modelName != null) ? modelName : "gemini-3.5-flash";
                model = OpenAiChatModel.builder()
                        .baseUrl("https://generativelanguage.googleapis.com/v1beta/openai/")
                        .apiKey(apiKey)
                        .modelName(selectedModel)
                        .temperature(0.0)
                        .maxTokens(8192*4)
                        .timeout(Duration.ofSeconds(120))
                        .build();
                break;
            }
            case "ollama": {
                String selectedModel = (modelName != null) ? modelName : "llama3";
                System.out.println(
                        "[AI] Connecting to local Ollama instance at " + ollamaUrl + " using " + selectedModel + "...");
                model = OllamaChatModel.builder()
                        .baseUrl(ollamaUrl)
                        .modelName(selectedModel)
                        .temperature(0.0)
                        .numPredict(8192*4)
                        .timeout(Duration.ofSeconds(240))
                        .build();
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    }

    /** 
     * Checks the API key and makes sure its valid. Does not check if it is a working API key, just makes sure it exists. 
     * @param apiKey
     * @param providerName
     */
    private void validateApiKey(String apiKey, String providerName) {
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalArgumentException("API key is required for " + providerName + " provider.");
        }
    }

    /** 
     * It creates the prompt and sends the scan findings to the AI model and gets  response.
     * @param scanResultsSummary
     * @return String
     */
    public String generateReport(List<ScanResult> scanResultsSummary) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("You are a Senior DevSecOps Engineer. Analyze these raw network scan findings:\n\n");
        prompt.append(
                "Return ONLY a valid JSON formatted string with NO markdown formatting, and NO extra prose. Do not include line breaks within cells of the JSON.\n\n");
        prompt.append("JSON Schema: {\"Domain\": \"string\", \"Reachable\": \"boolean\", \"SSL_Expiry_Days\": \"integer\", \"Missing_Headers\": \"array\", \"Risk_Level\": \"string\", \"Summary\": \"string\", \"Remediation\": \"string\"}\n");
        
        prompt.append("Scan Findings:\n");
        for (ScanResult res : scanResultsSummary) {
            if (!res.isReachable()) {
                if (SecurityAudit.debugMode) {
                    System.out.println("[AI] Domain " + res.getUrl() + " is unreachable. ");
                }
            } else {
                prompt.append(String.format("- Domain: %s | SSL Expiry: %d days | Missing Headers: %s | Recursive Scan: %s\n",
                        res.getUrl(),
                        res.getDayTillSSLExpiry(),
                        res.getMissingHeaders().keySet(),
                        res.wasScannedInRecursiveMode()));
            }
        }

        prompt.append("\nRules:\n");
        prompt.append("- Enclose Summary and Remediation fields in double quotes.\n");
        prompt.append("- Risk_Level must be one of: LOW, MEDIUM, HIGH, or UNKNOWN.\n");
        prompt.append("- If the domain is unreachable, set Risk_Level to HIGH and provide a summary and remediation.\n");
        prompt.append("Be concise and provide actionable recommendations for each domain. Do not include any additional text or explanations. Be as simple as you can be, use abreviations when possible. DO NOT MAKE UP ANY NEW RULES OR INFORMATION. ALWAYS FOLLOW THE INSTRUCTIONS.\n");
        if (SecurityAudit.debugMode) {
            System.out.println("\n\nPrompt for AI model:\n" + prompt.toString() + "\n\n");
        }
        
        System.out.println("[AI] Sending scan findings to model...");
        try {
            return model.generate(prompt.toString());
        } catch (Exception e) {
            System.err.println("[ API Error Detail]: " + e.getMessage());
            e.printStackTrace();
            return "Error generating report from.";
        }
    }
}
