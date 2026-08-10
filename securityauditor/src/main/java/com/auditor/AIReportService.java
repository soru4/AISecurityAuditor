package com.auditor;

import java.util.List;

import dev.langchain4j.model.chat.ChatLanguageModel;
import dev.langchain4j.model.googleai.GoogleAiGeminiChatModel;
import dev.langchain4j.model.ollama.OllamaChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;

public class AIReportService {

    private final ChatLanguageModel model;

    public AIReportService(String provider, String modelName, String apiKey, String ollamaUrl) {
        if (ollamaUrl == null || ollamaUrl.isEmpty()) {
            ollamaUrl = "http://localhost:11434";
        }
        switch (provider.toLowerCase()) {
            case "opennai": {
                validateApiKey(apiKey, "OpenAI");
                String selectedModel = (modelName != null) ? modelName : "gpt-4o-mini";
                model = OpenAiChatModel.builder()
                        .apiKey(apiKey)
                        .modelName(selectedModel)
                        .temperature(0.2)
                        .build();
                break;
            }
            case "gemini": {
                validateApiKey(apiKey, "Gemini");
                String selectedModel = (modelName != null) ? modelName : "gemini-2.5-flash";
                model = GoogleAiGeminiChatModel.builder()
                        .apiKey(apiKey)
                        .modelName(selectedModel)
                        .temperature(0.2)
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
                        .temperature(0.2)
                        .build();
                break;
            }
            default:
                throw new IllegalArgumentException("Unsupported provider: " + provider);
        }
    }

    private void validateApiKey(String apiKey, String providerName) {
        if (apiKey == null || apiKey.isEmpty()) {
            throw new IllegalArgumentException("API key is required for " + providerName + " provider.");
        }
    }

    public String generateReport(List<ScanResult> scanResultsSummary) {
        StringBuilder prompt = new StringBuilder();
        prompt.append("You are a Senior DevSecOps Engineer. Analyze these raw network scan findings:\n\n");
        prompt.append("Return ONLY a valid CSV formatted string with NO markdown formatting, NO code blocks, and NO extra prose.\n\n");
        prompt.append("CSV Header format:\n");
        prompt.append("Domain,Reachable,SSL_Expiry_Days,Missing_Headers,Risk_Level,Summary,Remediation\n\n");

        prompt.append("Scan Findings:\n");
        for (ScanResult res : scanResultsSummary) {
            if (!res.isReachable()) {
                prompt.append(String.format("- Domain: %s | Status: UNREACHABLE\n", res.getUrl()));
            } else {
                prompt.append(String.format("- Domain: %s | SSL Expiry: %d days | Missing Headers: %s\n",
                        res.getUrl(),
                        res.getDayTillSSLExpiry(),
                        res.getMissingHeaders().keySet()));
            }
        }

        prompt.append("\nRules:\n");
        prompt.append("- Enclose Summary and Remediation fields in double quotes.\n");
        prompt.append("- Risk_Level must be one of: LOW, MEDIUM, HIGH, or UNKNOWN.\n");

        System.out.println("[AI] Sending scan findings to model...");
        try {
            return model.generate(prompt.toString());
        } catch (Exception e) {
            System.err.println("[Gemini API Error Detail]: " + e.getMessage());
            e.printStackTrace();
            return "Error generating report from Gemini.";
        }
    }
}
