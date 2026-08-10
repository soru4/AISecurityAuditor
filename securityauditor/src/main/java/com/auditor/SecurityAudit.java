package com.auditor;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;   

import com.threadpool.ThreadPool;
import com.threadpool.ThreadSafeTaskQueue;
import com.threadpool.Task;


@Command(name = "Security Auditor", mixinStandardHelpOptions = true, version = "1.0",
        description = "Multi-threaded SSL/TLS & HTTP Header Security Auditor with AI Analysis")
public class SecurityAudit implements Callable<Integer>{


    @Option(names = {"-t", "-threads"}, description = "Number of threads to use for auditing (default: $d{numThreads})")
    private int numThreads = 5;

    @Option(names = {"-f", "-file"}, description = "The path to the file with a list of URLs to look over", required = true)
    private File urlFile;

    @Option(names = {"--ai"}, description = "Enable AI analysis for security recommendations")
    private boolean enableAIAnalysis = false;

    

    @Option(names = {"--p", "--provider"}, description = "Provider for AI analysis (required if --ai is enabled) you can choose from 'opennai' or 'gemini' or 'ollama'")
    private String aiProvider;

    @Option(
    names = {"--model-name"},
    description = "Model name to use (e.g., 'llama3', 'gpt-4o-mini', 'gemini-2.5-flash')"
    )
    private String modelName;

    @Option(
    names = {"--ollama-url"},
    description = "Ollama endpoint URL (default: ${DEFAULT-VALUE})")
    private String ollamaUrl;

    @Option(names = {"--ai-api-key", "--api-key"}, description = "API key for AI analysis (required if --ai is enabled) not needed for ollama provider")
    private String aiApiKey;

    @Option(
    names = {"-o", "--output"},
    description = "Output CSV file path (e.g., report.csv) this is only used if --ai is enabled and will save the AI report to the specified file"
)
    private File outputFile;

    @Override
    public Integer call() throws Exception {
        System.out.println("=== Starting Security Audit ===");
        System.out.println("\n\nTarget URL file: " + urlFile.getAbsolutePath());
        System.out.println("Number of threads: " + numThreads);
        System.out.println("AI Analysis enabled: " + enableAIAnalysis);
        
        if(!urlFile.exists()) {
            System.err.println("Oh no!: The specified URL file does not exist.");
            return 1;
        }
        System.out.println("\n\nOpening the URLs File and preparing to scan...");
        List<String> urls = Files.readAllLines(urlFile.toPath());
        System.out.println("Loaded " + urls.size()  + " domains from file.");

        

        System.out.println("\n\nTurning on the Thread Pool with " + numThreads + " threads...");
        List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());

        ThreadSafeTaskQueue queue = new ThreadSafeTaskQueue();
        ThreadPool pool = new ThreadPool(numThreads, queue);
        System.out.println("Thread Pool initialized successfully.");

        for(int i = 0; i < urls.size(); i++){
            String url = urls.get(i).trim();
            if(url.isEmpty()) continue;

            if(url.isEmpty())
                continue;
            Runnable work = () -> {
                System.out.println("\nAccessing URL: " + url);
                ScanResult result = DomainScanner.scanDomain(url);
                results.add(result);
                System.out.println(result.toString() );
            };
            Task task = new Task( url + "- Task - " + i, "SSL_AUDIT", work);

            pool.executeTask(task);
        }
        while(!queue.getTaskQueue().isEmpty())
            Thread.sleep(1000);
        Thread.sleep(2000); 

        System.out.println("\n\nAll tasks completed. Shutting down the Thread Pool...");

        pool.shutdown();
        System.out.println("\n\n=== Scan Complete! Total Scanned: " + results.size() + " ===");


        if(enableAIAnalysis){
            System.out.println("\n\n=== Starting AI Analysis ===");
            AIReportService aiService = new AIReportService(aiProvider, modelName, aiApiKey, ollamaUrl);
            System.out.println("\n\n=== Initializing AI Service ===");
            String aiReport = aiService.generateReport(results);
            System.out.println("\n\n=== AI Analysis Complete! ===");
           

            if(outputFile != null){
                Files.writeString(outputFile.toPath(), aiReport);
                System.out.println("\n\nAI Report saved to: " + outputFile.getAbsolutePath());
            }
        }
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new SecurityAudit()).execute(args);
        System.exit(exitCode);
    }


}
