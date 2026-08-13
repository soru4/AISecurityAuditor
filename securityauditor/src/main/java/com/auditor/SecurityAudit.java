package com.auditor;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;

import com.threadpool.ThreadPool;
import com.threadpool.ThreadSafeTaskQueue;
import com.threadpool.Task;

@Command(name = "Security Auditor", mixinStandardHelpOptions = true, version = "1.0", description = "Multi-threaded SSL/TLS & HTTP Header Security Auditor with AI Analysis")
public class SecurityAudit implements Callable<Integer> {

    @Option(names = { "-t",
            "-threads" }, description = "Number of threads to use for auditing (default: $d{numThreads})")
    private static int numThreads = 5;

    @Option(names = { "-f",
            "-file" }, description = "The path to the file with a list of URLs to look over")
    private File urlFile;

    @Option(names = { "-d",
            "-domain" }, description = "The domain to look over")
    private String domain;

    @Option(names = { "-r",
            "-recursive" }, description = "The flag to enable recursive scanning of embedded links (default: $d{recursive})")
    private boolean recursive = false;

    @Option(names = { "--rs",
            "--recursive-steps" }, description = "The number of recursive steps to take when scanning embedded links (default: $d{recursiveSteps})")
    private int recursiveSteps = 2;

    @Option(names = { "--ai" }, description = "Enable AI analysis for security recommendations")
    private boolean enableAIAnalysis = false;

    @Option(names = { "--p",
            "--provider" }, description = "Provider for AI analysis (required if --ai is enabled) you can choose from 'opennai' or 'gemini' or 'ollama'")
    private String aiProvider;

    @Option(names = {
            "--model-name" }, description = "Model name to use (e.g., 'llama3', 'gpt-4o-mini', 'gemini-2.5-flash')")
    private String modelName;

    @Option(names = { "--ollama-url" }, description = "Ollama endpoint URL (default: ${DEFAULT-VALUE})")
    private String ollamaUrl;

    @Option(names = { "--ai-api-key",
            "--api-key" }, description = "API key for AI analysis (required if --ai is enabled) not needed for ollama provider")
    private String aiApiKey;

    @Option(names = { "-o",
            "--output" }, description = "Output CSV file path (e.g., report.json) this is only used if --ai is enabled and will save the AI report to the specified file")
    private File outputFile;

    @Option(names = { "-debug", "--debug" }, description = "Enable debug mode for detailed logging")
    public static boolean debugMode = false;

    public static List<ScanResult> results = Collections.synchronizedList(new ArrayList<>());
    public static Set<String> scannedDomains = Collections.synchronizedSet(new HashSet<>());
    public static ThreadSafeTaskQueue queue = new ThreadSafeTaskQueue();
    public static ThreadPool pool = new ThreadPool(numThreads, queue);
    public static List<Task> tasks = Collections.synchronizedList(new ArrayList<>());

    /** 
     * Runs the CLI output. 
     * @return Integer
     * @throws Exception
     */
    @Override
    public Integer call() throws Exception {
        System.out.println("=== Starting Security Audit ===");

        System.out.println("AI Analysis enabled: " + enableAIAnalysis);
        if (urlFile == null || !urlFile.exists()) {
            System.out.println("NO URL FILE FOUND! ");
            if (domain != null && !domain.isEmpty()) {
                if (debugMode) {
                    System.out.println("Debug Mode: Scanning single domain: " + domain + " with recursive: " + recursive
                            + " and recursive steps: " + recursiveSteps + "\n\n");
                }
                Runnable w = () ->{
                ScanResult result = DomainScanner.scanDomain(domain, recursive, 0, recursiveSteps);
                if (result != null) {
                    results.add(result);
                    System.out.println(result.toString() + "\n\n");
                }
            };
                Task t = new Task("Domain1", "SSL SCAN", w);
                pool.executeTask(t);
                Thread.sleep(7000);
                if (enableAIAnalysis) {

                    System.out.println("\n\n=== Starting AI Analysis ===");
                    AIReportService aiService = new AIReportService(aiProvider, modelName, aiApiKey, ollamaUrl);
                    System.out.println("\n\n=== Initializing AI Service ===");
                    String aiReport = aiService.generateReport(results);
                    if (debugMode || outputFile == null) {
                        System.out.println("\n\n=== AI Report ===");
                        System.out.println(aiReport);
                    }
                    System.out.println("\n\n=== AI Analysis Complete! ===");

                    if (outputFile != null) {
                        Files.writeString(outputFile.toPath(), aiReport);
                        System.out.println("\n\nAI Report saved to: " + outputFile.getAbsolutePath());
                    }
                }
                pool.shutdown();
                return 0;

            } else {
                System.out.println("Please provide a valid URL file path or a domain to scan.");
                return 1;
            }

        }
        System.out.println("\n\nTarget URL file: " + urlFile.getAbsolutePath());
        System.out.println("Number of threads: " + numThreads);

        if (debugMode)
            System.out.println("\n\nOpening the URLs File and preparing to scan...");
        List<String> urls = Files.readAllLines(urlFile.toPath());
        if (debugMode)
            System.out.println("Loaded " + urls.size() + " domains from file.");
        if (debugMode)
            System.out.println("\n\nTurning on the Thread Pool with " + numThreads + " threads...");

        List<Task> tasks = Collections.synchronizedList(new ArrayList<>());

        if (debugMode)
            System.out.println("Thread Pool initialized successfully.");
        if (debugMode)
            System.out.println("Initializing scanning tasks for each URL in the file...");

        for (int i = 0; i < urls.size(); i++) {
            String url = urls.get(i).trim();
            if (url.isEmpty())
                continue;

            if (url.isEmpty())
                continue;
            Runnable work = () -> {
                System.out.println("\nAccessing URL: " + url);
                ScanResult result = DomainScanner.scanDomain(url, recursive, 0, recursiveSteps);
                results.add(result);
                if (debugMode) {
                    System.out.println("\n\nScan Result for URL: " + url);
                    System.out.println(result.toString() + "\n\n");
                }
            };
            Task task = new Task(url + "- Task - " + i, "SSL_AUDIT", work);
            tasks.add(task);
            pool.executeTask(task);
            if (debugMode)
                System.out.println("Task for URL: " + url + " added to the queue.");

        }
 
        boolean allTasksCompleted = false;
        while (!allTasksCompleted) {
            
            int numCompleted = 0;
            System.out.println(numCompleted + "/" + tasks.size());
            for (Task task : tasks) {
                if (task.isCompleted()) {
                    numCompleted++;
                } else {
                    Thread.sleep(1000);
                }
                System.out.println(numCompleted + "/" + tasks.size());

            }
            if (debugMode)
                System.out.println("Num of tasks completed - " + numCompleted + " / " + tasks.size());

            allTasksCompleted = numCompleted == tasks.size();

        }
        if (allTasksCompleted) {
            Thread.sleep(7000);
            if (debugMode)
                System.out.println("\n\nAll tasks completed. Shutting down the Thread Pool...");

            pool.shutdown();
        }
        System.out.println("\n\n=== Scan Complete! Total Scanned: " + results.size() + " ===");

        if (Thread.interrupted()) {
            if (debugMode) {
                System.out.println("[Notice] Thread interrupt flag detected. Clearing it before proceeding.");
            }

        }

        if (enableAIAnalysis) {

            Thread.sleep(7000);
            System.out.println("\n\n=== Starting AI Analysis ===");
            AIReportService aiService = new AIReportService(aiProvider, modelName, aiApiKey, ollamaUrl);
            if (debugMode) {
                System.out.println("[AI] AI Service initialized with provider: " + aiProvider + ", model: " + modelName
                        + ", ollamaUrl: " + ollamaUrl);
            }

            String aiReport = aiService.generateReport(results);
            if (debugMode || outputFile == null) {
                System.out.println("\n\n=== AI Report ===");
                System.out.println(aiReport);
                System.out.println("\n\n");
            }

            System.out.println("\n\n=== AI Analysis Complete! ===");

            if (outputFile != null) {
                Files.writeString(outputFile.toPath(), aiReport);
                System.out.println("\n\nAI Report saved to: " + outputFile.getAbsolutePath());
            }
        }
        return 0;
    }

    /** 
     * @param args
     */
    public static void main(String[] args) {
        System.setProperty("sun.net.client.defaultConnectTimeout", "120000");
        System.setProperty("sun.net.client.defaultReadTimeout", "120000");
        int exitCode = new CommandLine(new SecurityAudit()).execute(args);
        System.exit(exitCode);
    }

}