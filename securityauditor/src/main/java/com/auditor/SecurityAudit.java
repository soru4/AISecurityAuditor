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

    @Option(names = {"--ai-api-key", "--api-key"}, description = "API key for AI analysis (required if --ai is enabled)")
    private String aiApiKey;

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
            Task task = new Task("Task - " + i, "SSL_AUDIT", work);

            pool.executeTask(task);
        }
        while(!queue.getTaskQueue().isEmpty())
            Thread.sleep(1000);
        Thread.sleep(2000); 

        System.out.println("\n\nAll tasks completed. Shutting down the Thread Pool...");

        pool.shutdown();
        System.out.println("\n\n=== Scan Complete! Total Scanned: " + results.size() + " ===");
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new SecurityAudit()).execute(args);
        System.exit(exitCode);
    }


}
