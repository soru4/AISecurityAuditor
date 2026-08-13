# AI Security Auditor CLI tool
A high performance Java-based CLI tool that automates network security audits. It does HTTP security header evaluation as well as TLS and SSL certificate inspection. It can also recursively check these things for embedded links in the given domain. It will distribute all of the tasks on multiple threads to allow for many, many domains to be scanned concurrently. The project allows the user to choose an AI provider between Gemini, OpenAI, and Ollama for JSON summaries. 

## Table of Contents
  1. [Features](#-features)
  2. [Getting Started](#-getting-started)
  3. [Required Dependencies](#-required-dependencies)
  4. [Usage](#-usage)
  5. [Detailed Manual](#-detailed-menu)

## Features
  - **Intuitive CLI Interface (picocli):** Powered by picocli for elegant command-line argument parsing, subcommands, and built-in --help menus
  - **Multithreaded Concurrent Scanning:** Leverages Java's thread management to scan multiple domains, and inspect endpoints, concurrently for maximum throughput.
  - **SSL/TLS Expiry Tracking:** Inspects target certificates and calculates remaining validity days.
  - **HTTP Security Header Audit:** Scans for missing security headers like _Strict-Transport-Security_, _Content-Security-Policy_, _X-Frame-Options_, and more.
  - **Recursive Link Crawling:** Parses HTML with JSoup to recursively discover and scan internal/external links up to a configured step depth.
  - **Multi-Provider AI Analysis:** Integrates via _LangChain4j_ / REST endpoints with OpenAI (GPT-4o), Google Gemini, and local Ollama models.
  - **Duplicate Prevention:** Tracks scanned hosts across recursive passes to prevent infinite crawling loops.

## Getting Started
  1. Java JDK 17 or higher
  2. Use Maven or Gradle
  3. API Keys: Get OpenAI keys or Google Gemini keys or set up Ollama on your local machine.

## Required Dependencies
  1. PicoCLI
  2. JSoup
  3. LangChain4
  4. [TaskDistributor](https://github.com/soru4/TaskDistrib)

## Usage
  ### Basic Use:
   To scan a single domain:
   
   ```Command Line
    java -jar auditor.jar -d www.google.com
   ```

   Output:
   ```
    === Starting Security Audit ===
    AI Analysis enabled: false
    NO URL FILE FOUND! 
   [www.google.com] SSL Expiry: 59 days | Missing Headers: [Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, Content-Security-Policy, Permissions-Policy] | Recursive Scan: false
   ```

  To scan a single domain with recursive scanning of depth 1:
  ```
    java -jar auditor.jar -d www.google.com -r --rs 1
  ```
  Output:
  ```
    === Starting Security Audit ===
    AI Analysis enabled: false
    NO URL FILE FOUND! 
    adding task 1
    Task https://mail.google.com/mail/&ogbl- Task -  added to the line!
    adding task 2
    Task https://accounts.google.com/ServiceLogin?hl=en&passive=true&continue=https://www.google.com/&ec=GAZAmgQ- Task -  added to the line!
    Starting task https://accounts.google.com/ServiceLogin?hl=en&passive=true&continue=https://www.google.com/&ec=GAZAmgQ- Task -  on thread: CustomWorker-1
    Starting task https://mail.google.com/mail/&ogbl- Task -  on thread: CustomWorker-2
    
    Accessing URL: https://www.google.com
    
    Accessing URL: https://www.google.com
    [www.google.com] SSL Expiry: 59 days | Missing Headers: [Referrer-Policy, Strict-Transport-Security, X-Content-Type-Options, Content-Security-Policy, Permissions-Policy] | Recursive Scan: false
    
    
    Finished task https://accounts.google.com/ServiceLogin?hl=en&passive=true&continue=https://www.google.com/&ec=GAZAmgQ- Task - 
    CustomWorker-1 line empty
    Finished task https://mail.google.com/mail/&ogbl- Task - 
    CustomWorker-2 line empty
  ```
  To turn on AI report generation (You can change the model name to whatever model you would like to use):
  
  ```
    #Using Gemini
    java -jar auditor.jar -d www.google.com --ai --provider Gemini --model-name gemini-3.5-flash --api-key (_YOUR API KEY HERE_)
    #Using Open AI
    java -jar auditor.jar -d www.google.com --ai --provider OpenAI --model-name gpt-4o-mini --api-key (_YOUR API KEY HERE_)
    #Using Ollama
    java -jar auditor.jar -d www.google.com --ai --provider Ollama --model-name llama3 --ollama-url (_YOUR OLLAMA URL_)
  ```
  Example AI JSON output:

  ```
     {
        "Domain": "google.com",
        "Reachable": true,
        "SSL_Expiry_Days": 60,
        "Missing_Headers": [
            "Referrer-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Permissions-Policy"
        ],
        "Risk_Level": "MEDIUM",
        "Summary": "Domain reachable; SSL expires in 60d. Missing HSTS, CSP, and other security headers.",
        "Remediation": "Add HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."
    },
  ```

## Detailed Manual

  ### Scan one domain at a time
  Use the command:
  ```
  java -jar auditor.jar -d (domain to scan)
  ```

  ### Scan Multiple Domains at once, write a text file with domains on each line. 

  Example URL FIle:
  ```
  google.com
  youtube.com
  ```
  Use the command:
  ```
  java -jar auditor.jar -f (PATH TO YOUR FILE)
  ```
  ### Set number of threads in thread pool. 

  Use the command:
  ```
  java -jar auditor.jar -t 3 -f (PATH TO URL FILE)
  ```

  ### Turn on recursive scanning of embedded links in domain
  
  ```
    java -jar auditor.jar -t 2 -d (domain to scan) -r
  ```

  ### Change the depth of the recursion of embedded links (default depth is 2)
  
  ```
    java -jar auditor.jar -t 3 -d (domain to scan) -r --rs 1
  ```

  ### Turn on AI with a custom provider (Gemini, OpenAI, Ollama)
  
  ```
    java -jar auditor.jar -t 3 -d (domain to scan) --ai --provider (Choose provider) --api-key (YOUR API KEY)
  ```

  ### Change AI model
  
  ```
    java -jar auditor.jar -t 3 -d (domain to scan) --ai --provider (Choose provider) --model-name (choose ai model name ex. gemini-3.6-flash) --api-key (YOUR API KEY)
  ```

  ### Set output JSON file
  ```
    java -jar auditor.jar -t 3 -d (domain to scan) --ai --provider (Choose provider) --model-name (choose ai model name ex. gemini-3.6-flash) --api-key (YOUR API KEY) -o (Output File)
  ```

  ### Turn on Debug mode
  ```
    java -jar auditor.jar -debug -t 3 -d (domain to scan) --ai --provider (Choose provider) --model-name (choose ai model name ex. gemini-3.6-flash) --api-key (YOUR API KEY) -o (YOUR AI MODEL)
  ```  

