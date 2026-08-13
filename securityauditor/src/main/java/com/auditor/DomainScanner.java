package com.auditor;

import javax.net.ssl.HttpsURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.threadpool.Task;

public class DomainScanner {

    private static final List<String> REQUIRED_HEADERS = Arrays.asList(
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy",
            "Permissions-Policy");

    public static ScanResult scanDomain(String domain, boolean recursive, int step, int maxSteps) {
        if (step > maxSteps) {
            return new ScanResult(domain, -1, Collections.emptyMap(), false, true);
        }

        String urlString = domain.startsWith("http") ? domain : "https://" + domain;
        long daysUntilExpiry = -1;
        Map<String, String> missingHeaders = new HashMap<>();

        try {
            URI uri = new URI(urlString);
            URL url = uri.toURL();
            String currentHost = url.getHost();

            if (currentHost == null || !SecurityAudit.scannedDomains.add(currentHost)) {
                return null;
            }

            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("GET");

            connection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
            connection.setConnectTimeout(4000);
            connection.setReadTimeout(4000);
            connection.connect();
            if (SecurityAudit.debugMode) {
                System.out.println("Connected to domain: " + domain + " | Recursive Step: " + step + "/" + maxSteps);
            }

            X509Certificate[] certs = (X509Certificate[]) connection.getServerCertificates();

            if (certs != null && certs.length > 0) {
                Date cert = certs[0].getNotAfter();
                long diffInMillis = cert.getTime() - System.currentTimeMillis();
                daysUntilExpiry = TimeUnit.DAYS.convert(diffInMillis, TimeUnit.MILLISECONDS);
            }
            if (SecurityAudit.debugMode) {
                System.out.println("Retrieved SSL certificates for domain: " + domain + " | Recursive Step: " + step
                        + "/" + maxSteps);
            }

            Map<String, List<String>> headers = connection.getHeaderFields();

            for (String requiredHeader : REQUIRED_HEADERS) {
                boolean found = headers.keySet().stream()
                        .filter(Objects::nonNull)
                        .anyMatch(h -> h.equalsIgnoreCase(requiredHeader));
                if (SecurityAudit.debugMode) {
                    System.out.println("\n\nChecking header: " + requiredHeader + " | Found: " + found + " | Domain: "
                            + domain + " | Recursive Step: " + step + "/" + maxSteps);
                }
                if (!found) {
                    missingHeaders.put(requiredHeader, "Missing");
                }
            }
            if (SecurityAudit.debugMode) {
                System.out.println(
                        "Retrieved headers for domain: " + domain + " | Recursive Step: " + step + "/" + maxSteps);
            }
            // THe recursive scanning logic.

            Document doc = Jsoup.parse(connection.getInputStream(), "UTF-8", urlString);
            if (SecurityAudit.debugMode) {
                System.out.println("Parsed HTML for domain: " + domain + " | Recursive Step: " + step + "/" + maxSteps);
            }
            if (SecurityAudit.debugMode) {
                System.out.println("\nScanned domain: " + domain + " | SSL Expiry: " + daysUntilExpiry
                        + " days | Missing Headers: " + missingHeaders.keySet() + " | Recursive Step: " + step + "/"
                        + maxSteps + "\n\n");
            }

            Elements links = doc.select("a[href]");
            if (recursive && step < maxSteps) {

                for (Element link : links) {
                    String linkHref = link.attr("abs:href");

                    if (linkHref.startsWith("http://") || linkHref.startsWith("https://")) {
                        try {
                            URI linkUri = new URI(linkHref);
                            String linkHost = linkUri.getHost();

                            if (SecurityAudit.debugMode) {
                                System.out.println("Found link on domain: " + domain + " | Recursive Step: " + step
                                        + "/" + maxSteps + "Link: " + linkHref);
                            }

                            if (linkHost != null && !SecurityAudit.scannedDomains.contains(linkHost)) {
                                if (SecurityAudit.debugMode) {
                                    System.out.println("Found new link to scan: " + linkHref);
                                }
                                Runnable work = () -> {
                                    System.out.println("\nAccessing URL: " + url);
                                    ScanResult result = scanDomain(linkHref, recursive, step + 1, maxSteps);
                                    if(result != null)
                                        SecurityAudit.results.add(result);
                                    if (SecurityAudit.debugMode) {
                                        System.out.println("\n\nScan Result for URL: " + url);
                                        System.out.println(result.toString() + "\n\n");
                                    }
                                };
                                Task task = new Task(linkHref + "- Task - ", "SSL_AUDIT", work);
                                
                                SecurityAudit.tasks.add(task);
                                System.out.println("adding task " + SecurityAudit.tasks.size() );
                                SecurityAudit.pool.executeTask(task);

                            }
                        } catch (Exception ignored) {

                        }
                    }
                }
            }
            if (SecurityAudit.debugMode) {
                System.out.println("Found " + links.size() + " links on domain: " + domain + " | Recursive Step: "
                        + step + "/" + maxSteps);
            }

            connection.disconnect();
            return new ScanResult(domain, daysUntilExpiry, missingHeaders, true, false);

        } catch (Exception e) {
            System.err.println("Error scanning domain " + domain + ": " + e.getMessage());
            return new ScanResult(domain, -1, Collections.emptyMap(), false, false);
        }
    }
}