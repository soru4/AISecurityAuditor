package com.auditor;
import javax.net.ssl.HttpsURLConnection;
import java.net.URI;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.TimeUnit;
public class DomainScanner {
    private static final List<String> REQUIRED_HEADERS = Arrays.asList(
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Referrer-Policy"

    );

    public static ScanResult scanDomain(String domain){
        String urlString = domain.startsWith("http") ? domain : "https://" + domain;
        long daysUntilExpiry = -1;
        Map<String, String> missingHeaders = new HashMap<>();

        try{
            URI uri = new URI(urlString);
            URL url = uri.toURL();
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.connect();

            X509Certificate[] certs = (X509Certificate[]) connection.getServerCertificates();
            if(certs.length > 0){
                Date cert = certs[0].getNotAfter();
                long diffInMillis = cert.getTime() - System.currentTimeMillis();
                daysUntilExpiry = TimeUnit.DAYS.convert(diffInMillis, TimeUnit.MILLISECONDS);
            }

            Map<String, List<String>> headers = connection.getHeaderFields();
            for(String requiredHeader : REQUIRED_HEADERS){
                boolean found = headers.keySet().stream()
                        .filter(Objects::nonNull)
                        .anyMatch(h -> h.equalsIgnoreCase(requiredHeader));
                if(!found){
                    missingHeaders.put(requiredHeader, "Missing");
                }
            }
            connection.disconnect();
            return new ScanResult(domain, daysUntilExpiry, missingHeaders, true);
        } catch (Exception e){
            System.err.println("Error scanning domain " + domain + ": " + e.getMessage());
            return new ScanResult(domain, -1, Collections.emptyMap(), false);
        }
    }


}
