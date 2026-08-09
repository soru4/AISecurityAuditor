package com.auditor;
import java.util.Map;
public class ScanResult {
    private final String url;
    private final long dayTillSSLExpiry;
    private final Map<String, String> missingHeaders;
    private final boolean isReachable;

    public ScanResult(String url, long dayTillSSLExpiry, Map<String, String> missingHeaders, boolean isReachable) {
        this.url = url;
        this.dayTillSSLExpiry = dayTillSSLExpiry;
        this.missingHeaders = missingHeaders;
        this.isReachable = isReachable;
    }

    public String getUrl() {
        return url;
    }

    public long getDayTillSSLExpiry() {
        return dayTillSSLExpiry;
    }

    public Map<String, String> getMissingHeaders() {
        return missingHeaders;
    }

    public boolean isReachable() {
        return isReachable;
    }

    @Override
    public String toString(){
        if(!isReachable) {
            return "URL: " + url + " is not reachable.";
        }
        return String.format("[%s] SSL Expiry: %d days | Missing Headers: %s",
                url, dayTillSSLExpiry, missingHeaders.keySet());
    }
}
