package com.auditor;

import java.util.Map;
public class ScanResult {
    private final String url;
    private final long dayTillSSLExpiry;
    private final Map<String, String> missingHeaders;
    private final boolean isReachable;
    private final boolean wasScannedInRecursiveMode;
  

    public ScanResult(String url, long dayTillSSLExpiry, Map<String, String> missingHeaders, boolean isReachable, boolean wasScannedInRecursiveMode) {
        this.url = url;
        this.dayTillSSLExpiry = dayTillSSLExpiry;
        this.missingHeaders = missingHeaders;
        this.isReachable = isReachable;
        this.wasScannedInRecursiveMode = wasScannedInRecursiveMode;
        if(SecurityAudit.debugMode) {
            System.out.println("ScanResult created for URL: " + url );
        }
       
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
    public boolean wasScannedInRecursiveMode() {
        return wasScannedInRecursiveMode;
    }


    @Override
    public String toString(){
        if(!isReachable && wasScannedInRecursiveMode){
            return "URL: " + url + " is not reachable. (Scanned in recursive mode) (This is likely due to the fact that the domain scanner hit the max recursive steps and did not scan this domain directly)";
        }
        if(!isReachable) {
            return "URL: " + url + " is not reachable.";
        }
        return String.format("[%s] SSL Expiry: %d days | Missing Headers: %s | Recursive Scan: %s",
                url, dayTillSSLExpiry, missingHeaders.keySet(), wasScannedInRecursiveMode);
    }

}
