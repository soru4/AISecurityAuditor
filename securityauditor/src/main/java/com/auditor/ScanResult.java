package com.auditor;

import java.util.Map;
public class ScanResult {
    private final String url;
    private final long dayTillSSLExpiry;
    private final Map<String, String> missingHeaders;
    private final boolean isReachable;
    private final boolean wasScannedInRecursiveMode;
  
    /**
     * Sets up scan result. Just stores all of the information needed. 
     * @param url
     * @param dayTillSSLExpiry
     * @param missingHeaders
     * @param isReachable
     * @param wasScannedInRecursiveMode
     */
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


    

    /** 
     * Gets the URL scanned. 
     * @return String
     */
    public String getUrl() {
        return url;
    }

    /** 
     * gets the number of days until the SSL for the domain expires. 
     * @return long
     */
    public long getDayTillSSLExpiry() {
        return dayTillSSLExpiry;
    }

    /** 
     * Returns the http headers that are missing for the domain
     * @return Map<String, String>
     */
    public Map<String, String> getMissingHeaders() {
        return missingHeaders;
    }

    /** 
     * Returns if the DomainScanner was able to access the url. 
     * @return boolean
     */
    public boolean isReachable() {
        return isReachable;
    }
    /** 
     * Returns if the domain was conducting a recursive step when scanning. 
     * @return boolean
     */
    public boolean wasScannedInRecursiveMode() {
        return wasScannedInRecursiveMode;
    }


    /** 
     * Converts the Scan result to a string. 
     * @return String
     */
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
