package com.scburpscan;

public class FindingEntry {
    public enum Severity { HIGH, MEDIUM, LOW, INFO }
    public enum ScanType { PASSIVE, ACTIVE }

    public final int id;
    public final String url;
    public final String method;
    public final String host;
    public final String ruleName;
    public final Severity severity;
    public final ScanType scanType;
    public final String detail;
    public final String evidence;
    public final String timestamp;
    public final String rawRequest;
    public final String rawResponse;

    public FindingEntry(int id, String url, String method, String host,
                        String ruleName, Severity severity, ScanType scanType,
                        String detail, String evidence, String timestamp,
                        String rawRequest, String rawResponse) {
        this.id = id;
        this.url = url;
        this.method = method;
        this.host = host;
        this.ruleName = ruleName;
        this.severity = severity;
        this.scanType = scanType;
        this.detail = detail;
        this.evidence = evidence;
        this.timestamp = timestamp;
        this.rawRequest = rawRequest != null ? rawRequest : "";
        this.rawResponse = rawResponse != null ? rawResponse : "";
    }
}
