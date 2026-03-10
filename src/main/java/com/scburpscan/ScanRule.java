package com.scburpscan;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;

/**
 * Interface for all scan rules.
 * Each rule can run in passive mode (analyze only) or active mode (send requests).
 */
public interface ScanRule {

    String getName();

    FindingEntry.Severity getSeverity();

    /**
     * Passive check: analyze request/response without sending new requests.
     * Returns list of findings (empty if nothing found).
     */
    List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response);

    /**
     * Active check: generate payloads and test them.
     * The requester callback is used to send requests.
     * Returns list of findings (empty if nothing found).
     */
    List<FindingEntry> activeCheck(int entryId, HttpRequest request, ActiveRequester requester);
}
