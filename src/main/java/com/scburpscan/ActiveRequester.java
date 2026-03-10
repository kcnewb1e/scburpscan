package com.scburpscan;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * Callback interface for active rules to send HTTP requests.
 */
@FunctionalInterface
public interface ActiveRequester {
    HttpResponse send(HttpRequest request);
}
