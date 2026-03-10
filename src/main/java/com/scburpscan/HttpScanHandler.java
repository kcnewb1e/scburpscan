package com.scburpscan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Intercepts all HTTP traffic and feeds it to the scan engine.
 */
public class HttpScanHandler implements HttpHandler {

    private final MontoyaApi api;
    private final ScanEngine engine;
    private final AtomicInteger entryCounter;
    private final AtomicBoolean inScopeOnly = new AtomicBoolean(false);

    public HttpScanHandler(MontoyaApi api, ScanEngine engine, AtomicInteger entryCounter) {
        this.api = api;
        this.engine = engine;
        this.entryCounter = entryCounter;
    }

    public void setInScopeOnly(boolean enabled) {
        inScopeOnly.set(enabled);
    }

    public boolean isInScopeOnly() {
        return inScopeOnly.get();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        HttpRequest request = response.initiatingRequest();

        // Skip Burp's own internal requests to avoid infinite loops
        String tool = response.toolSource().toolType().toolName();
        if (tool.equals("Extender") || tool.equals("Scanner")) {
            return ResponseReceivedAction.continueWith(response);
        }

        // Filter by scope if enabled
        if (inScopeOnly.get() && !api.scope().isInScope(request.url())) {
            return ResponseReceivedAction.continueWith(response);
        }

        int id = entryCounter.incrementAndGet();
        engine.scan(id, request, response);

        return ResponseReceivedAction.continueWith(response);
    }
}
