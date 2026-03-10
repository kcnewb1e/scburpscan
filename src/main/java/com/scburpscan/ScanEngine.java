package com.scburpscan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.scburpscan.rules.*;
import com.scburpscan.rules.SqliTimeBasedRule;
import com.scburpscan.rules.SqliBooleanBasedRule;

import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Core scan engine. Manages rules, threading, and finding output.
 */
public class ScanEngine {

    private final MontoyaApi api;
    private final List<FindingEntry> findings;
    private final Set<String> seenKeys = ConcurrentHashMap.newKeySet();
    private final AtomicInteger findingCounter = new AtomicInteger(0);
    private final AtomicBoolean activeScanEnabled = new AtomicBoolean(false);
    private final ExecutorService executor = Executors.newFixedThreadPool(4);
    private Runnable onNewFinding;

    // Custom rules loaded from user-configured folder
    private volatile List<ScanRule> customPassiveRules = Collections.emptyList();
    private volatile List<ScanRule> customActiveRules  = Collections.emptyList();

    // Passive rules — always run
    private final List<ScanRule> passiveRules = List.of(
        new XssPassiveRule(),
        new SqliPassiveRule(),
        new OpenRedirectPassiveRule(),
        new SsrfPassiveRule(),
        new SensitiveInfoPassiveRule(),
        new SecurityHeadersPassiveRule()
    );

    // Active rules — run only when active scan is enabled
    private final List<ScanRule> activeRules = List.of(
        new XssActiveRule(),
        new SqliActiveRule(),
        new SqliTimeBasedRule(),
        new SqliBooleanBasedRule(),
        new PathTraversalActiveRule()
    );

    public ScanEngine(MontoyaApi api, List<FindingEntry> findings) {
        this.api = api;
        this.findings = findings;
    }

    public void setOnNewFinding(Runnable callback) {
        this.onNewFinding = callback;
    }

    public boolean isActiveScanEnabled() {
        return activeScanEnabled.get();
    }

    public void setActiveScanEnabled(boolean enabled) {
        activeScanEnabled.set(enabled);
        api.logging().logToOutput("SCBurpScan: Active scan " + (enabled ? "ENABLED" : "DISABLED"));
    }

    /**
     * Submit a request/response pair for scanning.
     */
    public void scan(int entryId, HttpRequest request, HttpResponse response) {
        executor.submit(() -> {
            // Always run passive rules (built-in + custom)
            for (ScanRule rule : passiveRules) {
                try {
                    addFindings(rule.passiveCheck(entryId, request, response));
                } catch (Exception e) {
                    api.logging().logToError("Passive rule error [" + rule.getName() + "]: " + e.getMessage());
                }
            }
            for (ScanRule rule : customPassiveRules) {
                try {
                    addFindings(rule.passiveCheck(entryId, request, response));
                } catch (Exception e) {
                    api.logging().logToError("Custom passive rule error [" + rule.getName() + "]: " + e.getMessage());
                }
            }

            // Run active rules only if enabled (built-in + custom)
            if (activeScanEnabled.get()) {
                ActiveRequester requester = req -> {
                    try {
                        return api.http().sendRequest(req).response();
                    } catch (Exception e) {
                        return null;
                    }
                };

                for (ScanRule rule : activeRules) {
                    try {
                        addFindings(rule.activeCheck(entryId, request, requester));
                    } catch (Exception e) {
                        api.logging().logToError("Active rule error [" + rule.getName() + "]: " + e.getMessage());
                    }
                }
                for (ScanRule rule : customActiveRules) {
                    try {
                        addFindings(rule.activeCheck(entryId, request, requester));
                    } catch (Exception e) {
                        api.logging().logToError("Custom active rule error [" + rule.getName() + "]: " + e.getMessage());
                    }
                }
            }
        });
    }

    private void addFindings(List<FindingEntry> found) {
        for (FindingEntry f : found) {
            String key = dedupKey(f);
            if (seenKeys.add(key)) {  // add() returns false if already present
                findings.add(f);
                if (onNewFinding != null) {
                    onNewFinding.run();
                }
            }
        }
    }

    /**
     * Dedup key: ruleName + host + url-path (no query string).
     * For rules that embed the param name in ruleName (active rules do),
     * this naturally deduplicates per-param-per-path.
     * For passive rules, detail already encodes param name so we include it.
     */
    private String dedupKey(FindingEntry f) {
        String path = urlPath(f.url);
        // Extract param name from detail if present (e.g. "param 'id'" or "param '" + name + "'")
        String paramHint = extractParamHint(f.detail);
        return f.ruleName + "|" + f.host + "|" + path + "|" + paramHint;
    }

    private String urlPath(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getPath();
            return path == null || path.isEmpty() ? "/" : path;
        } catch (Exception e) {
            // Fallback: strip query string manually
            int q = url.indexOf('?');
            int h = url.indexOf('#');
            int end = url.length();
            if (q >= 0) end = Math.min(end, q);
            if (h >= 0) end = Math.min(end, h);
            return url.substring(0, end);
        }
    }

    private String extractParamHint(String detail) {
        if (detail == null) return "";
        // Match patterns like: param 'name' or parameter 'name'
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("param(?:eter)?\\s+'([^']+)'", java.util.regex.Pattern.CASE_INSENSITIVE)
            .matcher(detail);
        return m.find() ? m.group(1) : "";
    }

    /** Called from SettingsPanel when user reloads custom rules. */
    public void setCustomRules(List<ScanRule> rules) {
        List<ScanRule> passive = new ArrayList<>();
        List<ScanRule> active  = new ArrayList<>();
        for (ScanRule r : rules) {
            // CustomRule always has both methods; route by config
            passive.add(r);  // passiveCheck returns empty list if no passive config
            active.add(r);   // activeCheck returns empty list if no active config
        }
        customPassiveRules = Collections.unmodifiableList(passive);
        customActiveRules  = Collections.unmodifiableList(active);
        api.logging().logToOutput("SCBurpScan: " + rules.size() + " custom rule(s) loaded.");
    }

    public void clearFindings() {
        findings.clear();
        seenKeys.clear();
    }

    public void shutdown() {
        executor.shutdownNow();
    }
}
