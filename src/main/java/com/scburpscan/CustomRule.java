package com.scburpscan;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A ScanRule built from a CustomRuleConfig (JSON file).
 */
public class CustomRule implements ScanRule {

    private final CustomRuleConfig config;
    private final FindingEntry.Severity severity;

    // Compiled passive patterns
    private final List<Pattern> compiledBodyPatterns   = new ArrayList<>();
    private final List<HeaderPatternPair> compiledHeaderPatterns = new ArrayList<>();

    // Compiled active detect patterns
    private final List<Pattern> compiledDetectBody    = new ArrayList<>();
    private final List<HeaderPatternPair> compiledDetectHeaders = new ArrayList<>();

    private record HeaderPatternPair(String headerName, Pattern valuePattern) {}

    public CustomRule(CustomRuleConfig config) {
        this.config   = config;
        this.severity = parseSeverity(config.severity);

        if (config.passive != null) {
            if (config.passive.bodyPatterns != null) {
                for (String p : config.passive.bodyPatterns)
                    safeCompile(p, compiledBodyPatterns);
            }
            if (config.passive.headerPatterns != null) {
                for (String p : config.passive.headerPatterns)
                    safeCompileHeader(p, compiledHeaderPatterns);
            }
        }

        if (config.active != null) {
            if (config.active.detectInBody != null) {
                for (String p : config.active.detectInBody)
                    safeCompile(p, compiledDetectBody);
            }
            if (config.active.detectInHeaders != null) {
                for (String p : config.active.detectInHeaders)
                    safeCompileHeader(p, compiledDetectHeaders);
            }
        }
    }

    @Override
    public String getName() {
        return "[Custom] " + (config.name != null ? config.name : "(unnamed)");
    }

    @Override
    public FindingEntry.Severity getSeverity() { return severity; }

    // ── Passive ──────────────────────────────────────────────────────

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        if (config.passive == null || response == null) return findings;

        String ts       = ts();
        String rawReq   = HttpUtil.toRaw(request);
        String rawResp  = HttpUtil.toRaw(response);
        String body     = response.bodyToString();

        // Body pattern checks
        for (Pattern p : compiledBodyPatterns) {
            Matcher m = p.matcher(body);
            if (m.find()) {
                findings.add(finding(entryId, request, FindingEntry.ScanType.PASSIVE,
                    config.description != null ? config.description
                        : "Pattern matched in response body",
                    "Matched: " + truncate(m.group(), 80), ts, rawReq, rawResp));
                return findings; // one finding per response is enough
            }
        }

        // Header pattern checks
        for (HeaderPatternPair hp : compiledHeaderPatterns) {
            for (HttpHeader header : response.headers()) {
                if (header.name().equalsIgnoreCase(hp.headerName())) {
                    if (hp.valuePattern().matcher(header.value()).find()) {
                        findings.add(finding(entryId, request, FindingEntry.ScanType.PASSIVE,
                            config.description != null ? config.description
                                : "Header pattern matched: " + header.name(),
                            header.name() + ": " + header.value(), ts, rawReq, rawResp));
                        return findings;
                    }
                }
            }
        }

        // Param reflection check
        if (config.passive.paramReflection) {
            for (HttpParameter param : request.parameters()) {
                String value = param.value();
                if (value != null && value.length() >= 4 && body.contains(value)) {
                    findings.add(finding(entryId, request, FindingEntry.ScanType.PASSIVE,
                        "Parameter '" + param.name() + "' value reflected in response",
                        truncate(body, value, 60), ts, rawReq, rawResp));
                    return findings;
                }
            }
        }

        return findings;
    }

    // ── Active ────────────────────────────────────────────────────────

    @Override
    public List<FindingEntry> activeCheck(int entryId, HttpRequest request, ActiveRequester requester) {
        List<FindingEntry> findings = new ArrayList<>();
        if (config.active == null) return findings;
        List<String> payloads = config.active.payloads;
        if (payloads == null || payloads.isEmpty()) return findings;

        String ts = ts();

        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) continue;

            for (String payload : payloads) {
                String injectedValue = config.active.appendToValue
                    ? param.value() + payload
                    : payload;

                HttpRequest fuzzed = request.withUpdatedParameters(
                    HttpParameter.parameter(param.name(), injectedValue, param.type())
                );

                HttpResponse resp;
                try {
                    resp = requester.send(fuzzed);
                } catch (Exception e) {
                    continue;
                }
                if (resp == null) continue;

                String body = resp.bodyToString();
                boolean triggered = false;
                String evidence   = "";

                // Status code check
                if (config.active.detectStatusCode > 0
                        && resp.statusCode() == config.active.detectStatusCode) {
                    triggered = true;
                    evidence  = "Status: " + resp.statusCode();
                }

                // Body pattern check
                if (!triggered) {
                    for (Pattern p : compiledDetectBody) {
                        Matcher m = p.matcher(body);
                        if (m.find()) {
                            triggered = true;
                            evidence  = "Body matched: " + truncate(m.group(), 80);
                            break;
                        }
                    }
                }

                // Response header pattern check
                if (!triggered) {
                    for (HeaderPatternPair hp : compiledDetectHeaders) {
                        for (HttpHeader header : resp.headers()) {
                            if (header.name().equalsIgnoreCase(hp.headerName())
                                    && hp.valuePattern().matcher(header.value()).find()) {
                                triggered = true;
                                evidence  = "Header matched: " + header.name() + ": " + header.value();
                                break;
                            }
                        }
                        if (triggered) break;
                    }
                }

                if (triggered) {
                    findings.add(finding(entryId, request, FindingEntry.ScanType.ACTIVE,
                        (config.description != null ? config.description : "Active rule triggered")
                            + " — param '" + param.name() + "', payload: " + truncate(payload, 60),
                        evidence, ts,
                        HttpUtil.toRaw(fuzzed), HttpUtil.toRaw(resp)));
                    break; // one per param
                }
            }
        }
        return findings;
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private FindingEntry finding(int id, HttpRequest req, FindingEntry.ScanType type,
                                  String detail, String evidence, String ts,
                                  String rawReq, String rawResp) {
        return new FindingEntry(id, req.url(), req.method(),
            req.httpService().host(), getName(), severity, type,
            detail, evidence, ts, rawReq, rawResp);
    }

    private static FindingEntry.Severity parseSeverity(String s) {
        if (s == null) return FindingEntry.Severity.INFO;
        return switch (s.toUpperCase()) {
            case "HIGH"   -> FindingEntry.Severity.HIGH;
            case "MEDIUM" -> FindingEntry.Severity.MEDIUM;
            case "LOW"    -> FindingEntry.Severity.LOW;
            default       -> FindingEntry.Severity.INFO;
        };
    }

    private static void safeCompile(String pattern, List<Pattern> list) {
        try {
            list.add(Pattern.compile(pattern));
        } catch (Exception ignored) {}
    }

    private static void safeCompileHeader(String spec, List<HeaderPatternPair> list) {
        int colon = spec.indexOf(':');
        if (colon <= 0) return;
        String headerName = spec.substring(0, colon).trim();
        String regex      = spec.substring(colon + 1).trim();
        try {
            list.add(new HeaderPatternPair(headerName, Pattern.compile(regex)));
        } catch (Exception ignored) {}
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }

    private static String truncate(String body, String value, int ctx) {
        int idx = body.indexOf(value);
        if (idx < 0) return value;
        int start = Math.max(0, idx - ctx);
        int end   = Math.min(body.length(), idx + value.length() + ctx);
        return "..." + body.substring(start, end) + "...";
    }

    private static String ts() {
        return LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
    }
}
