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
import java.util.List;

/**
 * Active Blind SQLi — Boolean Based.
 *
 * Strategy:
 *  For each parameter, inject a TRUE condition and a FALSE condition.
 *  If the two responses differ significantly (body length or content),
 *  the parameter is likely injectable.
 *
 * Pairs tested:
 *   TRUE  → query logically unchanged   → response = normal
 *   FALSE → query returns nothing/error → response changes
 *
 * Detection heuristics:
 *  1. Body length differs by > LENGTH_DIFF_THRESHOLD bytes.
 *  2. Body length differs by > LENGTH_DIFF_PCT percent of the TRUE response.
 *  3. HTTP status code differs between TRUE and FALSE.
 *
 * We also verify the baseline matches the TRUE condition to reduce false
 * positives (baseline ≈ true_response is expected).
 */
public class SqliBooleanBasedRule implements ScanRule {

    private static final int LENGTH_DIFF_THRESHOLD = 50;   // absolute byte difference
    private static final double LENGTH_DIFF_PCT     = 0.05; // 5% relative difference

    private record BoolPair(String label, String truePayload, String falsePayload) {}

    private static final List<BoolPair> PAIRS = List.of(
        // String-based
        new BoolPair("String quote",
            "' AND '1'='1",
            "' AND '1'='2"),
        new BoolPair("String double-quote",
            "\" AND \"1\"=\"1",
            "\" AND \"1\"=\"2"),
        // Numeric-based
        new BoolPair("Numeric AND",
            " AND 1=1-- -",
            " AND 1=2-- -"),
        new BoolPair("Numeric OR",
            " OR 1=1-- -",
            " OR 1=2-- -"),
        // Comment style variations
        new BoolPair("String hash comment",
            "' AND '1'='1'#",
            "' AND '1'='2'#"),
        new BoolPair("String inline comment",
            "' AND '1'='1'/*",
            "' AND '1'='2'/*"),
        // Substring-based (confirms DB interaction)
        new BoolPair("SUBSTRING true",
            "' AND SUBSTRING('a',1,1)='a'-- -",
            "' AND SUBSTRING('a',1,1)='b'-- -"),
        new BoolPair("Numeric BETWEEN true",
            " AND 1 BETWEEN 0 AND 2-- -",
            " AND 1 BETWEEN 5 AND 10-- -")
    );

    @Override
    public String getName() { return "SQL Injection - Blind (Boolean Based)"; }

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

        // Baseline: original response
        HttpResponse baseline;
        try {
            baseline = requester.send(request);
        } catch (Exception e) {
            return findings;
        }
        if (baseline == null) return findings;
        int baselineLen = baseline.bodyToString().length();
        int baselineStatus = baseline.statusCode();

        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) continue;

            for (BoolPair pair : PAIRS) {
                HttpRequest trueReq = request.withUpdatedParameters(
                    HttpParameter.parameter(param.name(), param.value() + pair.truePayload(), param.type())
                );
                HttpRequest falseReq = request.withUpdatedParameters(
                    HttpParameter.parameter(param.name(), param.value() + pair.falsePayload(), param.type())
                );

                HttpResponse trueResp, falseResp;
                try {
                    trueResp  = requester.send(trueReq);
                    falseResp = requester.send(falseReq);
                } catch (Exception e) {
                    continue;
                }
                if (trueResp == null || falseResp == null) continue;

                int trueLen  = trueResp.bodyToString().length();
                int falseLen = falseResp.bodyToString().length();
                int trueStatus  = trueResp.statusCode();
                int falseStatus = falseResp.statusCode();

                // Heuristic 1: TRUE ≈ baseline (sanity check)
                boolean trueMatchesBaseline =
                    Math.abs(trueLen - baselineLen) <= LENGTH_DIFF_THRESHOLD
                    && trueStatus == baselineStatus;

                if (!trueMatchesBaseline) continue; // likely not injectable this way

                // Heuristic 2: TRUE vs FALSE differ
                int absDiff = Math.abs(trueLen - falseLen);
                double pctDiff = trueLen > 0 ? (double) absDiff / trueLen : 0;
                boolean statusDiffers = trueStatus != falseStatus;
                boolean bodyDiffers   = absDiff >= LENGTH_DIFF_THRESHOLD
                                     || pctDiff >= LENGTH_DIFF_PCT;

                if (bodyDiffers || statusDiffers) {
                    String diffDesc = statusDiffers
                        ? "HTTP status differs: TRUE=" + trueStatus + " FALSE=" + falseStatus
                        : "Body length: TRUE=" + trueLen + "B FALSE=" + falseLen
                            + "B (diff=" + absDiff + "B, " + String.format("%.1f", pctDiff * 100) + "%)";

                    findings.add(new FindingEntry(
                        entryId, request.url(), request.method(),
                        request.httpService().host(),
                        getName(), getSeverity(), FindingEntry.ScanType.ACTIVE,
                        "Boolean-based SQLi in param '" + param.name() + "' [" + pair.label() + "]: "
                            + diffDesc,
                        "TRUE: " + pair.truePayload() + " | FALSE: " + pair.falsePayload(), ts,
                        HttpUtil.toRaw(trueReq), HttpUtil.toRaw(trueResp)
                    ));
                    break; // one confirmed finding per param
                }
            }
        }
        return findings;
    }
}
