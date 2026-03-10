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

public class XssActiveRule implements ScanRule {

    private static final List<String> PAYLOADS = List.of(
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)"
    );

    @Override
    public String getName() { return "Reflected XSS (Active)"; }

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

        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) continue;

            for (String payload : PAYLOADS) {
                HttpRequest fuzzed = request.withUpdatedParameters(
                    burp.api.montoya.http.message.params.HttpParameter.parameter(
                        param.name(), payload, param.type()
                    )
                );
                try {
                    HttpResponse resp = requester.send(fuzzed);
                    if (resp == null) continue;
                    String body = resp.bodyToString();

                    if (body.contains(payload) || (body.contains("<script>") && body.contains("alert(1)"))) {
                        findings.add(new FindingEntry(
                            entryId, request.url(), request.method(), request.httpService().host(),
                            getName(), getSeverity(), FindingEntry.ScanType.ACTIVE,
                            "XSS payload reflected in param '" + param.name() + "': " + payload,
                            truncate(body, payload, 80), ts,
                            HttpUtil.toRaw(fuzzed), HttpUtil.toRaw(resp)
                        ));
                        break;
                    }
                } catch (Exception ignored) {}
            }
        }
        return findings;
    }

    private String truncate(String body, String value, int context) {
        int idx = body.indexOf(value);
        if (idx < 0) return "";
        int start = Math.max(0, idx - context);
        int end = Math.min(body.length(), idx + value.length() + context);
        return "..." + body.substring(start, end) + "...";
    }
}
