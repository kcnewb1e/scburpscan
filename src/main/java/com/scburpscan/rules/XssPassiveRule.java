package com.scburpscan.rules;

import burp.api.montoya.http.message.params.HttpParameter;
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

public class XssPassiveRule implements ScanRule {

    @Override
    public String getName() { return "Reflected XSS (Passive)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.HIGH; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        if (response == null) return findings;

        String body = response.bodyToString();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String rawReq = HttpUtil.toRaw(request);
        String rawResp = HttpUtil.toRaw(response);

        for (HttpParameter param : request.parameters()) {
            String value = param.value();
            if (value == null || value.length() < 2) continue;

            boolean hasCrits = value.contains("<") || value.contains("'") || value.contains("\"")
                    || value.contains("javascript") || value.contains("onerror");

            if (!hasCrits) {
                if (value.length() >= 4 && body.contains(value)) {
                    findings.add(new FindingEntry(
                        entryId, request.url(), request.method(), request.httpService().host(),
                        getName(), getSeverity(), FindingEntry.ScanType.PASSIVE,
                        "Parameter '" + param.name() + "' value reflected in response — potential XSS injection point",
                        truncate(body, value, 100), ts, rawReq, rawResp
                    ));
                }
            } else {
                if (body.contains(value)) {
                    findings.add(new FindingEntry(
                        entryId, request.url(), request.method(), request.httpService().host(),
                        getName(), getSeverity(), FindingEntry.ScanType.PASSIVE,
                        "XSS-like chars in param '" + param.name() + "' reflected unencoded",
                        truncate(body, value, 100), ts, rawReq, rawResp
                    ));
                }
            }
        }
        return findings;
    }

    @Override
    public List<FindingEntry> activeCheck(int entryId, HttpRequest request, ActiveRequester requester) {
        return List.of();
    }

    private String truncate(String body, String value, int context) {
        int idx = body.indexOf(value);
        if (idx < 0) return "";
        int start = Math.max(0, idx - context);
        int end = Math.min(body.length(), idx + value.length() + context);
        return "..." + body.substring(start, end) + "...";
    }
}
