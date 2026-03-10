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
import java.util.Set;
import java.util.regex.Pattern;

public class SsrfPassiveRule implements ScanRule {

    private static final Set<String> SSRF_PARAMS = Set.of(
        "url", "uri", "path", "src", "source", "href", "link",
        "fetch", "load", "file", "document", "page", "host",
        "endpoint", "callback", "webhook", "proxy", "remote"
    );

    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://|file://|ftp://|//", Pattern.CASE_INSENSITIVE
    );

    private static final Pattern INTERNAL_IP = Pattern.compile(
        "(localhost|127\\.0\\.0\\.1|169\\.254\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)",
        Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getName() { return "SSRF (Passive)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.HIGH; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String rawReq = HttpUtil.toRaw(request);
        String rawResp = HttpUtil.toRaw(response);

        for (HttpParameter param : request.parameters()) {
            String name = param.name().toLowerCase();
            String value = param.value();

            if (SSRF_PARAMS.contains(name) && URL_PATTERN.matcher(value).find()) {
                FindingEntry.Severity sev;
                String detail;
                if (INTERNAL_IP.matcher(value).find()) {
                    sev = FindingEntry.Severity.HIGH;
                    detail = "SSRF param '" + param.name() + "' points to internal/loopback address: " + value;
                } else {
                    sev = FindingEntry.Severity.MEDIUM;
                    detail = "Potential SSRF: param '" + param.name() + "' contains URL: " + value;
                }
                findings.add(new FindingEntry(
                    entryId, request.url(), request.method(), request.httpService().host(),
                    getName(), sev, FindingEntry.ScanType.PASSIVE,
                    detail, value, ts, rawReq, rawResp
                ));
            }
        }
        return findings;
    }

    @Override
    public List<FindingEntry> activeCheck(int entryId, HttpRequest request, ActiveRequester requester) {
        return List.of();
    }
}
