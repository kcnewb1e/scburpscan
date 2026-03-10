package com.scburpscan.rules;

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
import java.util.stream.Collectors;

public class SecurityHeadersPassiveRule implements ScanRule {

    private record HeaderCheck(String header, String detail) {}

    private static final List<HeaderCheck> REQUIRED_HEADERS = List.of(
        new HeaderCheck("X-Content-Type-Options", "Missing X-Content-Type-Options: nosniff — allows MIME sniffing attacks"),
        new HeaderCheck("X-Frame-Options", "Missing X-Frame-Options — page may be embeddable (Clickjacking risk)"),
        new HeaderCheck("Content-Security-Policy", "Missing Content-Security-Policy — no XSS protection policy"),
        new HeaderCheck("Strict-Transport-Security", "Missing HSTS — connection may be downgraded to HTTP"),
        new HeaderCheck("Permissions-Policy", "Missing Permissions-Policy header")
    );

    @Override
    public String getName() { return "Missing Security Headers (Passive)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.LOW; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        if (response == null) return findings;

        String contentType = response.headers().stream()
            .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
            .map(h -> h.value())
            .findFirst().orElse("");
        if (!contentType.contains("text/html")) return findings;

        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String rawReq = HttpUtil.toRaw(request);
        String rawResp = HttpUtil.toRaw(response);

        Set<String> presentHeaders = response.headers().stream()
            .map(h -> h.name().toLowerCase())
            .collect(Collectors.toSet());

        for (HeaderCheck check : REQUIRED_HEADERS) {
            if (!presentHeaders.contains(check.header().toLowerCase())) {
                findings.add(new FindingEntry(
                    entryId, request.url(), request.method(), request.httpService().host(),
                    getName() + " - " + check.header(), FindingEntry.Severity.LOW,
                    FindingEntry.ScanType.PASSIVE,
                    check.detail(),
                    "Header not present: " + check.header(), ts, rawReq, rawResp
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
