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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class SensitiveInfoPassiveRule implements ScanRule {

    private record InfoPattern(String name, Pattern pattern, FindingEntry.Severity severity) {}

    private static final List<InfoPattern> PATTERNS = List.of(
        new InfoPattern("AWS Access Key", Pattern.compile("AKIA[0-9A-Z]{16}"), FindingEntry.Severity.HIGH),
        new InfoPattern("AWS Secret Key", Pattern.compile("(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"), FindingEntry.Severity.HIGH),
        new InfoPattern("Google API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}"), FindingEntry.Severity.HIGH),
        new InfoPattern("JWT Token", Pattern.compile("eyJ[A-Za-z0-9\\-_]+\\.eyJ[A-Za-z0-9\\-_]+\\.[A-Za-z0-9\\-_]+"), FindingEntry.Severity.MEDIUM),
        new InfoPattern("Private Key Header", Pattern.compile("-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----"), FindingEntry.Severity.HIGH),
        new InfoPattern("Email Address", Pattern.compile("[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}"), FindingEntry.Severity.LOW),
        new InfoPattern("Internal IP", Pattern.compile("(192\\.168\\.|10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)\\d{1,3}\\.\\d{1,3}"), FindingEntry.Severity.INFO),
        new InfoPattern("Stack Trace (Java)", Pattern.compile("at [a-zA-Z0-9.$_]+\\([a-zA-Z0-9]+\\.java:\\d+\\)"), FindingEntry.Severity.MEDIUM),
        new InfoPattern("Stack Trace (PHP)", Pattern.compile("Stack trace:|Fatal error:"), FindingEntry.Severity.MEDIUM),
        new InfoPattern("Generic Secret/Password", Pattern.compile("(?i)(password|secret|api_key|apikey|token)[\\s]*[=:][\\s]*['\"]?[^\\s'\"<>]{8,}"), FindingEntry.Severity.MEDIUM)
    );

    @Override
    public String getName() { return "Sensitive Information Disclosure (Passive)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.MEDIUM; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        if (response == null) return findings;

        String body = response.bodyToString();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String rawReq = HttpUtil.toRaw(request);
        String rawResp = HttpUtil.toRaw(response);

        for (InfoPattern info : PATTERNS) {
            Matcher m = info.pattern().matcher(body);
            if (m.find()) {
                String match = m.group();
                if (match.length() > 60) match = match.substring(0, 60) + "...";
                findings.add(new FindingEntry(
                    entryId, request.url(), request.method(), request.httpService().host(),
                    getName() + " - " + info.name(), info.severity(), FindingEntry.ScanType.PASSIVE,
                    info.name() + " pattern detected in response body",
                    "Matched: " + match, ts, rawReq, rawResp
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
