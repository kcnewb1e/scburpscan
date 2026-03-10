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
import java.util.regex.Pattern;

public class PathTraversalActiveRule implements ScanRule {

    private static final List<String> PAYLOADS = List.of(
        "../../../../etc/passwd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "../../../../windows/win.ini",
        "..\\..\\..\\..\\windows\\win.ini"
    );

    private static final Pattern UNIX_PASSWD = Pattern.compile("root:[x*]?:0:0:", Pattern.CASE_INSENSITIVE);
    private static final Pattern WIN_INI = Pattern.compile("\\[fonts\\]|\\[extensions\\]", Pattern.CASE_INSENSITIVE);

    @Override
    public String getName() { return "Path Traversal (Active)"; }

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
            String val = param.value().toLowerCase();
            if (!val.contains("/") && !val.contains("\\") && !val.contains("..") &&
                !val.endsWith(".php") && !val.endsWith(".html") && !val.endsWith(".txt") &&
                !param.name().toLowerCase().matches(".*(file|path|dir|page|doc|load|include|src).*")) {
                continue;
            }

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

                    if (UNIX_PASSWD.matcher(body).find() || WIN_INI.matcher(body).find()) {
                        findings.add(new FindingEntry(
                            entryId, request.url(), request.method(), request.httpService().host(),
                            getName(), getSeverity(), FindingEntry.ScanType.ACTIVE,
                            "Path traversal succeeded in param '" + param.name() + "' with: " + payload,
                            body.substring(0, Math.min(200, body.length())), ts,
                            HttpUtil.toRaw(fuzzed), HttpUtil.toRaw(resp)
                        ));
                        break;
                    }
                } catch (Exception ignored) {}
            }
        }
        return findings;
    }
}
