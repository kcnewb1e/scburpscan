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

public class OpenRedirectPassiveRule implements ScanRule {

    private static final Set<String> REDIRECT_PARAMS = Set.of(
        "redirect", "redirect_to", "redirect_url", "redirecturl", "return",
        "return_to", "returnurl", "next", "url", "goto", "target", "dest",
        "destination", "redir", "location", "continue", "forward"
    );

    private static final Pattern EXTERNAL_URL = Pattern.compile(
        "^(https?:)?//(?!localhost)[a-zA-Z0-9]", Pattern.CASE_INSENSITIVE
    );

    @Override
    public String getName() { return "Open Redirect (Passive)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.MEDIUM; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        String rawReq = HttpUtil.toRaw(request);
        String rawResp = HttpUtil.toRaw(response);

        for (HttpParameter param : request.parameters()) {
            if (REDIRECT_PARAMS.contains(param.name().toLowerCase())) {
                String value = param.value();
                if (EXTERNAL_URL.matcher(value).find()) {
                    findings.add(new FindingEntry(
                        entryId, request.url(), request.method(), request.httpService().host(),
                        getName(), getSeverity(), FindingEntry.ScanType.PASSIVE,
                        "Redirect param '" + param.name() + "' points to external URL: " + value,
                        value, ts, rawReq, rawResp
                    ));
                }
            }
        }

        if (response != null) {
            String location = response.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase("Location"))
                .map(h -> h.value())
                .findFirst().orElse(null);

            if (location != null && EXTERNAL_URL.matcher(location).find()) {
                String host = request.httpService().host();
                if (!location.contains(host)) {
                    findings.add(new FindingEntry(
                        entryId, request.url(), request.method(), host,
                        getName(), getSeverity(), FindingEntry.ScanType.PASSIVE,
                        "Response redirects to external domain via Location header",
                        "Location: " + location, ts, rawReq, rawResp
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
}
