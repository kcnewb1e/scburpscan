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

public class SqliActiveRule implements ScanRule {

    private static final List<String> PAYLOADS = List.of(
        "'", "\"", "1'", "1\"", "' OR '1'='1", "' OR 1=1--",
        "1 AND 1=2--", "'; SELECT SLEEP(0)--"
    );

    private static final List<Pattern> ERROR_PATTERNS = List.of(
        Pattern.compile("you have an error in your sql syntax", Pattern.CASE_INSENSITIVE),
        Pattern.compile("warning: mysql", Pattern.CASE_INSENSITIVE),
        Pattern.compile("unclosed quotation mark", Pattern.CASE_INSENSITIVE),
        Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ora-[0-9]{4,5}:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("pg::syntaxerror", Pattern.CASE_INSENSITIVE),
        Pattern.compile("sqlite_error", Pattern.CASE_INSENSITIVE),
        Pattern.compile("microsoft ole db provider for sql server", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public String getName() { return "SQL Injection (Active - Error Based)"; }

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

        outer:
        for (HttpParameter param : request.parameters()) {
            if (param.type() == HttpParameterType.COOKIE) continue;

            for (String payload : PAYLOADS) {
                HttpRequest fuzzed = request.withUpdatedParameters(
                    burp.api.montoya.http.message.params.HttpParameter.parameter(
                        param.name(), param.value() + payload, param.type()
                    )
                );
                try {
                    HttpResponse resp = requester.send(fuzzed);
                    if (resp == null) continue;
                    String body = resp.bodyToString();

                    for (Pattern pattern : ERROR_PATTERNS) {
                        if (pattern.matcher(body).find()) {
                            findings.add(new FindingEntry(
                                entryId, request.url(), request.method(), request.httpService().host(),
                                getName(), getSeverity(), FindingEntry.ScanType.ACTIVE,
                                "SQLi error triggered in param '" + param.name() + "' with payload: " + payload,
                                pattern.pattern(), ts,
                                HttpUtil.toRaw(fuzzed), HttpUtil.toRaw(resp)
                            ));
                            continue outer;
                        }
                    }
                } catch (Exception ignored) {}
            }
        }
        return findings;
    }
}
