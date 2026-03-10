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
import java.util.regex.Pattern;

public class SqliPassiveRule implements ScanRule {

    private static final List<Pattern> ERROR_PATTERNS = List.of(
        Pattern.compile("you have an error in your sql syntax", Pattern.CASE_INSENSITIVE),
        Pattern.compile("warning: mysql", Pattern.CASE_INSENSITIVE),
        Pattern.compile("unclosed quotation mark after the character string", Pattern.CASE_INSENSITIVE),
        Pattern.compile("quoted string not properly terminated", Pattern.CASE_INSENSITIVE),
        Pattern.compile("microsoft ole db provider for sql server", Pattern.CASE_INSENSITIVE),
        Pattern.compile("odbc sql server driver", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ora-[0-9]{4,5}:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("pg::syntaxerror", Pattern.CASE_INSENSITIVE),
        Pattern.compile("sqlite_error", Pattern.CASE_INSENSITIVE),
        Pattern.compile("syntax error.*near", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public String getName() { return "SQL Injection (Passive - Error Detection)"; }

    @Override
    public FindingEntry.Severity getSeverity() { return FindingEntry.Severity.HIGH; }

    @Override
    public List<FindingEntry> passiveCheck(int entryId, HttpRequest request, HttpResponse response) {
        List<FindingEntry> findings = new ArrayList<>();
        if (response == null) return findings;

        String body = response.bodyToString();
        String ts = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);

        for (Pattern pattern : ERROR_PATTERNS) {
            var matcher = pattern.matcher(body);
            if (matcher.find()) {
                findings.add(new FindingEntry(
                    entryId, request.url(), request.method(), request.httpService().host(),
                    getName(), getSeverity(), FindingEntry.ScanType.PASSIVE,
                    "SQL error message detected in response — possible SQLi vulnerability",
                    "Matched: " + matcher.group(), ts,
                    HttpUtil.toRaw(request), HttpUtil.toRaw(response)
                ));
                break;
            }
        }
        return findings;
    }

    @Override
    public List<FindingEntry> activeCheck(int entryId, HttpRequest request, ActiveRequester requester) {
        return List.of();
    }
}
