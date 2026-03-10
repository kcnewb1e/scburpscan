package com.scburpscan;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;

public class HttpUtil {

    public static String toRaw(HttpRequest req) {
        if (req == null) return "(no request)";
        try {
            return new String(req.toByteArray().getBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return req.toString();
        }
    }

    public static String toRaw(HttpResponse resp) {
        if (resp == null) return "(no response)";
        try {
            return new String(resp.toByteArray().getBytes(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return resp.toString();
        }
    }
}
