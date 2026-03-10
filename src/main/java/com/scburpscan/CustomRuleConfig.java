package com.scburpscan;

import java.util.List;

/**
 * POJO mapping a custom rule JSON file.
 * Parsed by Gson — field names must match JSON keys exactly.
 *
 * Minimal example (passive):
 * {
 *   "name": "My Rule",
 *   "severity": "MEDIUM",
 *   "description": "What this detects",
 *   "passive": {
 *     "bodyPatterns": ["(?i)debug\\s*=\\s*true"]
 *   }
 * }
 */
public class CustomRuleConfig {

    public String name;
    public String severity;      // HIGH | MEDIUM | LOW | INFO
    public String description;

    public PassiveConfig passive; // null → no passive check
    public ActiveConfig  active;  // null → no active check

    // ── Passive ──────────────────────────────────────────────────────

    public static class PassiveConfig {
        /**
         * List of regex patterns matched against the response body.
         * A match triggers a finding.
         */
        public List<String> bodyPatterns;

        /**
         * List of response header patterns, format: "Header-Name: regex"
         * e.g. "Server: (?i)apache/1\\."
         * Match triggers a finding.
         */
        public List<String> headerPatterns;

        /**
         * If true, check whether any request parameter value is reflected
         * verbatim in the response body (min 4 chars).
         */
        public boolean paramReflection;
    }

    // ── Active ────────────────────────────────────────────────────────

    public static class ActiveConfig {
        /**
         * Payloads to inject into each parameter.
         */
        public List<String> payloads;

        /**
         * If true, payload is appended to the existing parameter value.
         * If false (default), payload replaces the value entirely.
         */
        public boolean appendToValue;

        /**
         * Regex patterns checked against the fuzzed response body.
         * Any match = finding.
         */
        public List<String> detectInBody;

        /**
         * Header patterns checked in fuzzed response, same format as
         * passive.headerPatterns.
         */
        public List<String> detectInHeaders;

        /**
         * If set, finding is triggered when response status equals this value.
         * e.g. 500 for server errors, 200 for always-reflect.
         * Use 0 or omit to disable.
         */
        public int detectStatusCode;
    }
}
