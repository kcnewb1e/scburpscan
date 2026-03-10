package com.scburpscan;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads custom rules from a directory of *.json files.
 * Also writes example template files on first setup.
 */
public class CustomRuleLoader {

    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();

    /** Load all valid *.json files from folder as ScanRule instances. */
    public static LoadResult load(Path folder) {
        List<ScanRule> rules  = new ArrayList<>();
        List<String>   errors = new ArrayList<>();

        if (!Files.isDirectory(folder)) {
            errors.add("Folder not found: " + folder);
            return new LoadResult(rules, errors);
        }

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder, "*.json")) {
            for (Path file : stream) {
                String fileName = file.getFileName().toString();
                // Skip template files
                if (fileName.startsWith("_template")) continue;

                try {
                    String json = Files.readString(file, StandardCharsets.UTF_8);
                    CustomRuleConfig config = GSON.fromJson(json, CustomRuleConfig.class);

                    if (config == null) {
                        errors.add(fileName + ": empty or unparseable");
                        continue;
                    }
                    if (config.name == null || config.name.isBlank()) {
                        errors.add(fileName + ": missing 'name' field");
                        continue;
                    }
                    if (config.passive == null && config.active == null) {
                        errors.add(fileName + ": must have at least 'passive' or 'active' section");
                        continue;
                    }
                    rules.add(new CustomRule(config));
                } catch (JsonSyntaxException e) {
                    errors.add(fileName + ": JSON syntax error — " + e.getMessage());
                } catch (IOException e) {
                    errors.add(fileName + ": read error — " + e.getMessage());
                }
            }
        } catch (IOException e) {
            errors.add("Cannot read folder: " + e.getMessage());
        }

        return new LoadResult(rules, errors);
    }

    /** Write template files into the folder (skips if already exist). */
    public static void writeTemplates(Path folder) {
        try {
            Files.createDirectories(folder);
        } catch (IOException e) {
            return;
        }
        writeIfAbsent(folder.resolve("_template_passive.json"), PASSIVE_TEMPLATE);
        writeIfAbsent(folder.resolve("_template_active.json"),  ACTIVE_TEMPLATE);
        writeIfAbsent(folder.resolve("_template_combined.json"), COMBINED_TEMPLATE);
        writeIfAbsent(folder.resolve("README.txt"), README);
    }

    private static void writeIfAbsent(Path path, String content) {
        if (Files.exists(path)) return;
        try {
            Files.writeString(path, content, StandardCharsets.UTF_8);
        } catch (IOException ignored) {}
    }

    public record LoadResult(List<ScanRule> rules, List<String> errors) {}

    // ── Templates ─────────────────────────────────────────────────────

    private static final String PASSIVE_TEMPLATE = """
{
  "_comment": "PASSIVE RULE TEMPLATE — rename this file (remove _template prefix) to activate.",

  "name": "Debug Mode Enabled",
  "severity": "MEDIUM",
  "description": "Detects when application debug mode is exposed in the response.",

  "passive": {

    "bodyPatterns": [
      "(?i)debug\\\\s*=\\\\s*true",
      "(?i)APP_DEBUG.*=.*true",
      "(?i)Traceback \\\\(most recent call",
      "(?i)Fatal error:.*on line \\\\d+"
    ],

    "headerPatterns": [
      "X-Powered-By: (?i)PHP/[45]\\\\.",
      "Server: (?i)apache/1\\\\."
    ],

    "paramReflection": false
  }
}
""";

    private static final String ACTIVE_TEMPLATE = """
{
  "_comment": "ACTIVE RULE TEMPLATE — rename this file (remove _template prefix) to activate.",

  "name": "Custom XSS Payloads",
  "severity": "HIGH",
  "description": "Tests custom XSS payloads not covered by the built-in rule.",

  "active": {

    "payloads": [
      "<img/src=x onerror=confirm(document.domain)>",
      "<details open ontoggle=alert(1)>",
      "<svg/onload=alert`1`>",
      "';alert(1);//"
    ],

    "appendToValue": false,

    "detectInBody": [
      "onerror=confirm",
      "ontoggle=alert",
      "onload=alert`1`"
    ],

    "detectInHeaders": [],

    "detectStatusCode": 0
  }
}
""";

    private static final String COMBINED_TEMPLATE = """
{
  "_comment": "COMBINED RULE TEMPLATE — has both passive and active sections.",

  "name": "Exposed .git Directory",
  "severity": "HIGH",
  "description": "Passively detects git metadata in responses; actively probes /.git/HEAD.",

  "passive": {
    "bodyPatterns": [
      "\\\\[core\\\\]",
      "ref: refs/heads/"
    ],
    "headerPatterns": [],
    "paramReflection": false
  },

  "active": {
    "payloads": [
      "/../../../.git/HEAD",
      "/.git/HEAD"
    ],
    "appendToValue": false,
    "detectInBody": [
      "ref: refs/heads/"
    ],
    "detectInHeaders": [],
    "detectStatusCode": 0
  }
}
""";

    private static final String README = """
SCBurpScan — Custom Rules Folder
=================================

Each .json file in this folder is loaded as a custom scan rule.
Files starting with "_template" are ignored (they are examples only).

To add your own rule:
  1. Copy one of the _template_*.json files.
  2. Rename it (e.g. my_custom_rule.json).
  3. Edit the fields.
  4. Click "Reload Rules" in the SCBurpScan Settings tab.

--- JSON FIELD REFERENCE ---

Required fields:
  name        (string)  Display name shown in the Findings table.
  severity    (string)  HIGH | MEDIUM | LOW | INFO
  description (string)  Shown in the Advisory panel when a finding is selected.

Optional sections (at least one required):

"passive" section — runs on every response without sending new requests:
  bodyPatterns      list of Java regex, matched against response body
  headerPatterns    list of "Header-Name: regex" strings
  paramReflection   true/false — flag if any param value is reflected in body

"active" section — runs only when Active Scan is toggled ON:
  payloads          list of strings to inject into each parameter
  appendToValue     true = append payload to existing value; false = replace
  detectInBody      list of Java regex checked in the fuzzed response body
  detectInHeaders   list of "Header-Name: regex" for fuzzed response headers
  detectStatusCode  integer — trigger if response status matches (0 = disabled)

--- REGEX TIPS ---

Java regex — remember to double-escape backslashes in JSON:
  \\d+       matches one or more digits
  (?i)foo    case-insensitive match
  foo|bar    alternation

Test your regex at: https://regex101.com  (select Java 8 flavor)
""";
}
