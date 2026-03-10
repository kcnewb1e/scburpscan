package com.scburpscan;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * Settings tab for SCBurpScan.
 * Allows configuring a custom rules folder and reloading rules at runtime.
 */
public class SettingsPanel extends JPanel {

    private static final String PREF_KEY = "scburpscan.rulesFolder";

    private static final Color BG          = new Color(245, 245, 247);
    private static final Color PANEL_BG    = new Color(252, 252, 254);
    private static final Color TOOLBAR_BG  = new Color(237, 237, 242);
    private static final Color BORDER_CLR  = new Color(210, 210, 218);
    private static final Color TEXT_MAIN   = new Color(40,  40,  50);
    private static final Color TEXT_MUTED  = new Color(120, 120, 135);
    private static final Color TEXT_OK     = new Color(30,  120, 60);
    private static final Color TEXT_ERR    = new Color(160, 40,  40);
    private static final Font  FONT_UI     = new Font("Segoe UI", Font.PLAIN, 12);
    private static final Font  FONT_BOLD   = new Font("Segoe UI", Font.BOLD,  12);
    private static final Font  FONT_MONO   = new Font(Font.MONOSPACED, Font.PLAIN, 12);

    private final MontoyaApi api;
    private final ScanEngine engine;

    private final JTextField folderField  = new JTextField(40);
    private final JLabel     statusLabel  = new JLabel(" ");
    private final JTextArea  ruleListArea = new JTextArea();
    private final JTextArea  errorArea    = new JTextArea();

    public SettingsPanel(MontoyaApi api, ScanEngine engine) {
        this.api    = api;
        this.engine = engine;

        setLayout(new BorderLayout(0, 0));
        setBackground(BG);

        JPanel inner = new JPanel();
        inner.setLayout(new BoxLayout(inner, BoxLayout.Y_AXIS));
        inner.setBackground(BG);
        inner.setBorder(BorderFactory.createEmptyBorder(16, 20, 16, 20));

        inner.add(buildFolderSection());
        inner.add(Box.createVerticalStrut(14));
        inner.add(buildStatusSection());
        inner.add(Box.createVerticalStrut(14));
        inner.add(buildRuleListSection());
        inner.add(Box.createVerticalStrut(14));
        inner.add(buildFormatSection());

        JScrollPane scroll = new JScrollPane(inner);
        scroll.setBorder(null);
        scroll.setBackground(BG);
        scroll.getViewport().setBackground(BG);
        add(scroll, BorderLayout.CENTER);

        // Load saved folder path
        String saved = loadSavedFolder();
        if (saved != null && !saved.isBlank()) {
            folderField.setText(saved);
            reloadRules(false); // silent reload on startup
        }
    }

    // ── Folder picker section ─────────────────────────────────────────

    private JPanel buildFolderSection() {
        JPanel p = section("Custom Rules Folder");

        JLabel desc = muted("Path to a folder containing your custom *.json rule files.");
        desc.setAlignmentX(LEFT_ALIGNMENT);
        p.add(desc);
        p.add(Box.createVerticalStrut(8));

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        row.setBackground(PANEL_BG);
        row.setAlignmentX(LEFT_ALIGNMENT);

        folderField.setFont(FONT_UI);
        folderField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 28));

        JButton browseBtn = btn("Browse...");
        browseBtn.addActionListener(e -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            String current = folderField.getText().trim();
            if (!current.isEmpty()) chooser.setCurrentDirectory(new File(current));
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                folderField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        JButton reloadBtn = btn("Reload Rules");
        reloadBtn.setFont(FONT_BOLD);
        reloadBtn.addActionListener(e -> reloadRules(true));

        JButton templateBtn = btn("Write Templates");
        templateBtn.addActionListener(e -> writeTemplates());

        row.add(folderField);
        row.add(browseBtn);
        row.add(reloadBtn);
        row.add(templateBtn);
        p.add(row);

        return p;
    }

    // ── Status section ────────────────────────────────────────────────

    private JPanel buildStatusSection() {
        JPanel p = section("Status");
        statusLabel.setFont(FONT_UI);
        statusLabel.setAlignmentX(LEFT_ALIGNMENT);
        p.add(statusLabel);

        errorArea.setEditable(false);
        errorArea.setFont(FONT_MONO);
        errorArea.setForeground(TEXT_ERR);
        errorArea.setBackground(new Color(255, 248, 248));
        errorArea.setLineWrap(true);
        errorArea.setWrapStyleWord(true);
        errorArea.setRows(3);
        errorArea.setVisible(false);

        JScrollPane errScroll = new JScrollPane(errorArea);
        errScroll.setBorder(new MatteBorder(1, 1, 1, 1, new Color(220, 180, 180)));
        errScroll.setAlignmentX(LEFT_ALIGNMENT);
        errScroll.setVisible(false);
        p.add(Box.createVerticalStrut(6));
        p.add(errScroll);

        // Store reference to errScroll for visibility toggle
        errorArea.putClientProperty("scrollPane", errScroll);

        return p;
    }

    // ── Loaded rules list ─────────────────────────────────────────────

    private JPanel buildRuleListSection() {
        JPanel p = section("Loaded Custom Rules");

        ruleListArea.setEditable(false);
        ruleListArea.setFont(FONT_MONO);
        ruleListArea.setBackground(new Color(248, 248, 252));
        ruleListArea.setForeground(TEXT_MAIN);
        ruleListArea.setRows(6);
        ruleListArea.setText("(no rules loaded)");

        JScrollPane scroll = new JScrollPane(ruleListArea);
        scroll.setBorder(new MatteBorder(1, 1, 1, 1, BORDER_CLR));
        scroll.setAlignmentX(LEFT_ALIGNMENT);
        p.add(scroll);
        return p;
    }

    // ── Format reference section ──────────────────────────────────────

    private JPanel buildFormatSection() {
        JPanel p = section("Rule File Format Reference");

        JLabel desc = muted("Each .json file in your rules folder defines one rule. "
            + "Files starting with _template are skipped. "
            + "Click 'Write Templates' to generate ready-to-edit examples in your folder.");
        desc.setAlignmentX(LEFT_ALIGNMENT);
        p.add(desc);
        p.add(Box.createVerticalStrut(8));

        JTextArea ref = new JTextArea(FORMAT_REFERENCE);
        ref.setEditable(false);
        ref.setFont(FONT_MONO);
        ref.setBackground(new Color(30, 32, 40));
        ref.setForeground(new Color(200, 210, 220));
        ref.setRows(26);
        ref.setLineWrap(false);

        JScrollPane scroll = new JScrollPane(ref);
        scroll.setBorder(new MatteBorder(1, 1, 1, 1, new Color(60, 65, 80)));
        scroll.setAlignmentX(LEFT_ALIGNMENT);
        p.add(scroll);
        return p;
    }

    // ── Logic ─────────────────────────────────────────────────────────

    private void reloadRules(boolean verbose) {
        String folder = folderField.getText().trim();
        if (folder.isEmpty()) {
            if (verbose) setStatus("Set a folder path first.", false);
            return;
        }

        saveFolder(folder);
        Path path = Paths.get(folder);
        CustomRuleLoader.LoadResult result = CustomRuleLoader.load(path);

        engine.setCustomRules(result.rules());

        // Update rule list display
        if (result.rules().isEmpty()) {
            ruleListArea.setText("(no valid rules found)");
        } else {
            StringBuilder sb = new StringBuilder();
            for (ScanRule r : result.rules()) {
                sb.append("  ✓  ").append(r.getName())
                  .append("  [").append(r.getSeverity()).append("]\n");
            }
            ruleListArea.setText(sb.toString().trim());
        }

        // Error display
        JScrollPane errScroll = (JScrollPane) errorArea.getClientProperty("scrollPane");
        if (result.errors().isEmpty()) {
            errorArea.setText("");
            errorArea.setVisible(false);
            if (errScroll != null) errScroll.setVisible(false);
        } else {
            errorArea.setText(String.join("\n", result.errors()));
            errorArea.setVisible(true);
            if (errScroll != null) errScroll.setVisible(true);
        }

        setStatus(result.rules().size() + " custom rule(s) loaded from " + folder
            + (result.errors().isEmpty() ? "" : "  (" + result.errors().size() + " error(s))"),
            result.errors().isEmpty());

        revalidate();
    }

    private void writeTemplates() {
        String folder = folderField.getText().trim();
        if (folder.isEmpty()) {
            setStatus("Set a folder path first.", false);
            return;
        }
        CustomRuleLoader.writeTemplates(Paths.get(folder));
        setStatus("Templates written to: " + folder, true);
    }

    private void setStatus(String msg, boolean ok) {
        statusLabel.setText(msg);
        statusLabel.setForeground(ok ? TEXT_OK : TEXT_ERR);
    }

    private void saveFolder(String path) {
        try {
            api.persistence().preferences().setString(PREF_KEY, path);
        } catch (Exception ignored) {}
    }

    private String loadSavedFolder() {
        try {
            return api.persistence().preferences().getString(PREF_KEY);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Swing helpers ─────────────────────────────────────────────────

    private JPanel section(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setBackground(PANEL_BG);
        p.setAlignmentX(LEFT_ALIGNMENT);

        TitledBorder tb = BorderFactory.createTitledBorder(
            new MatteBorder(1, 1, 1, 1, BORDER_CLR), title
        );
        tb.setTitleFont(FONT_BOLD);
        tb.setTitleColor(TEXT_MUTED);
        p.setBorder(new CompoundBorder(tb,
            BorderFactory.createEmptyBorder(8, 10, 10, 10)));
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        return p;
    }

    private static JLabel muted(String text) {
        JLabel l = new JLabel("<html>" + text + "</html>");
        l.setFont(FONT_UI);
        l.setForeground(TEXT_MUTED);
        return l;
    }

    private static JButton btn(String text) {
        JButton b = new JButton(text);
        b.setFont(FONT_UI);
        b.setFocusPainted(false);
        b.setBackground(TOOLBAR_BG);
        b.setForeground(TEXT_MAIN);
        b.setBorder(new CompoundBorder(
            new MatteBorder(1, 1, 1, 1, BORDER_CLR),
            BorderFactory.createEmptyBorder(3, 10, 3, 10)
        ));
        return b;
    }

    // ── Format reference (shown inline) ──────────────────────────────

    private static final String FORMAT_REFERENCE = """
  Minimal passive rule (body pattern):
  ──────────────────────────────────────────────────────────
  {
    "name": "Debug Mode Exposed",
    "severity": "MEDIUM",
    "description": "Debug info found in response",
    "passive": {
      "bodyPatterns": ["(?i)debug\\\\s*=\\\\s*true"]
    }
  }

  Minimal active rule (fuzzing):
  ──────────────────────────────────────────────────────────
  {
    "name": "Custom XSS",
    "severity": "HIGH",
    "description": "Tests custom XSS payloads",
    "active": {
      "payloads": ["<img/src=x onerror=confirm(1)>"],
      "appendToValue": false,
      "detectInBody": ["onerror=confirm"]
    }
  }

  All fields:
  ──────────────────────────────────────────────────────────
  {
    "name"        : "Rule display name",
    "severity"    : "HIGH | MEDIUM | LOW | INFO",
    "description" : "Shown in Advisory panel",

    "passive": {
      "bodyPatterns"   : ["java-regex-1", "java-regex-2"],
      "headerPatterns" : ["Header-Name: java-regex"],
      "paramReflection": false
    },

    "active": {
      "payloads"         : ["payload1", "payload2"],
      "appendToValue"    : false,
      "detectInBody"     : ["java-regex"],
      "detectInHeaders"  : ["Header-Name: java-regex"],
      "detectStatusCode" : 500
    }
  }

  Notes:
    • bodyPatterns   — matched against full response body (Java regex)
    • headerPatterns — format "Header-Name: regex" e.g. "Server: (?i)nginx"
    • appendToValue  — true: param=original+payload | false: param=payload
    • detectStatusCode — set to 0 or omit to disable status check
    • Files starting with _template are ignored
    • Reload without restarting Burp via "Reload Rules" button
""";
}
