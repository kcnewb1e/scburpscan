package com.scburpscan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;

public class ScannerTab extends JPanel {

    // ── Palette ──────────────────────────────────────────────────────
    private static final Color BG           = new Color(245, 245, 247);
    private static final Color TOOLBAR_BG   = new Color(237, 237, 242);
    private static final Color PANEL_BG     = new Color(252, 252, 254);
    private static final Color BORDER_COLOR = new Color(210, 210, 218);
    private static final Color TEXT_MAIN    = new Color(40,  40,  50);
    private static final Color TEXT_MUTED   = new Color(120, 120, 135);
    private static final Color MONO_BG      = new Color(30,  32,  40);
    private static final Color MONO_FG      = new Color(208, 213, 221);

    private static final Color SEV_HIGH   = new Color(242, 210, 210);
    private static final Color SEV_MEDIUM = new Color(250, 235, 195);
    private static final Color SEV_LOW    = new Color(210, 230, 220);
    private static final Color SEV_INFO   = new Color(210, 222, 242);

    private static final Font  FONT_UI    = new Font("Segoe UI", Font.PLAIN, 12);
    private static final Font  FONT_BOLD  = new Font("Segoe UI", Font.BOLD,  12);
    private static final Font  FONT_MONO  = new Font("JetBrains Mono", Font.PLAIN, 12);

    // ── State ─────────────────────────────────────────────────────────
    private final MontoyaApi api;
    private final List<FindingEntry> findings;
    private final ScanEngine engine;
    private final HttpScanHandler scanHandler;

    private FindingsTableModel tableModel;
    private JTable table;
    private JToggleButton activeToggle;
    private JToggleButton scopeToggle;
    private JLabel findingCount;

    // Detail pane
    private final JEditorPane infoPane   = makeInfoPane();
    private final JTextArea   requestArea  = makeMonoArea();
    private final JTextArea   responseArea = makeMonoArea();

    public ScannerTab(MontoyaApi api, List<FindingEntry> findings,
                      ScanEngine engine, HttpScanHandler scanHandler) {
        this.api = api;
        this.findings = findings;
        this.engine = engine;
        this.scanHandler = scanHandler;

        setLayout(new BorderLayout(0, 0));
        setBackground(BG);

        add(buildToolbar(), BorderLayout.NORTH);

        // Table model
        tableModel = new FindingsTableModel(findings);
        table = buildTable();
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showDetail();
        });

        JSplitPane main = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
            wrapScroll(table, "Issues"),
            buildRightPane()
        );
        main.setResizeWeight(0.40);
        main.setDividerSize(5);
        main.setBorder(null);
        main.setBackground(BG);

        add(main, BorderLayout.CENTER);
    }

    // ── Toolbar ───────────────────────────────────────────────────────

    private JPanel buildToolbar() {
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 5));
        bar.setBackground(TOOLBAR_BG);
        bar.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_COLOR));

        activeToggle = styledToggle("○  Active Scan");
        activeToggle.addActionListener(e -> {
            boolean on = activeToggle.isSelected();
            engine.setActiveScanEnabled(on);
            activeToggle.setText(on ? "●  Active Scan" : "○  Active Scan");
            applyToggleState(activeToggle, on,
                new Color(252, 242, 240), new Color(160, 60, 50));
        });

        scopeToggle = styledToggle("○  In-Scope Only");
        scopeToggle.addActionListener(e -> {
            boolean on = scopeToggle.isSelected();
            scanHandler.setInScopeOnly(on);
            scopeToggle.setText(on ? "●  In-Scope Only" : "○  In-Scope Only");
            applyToggleState(scopeToggle, on,
                new Color(238, 248, 240), new Color(35, 110, 60));
        });

        JButton clearBtn = styledButton("Clear");
        JButton copyBtn  = styledButton("Copy Selected");

        findingCount = new JLabel("0 findings");
        findingCount.setFont(FONT_BOLD);
        findingCount.setForeground(TEXT_MUTED);

        // Wire actions after detail components exist
        clearBtn.addActionListener(e -> {
            engine.clearFindings();
            tableModel.fireTableDataChanged();
            clearDetail();
            updateCount();
        });
        copyBtn.addActionListener(e -> copySelected());

        bar.add(activeToggle);
        bar.add(sep());
        bar.add(scopeToggle);
        bar.add(sep());
        bar.add(clearBtn);
        bar.add(copyBtn);
        bar.add(Box.createHorizontalStrut(12));
        bar.add(findingCount);
        return bar;
    }

    // ── Table ─────────────────────────────────────────────────────────

    private JTable buildTable() {
        JTable t = new JTable(tableModel);
        t.setFont(FONT_UI);
        t.setBackground(PANEL_BG);
        t.setForeground(TEXT_MAIN);
        t.setGridColor(BORDER_COLOR);
        t.setSelectionBackground(new Color(195, 210, 235));
        t.setSelectionForeground(TEXT_MAIN);
        t.setRowHeight(22);
        t.setShowHorizontalLines(true);
        t.setShowVerticalLines(false);
        t.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setDefaultRenderer(Object.class, new SeverityRenderer());

        JTableHeader header = t.getTableHeader();
        header.setFont(FONT_BOLD);
        header.setBackground(TOOLBAR_BG);
        header.setForeground(TEXT_MAIN);
        header.setBorder(new MatteBorder(0, 0, 1, 0, BORDER_COLOR));

        // Column widths: #, Sev, Type, Method, Host, Rule, Detail
        int[] widths = {38, 65, 65, 60, 175, 220, 999};
        for (int i = 0; i < widths.length && i < t.getColumnCount(); i++) {
            TableColumn col = t.getColumnModel().getColumn(i);
            col.setPreferredWidth(widths[i]);
            if (widths[i] != 999) col.setMaxWidth(widths[i] * 2);
        }

        // Right-click context menu
        t.addMouseListener(new MouseAdapter() {
            @Override public void mousePressed(MouseEvent e)  { maybePopup(e, t); }
            @Override public void mouseReleased(MouseEvent e) { maybePopup(e, t); }
        });

        return t;
    }

    private void maybePopup(MouseEvent e, JTable t) {
        if (!e.isPopupTrigger()) return;
        int row = t.rowAtPoint(e.getPoint());
        if (row < 0 || row >= findings.size()) return;
        t.setRowSelectionInterval(row, row);
        showDetail();
        buildPopupMenu(findings.get(row)).show(t, e.getX(), e.getY());
    }

    private JPopupMenu buildPopupMenu(FindingEntry f) {
        boolean hasReq  = !f.rawRequest.isBlank();
        boolean hasResp = !f.rawResponse.isBlank();

        JPopupMenu menu = new JPopupMenu();

        JMenuItem toRepeater = menuItem("Send to Repeater", hasReq, () -> {
            HttpRequest req = reconstructRequest(f);
            if (req != null) api.repeater().sendToRepeater(req);
        });

        JMenuItem toIntruder = menuItem("Send to Intruder", hasReq, () -> {
            HttpRequest req = reconstructRequest(f);
            if (req != null) api.intruder().sendToIntruder(req);
        });

        JMenuItem comparerReq = menuItem("Send Request to Comparer", hasReq, () ->
            api.comparer().sendToComparer(
                ByteArray.byteArray(f.rawRequest.getBytes(StandardCharsets.UTF_8)))
        );

        JMenuItem comparerResp = menuItem("Send Response to Comparer", hasResp, () ->
            api.comparer().sendToComparer(
                ByteArray.byteArray(f.rawResponse.getBytes(StandardCharsets.UTF_8)))
        );

        menu.add(toRepeater);
        menu.add(toIntruder);
        menu.addSeparator();
        menu.add(comparerReq);
        menu.add(comparerResp);
        return menu;
    }

    private static JMenuItem menuItem(String label, boolean enabled, Runnable action) {
        JMenuItem item = new JMenuItem(label);
        item.setEnabled(enabled);
        item.addActionListener(e -> action.run());
        return item;
    }

    private HttpRequest reconstructRequest(FindingEntry f) {
        try {
            URI uri    = new URI(f.url);
            boolean secure = "https".equalsIgnoreCase(uri.getScheme());
            int port   = uri.getPort();
            if (port == -1) port = secure ? 443 : 80;
            HttpService service = HttpService.httpService(f.host, port, secure);
            return HttpRequest.httpRequest(service,
                ByteArray.byteArray(f.rawRequest.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return null;
        }
    }

    // ── Right pane (tabs: Advisory / Request / Response) ─────────────

    private JTabbedPane buildRightPane() {
        JTabbedPane tabs = new JTabbedPane(JTabbedPane.TOP);
        tabs.setFont(FONT_UI);
        tabs.setBackground(PANEL_BG);

        // Advisory tab
        JScrollPane advisoryScroll = new JScrollPane(infoPane);
        advisoryScroll.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        advisoryScroll.setBackground(PANEL_BG);
        advisoryScroll.getViewport().setBackground(PANEL_BG);
        advisoryScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        tabs.addTab("Advisory", advisoryScroll);

        // Request / Response tabs
        tabs.addTab("Request",  wrapMonoTab(requestArea));
        tabs.addTab("Response", wrapMonoTab(responseArea));

        return tabs;
    }

    private static JScrollPane wrapMonoTab(JTextArea area) {
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(BorderFactory.createEmptyBorder(2, 2, 2, 2));
        sp.setBackground(MONO_BG);
        sp.getViewport().setBackground(MONO_BG);
        return sp;
    }

    // ── Helpers ───────────────────────────────────────────────────────

    private void showDetail() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= findings.size()) return;
        FindingEntry f = findings.get(row);

        String sevHex   = toHex(severityColor(f.severity));
        String sevBgHex = toHex(severityBg(f.severity));
        String evidence = f.evidence.isBlank() ? "" :
            "<p style='margin:8px 0 0 0;'>"
            + "<span style='color:#888;font-size:10px;'>EVIDENCE</span><br>"
            + "<code style='font-size:11px;color:#444;'>" + escHtml(f.evidence) + "</code></p>";

        infoPane.setText(
            "<html><body style='font-family:Segoe UI,sans-serif;font-size:12px;"
            + "margin:12px 14px;color:#282832;line-height:1.5;'>"

            // Severity badge + issue name
            + "<p style='margin:0 0 8px 0;'>"
            + "<span style='background:" + sevBgHex + ";color:" + sevHex + ";"
            +   "font-weight:bold;font-size:10px;padding:2px 7px;"
            +   "border:1px solid " + sevHex + ";margin-right:8px;'>"
            +   f.severity.name()
            + "</span>"
            + "<span style='font-size:10px;color:#aaa;border:1px solid #ddd;"
            +   "padding:2px 6px;'>" + f.scanType.name() + "</span>"
            + "</p>"

            // Issue title
            + "<p style='margin:0 0 10px 0;font-size:13px;font-weight:bold;color:#1a1a2e;'>"
            + escHtml(f.ruleName) + "</p>"

            // Meta grid
            + "<table cellpadding='0' cellspacing='0' style='margin-bottom:10px;'>"
            + metaRow("Host", f.host)
            + metaRow("URL",  f.url)
            + metaRow("Method", f.method)
            + metaRow("Detected", f.timestamp)
            + "</table>"

            + "<hr style='border:none;border-top:1px solid #e0e0e8;margin:0 0 10px 0;'>"

            // Detail
            + "<p style='margin:0;color:#333;'>" + escHtml(f.detail) + "</p>"
            + evidence

            + "</body></html>"
        );
        infoPane.setCaretPosition(0);

        requestArea.setText(f.rawRequest.isBlank() ? "(no request captured)" : f.rawRequest);
        requestArea.setCaretPosition(0);
        responseArea.setText(f.rawResponse.isBlank() ? "(no response captured)" : f.rawResponse);
        responseArea.setCaretPosition(0);
    }

    private void clearDetail() {
        infoPane.setText("");
        requestArea.setText("");
        responseArea.setText("");
    }

    private static String metaRow(String label, String value) {
        return "<tr>"
            + "<td style='color:#888;font-size:11px;padding-right:12px;"
            +   "white-space:nowrap;vertical-align:top;'>" + label + "</td>"
            + "<td style='font-size:11px;color:#444;word-break:break-all;'>"
            + escHtml(value) + "</td>"
            + "</tr>";
    }

    private static String escHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String toHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static Color severityBg(FindingEntry.Severity s) {
        return switch (s) {
            case HIGH   -> new Color(253, 243, 243);
            case MEDIUM -> new Color(255, 250, 238);
            case LOW    -> new Color(242, 250, 244);
            case INFO   -> new Color(240, 245, 255);
        };
    }

    public void refresh() {
        SwingUtilities.invokeLater(() -> {
            tableModel.fireTableDataChanged();
            updateCount();
        });
    }

    public void shutdown() {
        engine.shutdown();
    }

    private void updateCount() {
        int n = findings.size();
        findingCount.setText(n + (n == 1 ? " finding" : " findings"));
    }

    private void copySelected() {
        int row = table.getSelectedRow();
        if (row < 0 || row >= findings.size()) return;
        FindingEntry f = findings.get(row);
        String text = "[" + f.severity + "] " + f.ruleName + "\n"
            + "URL: " + f.url + "\n"
            + f.detail + "\nEvidence: " + f.evidence;
        Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new StringSelection(text), null);
    }

    // ── Widget factories ──────────────────────────────────────────────

    private static JTextArea makeMonoArea() {
        JTextArea a = new JTextArea();
        a.setEditable(false);
        a.setFont(pickMonoFont());
        a.setBackground(MONO_BG);
        a.setForeground(MONO_FG);
        a.setCaretColor(MONO_FG);
        a.setSelectionColor(new Color(70, 90, 120));
        a.setSelectedTextColor(MONO_FG);
        a.setLineWrap(false);
        return a;
    }

    private static Font pickMonoFont() {
        for (String name : new String[]{"JetBrains Mono", "Consolas", "Menlo", "DejaVu Sans Mono"}) {
            Font f = new Font(name, Font.PLAIN, 12);
            if (f.getFamily().equalsIgnoreCase(name)) return f;
        }
        return new Font(Font.MONOSPACED, Font.PLAIN, 12);
    }

    private static JScrollPane wrapMonoScroll(JTextArea area, String title) {
        JScrollPane sp = new JScrollPane(area);
        sp.setBorder(new CompoundBorder(
            new MatteBorder(0, 0, 0, 0, BORDER_COLOR),
            BorderFactory.createEmptyBorder(0, 0, 0, 0)
        ));
        sp.setBackground(MONO_BG);
        sp.getViewport().setBackground(MONO_BG);

        TitledBorder tb = BorderFactory.createTitledBorder(
            new MatteBorder(1, 1, 1, 1, new Color(60, 65, 80)),
            title
        );
        tb.setTitleFont(FONT_BOLD);
        tb.setTitleColor(new Color(160, 170, 190));
        sp.setBorder(tb);
        return sp;
    }

    private static JScrollPane wrapScroll(JTable t, String title) {
        JScrollPane sp = new JScrollPane(t);
        TitledBorder tb = BorderFactory.createTitledBorder(
            new MatteBorder(1, 1, 1, 1, BORDER_COLOR), title
        );
        tb.setTitleFont(FONT_BOLD);
        tb.setTitleColor(TEXT_MUTED);
        sp.setBorder(tb);
        sp.setBackground(PANEL_BG);
        return sp;
    }

    private static JToggleButton styledToggle(String text) {
        JToggleButton b = new JToggleButton(text, false);
        b.setFont(FONT_UI);
        b.setFocusPainted(false);
        b.setContentAreaFilled(false);  // we paint background manually
        b.setOpaque(true);
        b.setBackground(TOOLBAR_BG);
        b.setForeground(TEXT_MUTED);
        b.setBorder(new CompoundBorder(
            new MatteBorder(1, 1, 1, 1, BORDER_COLOR),
            BorderFactory.createEmptyBorder(3, 10, 3, 10)
        ));
        return b;
    }

    private static void applyToggleState(JToggleButton b, boolean on,
                                         Color activeBg, Color activeFg) {
        b.setBackground(on ? activeBg : TOOLBAR_BG);
        b.setForeground(on ? activeFg : TEXT_MUTED);
        b.setFont(FONT_UI);
        b.setBorder(new CompoundBorder(
            new MatteBorder(1, 1, 1, 1, on ? activeFg.brighter() : BORDER_COLOR),
            BorderFactory.createEmptyBorder(3, 10, 3, 10)
        ));
    }

    private static JEditorPane makeInfoPane() {
        JEditorPane p = new JEditorPane("text/html", "");
        p.setEditable(false);
        p.setOpaque(true);
        p.setBackground(PANEL_BG);
        p.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        p.setFont(FONT_UI);
        return p;
    }

    private static JButton styledButton(String text) {
        JButton b = new JButton(text);
        b.setFont(FONT_UI);
        b.setFocusPainted(false);
        b.setBackground(TOOLBAR_BG);
        b.setForeground(TEXT_MAIN);
        b.setBorder(new CompoundBorder(
            new MatteBorder(1, 1, 1, 1, BORDER_COLOR),
            BorderFactory.createEmptyBorder(3, 8, 3, 8)
        ));
        return b;
    }

    private static JSeparator sep() {
        JSeparator s = new JSeparator(JSeparator.VERTICAL);
        s.setPreferredSize(new Dimension(1, 20));
        s.setForeground(BORDER_COLOR);
        return s;
    }

    private static Color severityColor(FindingEntry.Severity s) {
        return switch (s) {
            case HIGH   -> new Color(180, 60,  60);
            case MEDIUM -> new Color(170, 110, 20);
            case LOW    -> new Color(40,  130, 70);
            case INFO   -> new Color(50,  90,  170);
        };
    }

    // ── Table model ───────────────────────────────────────────────────

    private static class FindingsTableModel extends AbstractTableModel {
        final List<FindingEntry> findings;
        private static final String[] COLS = {"#", "Severity", "Type", "Method", "Host", "Rule", "Detail"};

        FindingsTableModel(List<FindingEntry> findings) { this.findings = findings; }

        @Override public int getRowCount()    { return findings.size(); }
        @Override public int getColumnCount() { return COLS.length; }
        @Override public String getColumnName(int c) { return COLS[c]; }

        @Override
        public Object getValueAt(int row, int col) {
            if (row >= findings.size()) return "";
            FindingEntry f = findings.get(row);
            return switch (col) {
                case 0 -> f.id;
                case 1 -> f.severity;
                case 2 -> f.scanType;
                case 3 -> f.method;
                case 4 -> f.host;
                case 5 -> f.ruleName;
                case 6 -> f.detail;
                default -> "";
            };
        }
    }

    // ── Severity renderer ─────────────────────────────────────────────

    private static class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table, Object value,
                boolean isSelected, boolean hasFocus, int row, int col) {

            Component c = super.getTableCellRendererComponent(
                table, value, isSelected, hasFocus, row, col);

            setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));

            if (!isSelected) {
                FindingsTableModel model = (FindingsTableModel) table.getModel();
                if (row < model.findings.size()) {
                    FindingEntry f = model.findings.get(row);
                    Color bg = switch (f.severity) {
                        case HIGH   -> SEV_HIGH;
                        case MEDIUM -> SEV_MEDIUM;
                        case LOW    -> SEV_LOW;
                        case INFO   -> SEV_INFO;
                    };
                    c.setBackground(bg);
                    c.setForeground(TEXT_MAIN);

                    // Severity column: bold + colored text
                    if (col == 1) {
                        ((JLabel) c).setFont(FONT_BOLD);
                        c.setForeground(severityColor(f.severity));
                    } else {
                        ((JLabel) c).setFont(FONT_UI);
                    }
                }
            } else {
                ((JLabel) c).setFont(FONT_UI);
            }
            return c;
        }
    }
}
