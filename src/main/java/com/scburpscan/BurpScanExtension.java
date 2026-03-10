package com.scburpscan;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import java.awt.*;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public class BurpScanExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("SCBurpScan v1.0");

        List<FindingEntry> findings = new CopyOnWriteArrayList<>();
        AtomicInteger counter = new AtomicInteger(0);

        ScanEngine engine = new ScanEngine(api, findings);
        HttpScanHandler handler = new HttpScanHandler(api, engine, counter);
        ScannerTab scannerTab = new ScannerTab(api, findings, engine, handler);
        SettingsPanel settingsPanel = new SettingsPanel(api, engine);
        engine.setOnNewFinding(scannerTab::refresh);

        // Wrap scanner + settings in a top-level tabbed pane
        JTabbedPane root = new JTabbedPane(JTabbedPane.TOP);
        root.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        root.addTab("Scanner",  scannerTab);
        root.addTab("Settings", settingsPanel);

        api.http().registerHttpHandler(handler);
        api.userInterface().registerSuiteTab("SCBurpScan", root);
        api.extension().registerUnloadingHandler(scannerTab::shutdown);

        api.logging().logToOutput("SCBurpScan v1.0 loaded.");
    }
}
