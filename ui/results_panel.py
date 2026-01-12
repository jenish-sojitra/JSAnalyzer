# -*- coding: utf-8 -*-
"""
JS Analyzer - Results Panel
Features: Search filter, Copy button, Source filtering
"""

from javax.swing import (
    JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, BorderFactory
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Font, Dimension, Toolkit
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener, KeyEvent
import json


class ResultsPanel(JPanel):
    """Results panel with search filter and copy functionality."""
    
    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self.callbacks = callbacks
        self.extender = extender
        
        # Findings by category
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
        }
        
        # Unique sources
        self.sources = set()
        
        self._init_ui()
    
    def _init_ui(self):
        """Build the UI."""
        self.setLayout(BorderLayout(5, 5))
        
        # ===== HEADER =====
        header = JPanel(BorderLayout(5, 0))
        header.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Left side - Title and stats
        left_panel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        left_panel.add(JLabel("JS Analyzer"))
        
        self.stats_label = JLabel("| E:0 | U:0 | S:0 | M:0")
        self.stats_label.setFont(Font("SansSerif", Font.PLAIN, 11))
        left_panel.add(self.stats_label)
        header.add(left_panel, BorderLayout.WEST)
        
        # Right side - Controls
        controls = JPanel(FlowLayout(FlowLayout.RIGHT, 5, 0))
        
        # Search box
        controls.add(JLabel("Search:"))
        self.search_field = JTextField(15)
        self.search_field.addKeyListener(SearchKeyListener(self))
        controls.add(self.search_field)
        
        # Source filter
        controls.add(JLabel("Source:"))
        self.source_filter = JComboBox(["All"])
        self.source_filter.setPreferredSize(Dimension(150, 25))
        self.source_filter.addActionListener(FilterAction(self))
        controls.add(self.source_filter)
        
        # Copy button
        copy_btn = JButton("Copy")
        copy_btn.addActionListener(CopyAction(self))
        controls.add(copy_btn)
        
        # Copy All button
        copy_all_btn = JButton("Copy All")
        copy_all_btn.addActionListener(CopyAllAction(self))
        controls.add(copy_all_btn)
        
        # Clear button
        clear_btn = JButton("Clear")
        clear_btn.addActionListener(ClearAction(self))
        controls.add(clear_btn)
        
        # Export button
        export_btn = JButton("Export")
        export_btn.addActionListener(ExportAction(self))
        controls.add(export_btn)
        
        header.add(controls, BorderLayout.EAST)
        self.add(header, BorderLayout.NORTH)
        
        # ===== TABS WITH TABLES =====
        self.tabs = JTabbedPane()
        
        self.tables = {}
        self.models = {}
        
        categories = [
            ("Endpoints", "endpoints"),
            ("URLs", "urls"),
            ("Secrets", "secrets"),
            ("Emails", "emails"),
            ("Files", "files"),
        ]
        
        for title, key in categories:
            panel = JPanel(BorderLayout())
            
            # 2 columns: Value, Source
            columns = ["Value", "Source", "Host", "Origin", "Referer"]
            model = NonEditableTableModel(columns, 0)
            self.models[key] = model
            
            table = JTable(model)
            table.setAutoCreateRowSorter(True)
            table.setFont(Font("Monospaced", Font.PLAIN, 12))
            
            # Set column widths
            table.getColumnModel().getColumn(0).setPreferredWidth(500)
            table.getColumnModel().getColumn(1).setPreferredWidth(150)
            table.getColumnModel().getColumn(2).setPreferredWidth(150)
            table.getColumnModel().getColumn(3).setPreferredWidth(150)
            table.getColumnModel().getColumn(4).setPreferredWidth(150)
            
            self.tables[key] = table
            
            scroll = JScrollPane(table)
            panel.add(scroll, BorderLayout.CENTER)
            
            self.tabs.addTab(title + " (0)", panel)
        
        self.add(self.tabs, BorderLayout.CENTER)
    
    def add_findings(self, new_findings, source_name):
        """Add new findings."""
        if source_name and source_name not in self.sources:
            self.sources.add(source_name)
            self.source_filter.addItem(source_name)
        
        for finding in new_findings:
            category = finding.get("category", "")
            if category in self.findings:
                self.findings[category].append({
                    "value": finding.get("value", ""),
                    "source": finding.get("source", source_name),
                    "host": finding.get("host", ""),
                    "origin": finding.get("origin", ""),
                    "referer": finding.get("referer", ""),
                })
        
        self._refresh_tables()
    
    def _refresh_tables(self):
        """Refresh tables with current filters."""
        selected_source = str(self.source_filter.getSelectedItem())
        search_text = self.search_field.getText().lower().strip()
        
        titles = ["Endpoints", "URLs", "Secrets", "Emails", "Files"]
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        
        for i, (title, key) in enumerate(zip(titles, keys)):
            model = self.models[key]
            model.setRowCount(0)
            
            count = 0
            for item in self.findings.get(key, []):
                # Source filter
                if selected_source != "All" and item.get("source") != selected_source:
                    continue
                
                # Search filter
                if search_text:
                    value_lower = item.get("value", "").lower()
                    if search_text not in value_lower:
                        continue
                
                model.addRow([
                    item.get("value", ""),
                    item.get("source", ""),
                    item.get("host", ""),
                    item.get("origin", ""),
                    item.get("referer", ""),
                ])
                count += 1
            
            self.tabs.setTitleAt(i, "%s (%d)" % (title, count))
        
        self._update_stats()
    
    def _update_stats(self):
        """Update stats label."""
        e = len(self.findings.get("endpoints", []))
        u = len(self.findings.get("urls", []))
        s = len(self.findings.get("secrets", []))
        m = len(self.findings.get("emails", []))
        f = len(self.findings.get("files", []))
        self.stats_label.setText("| E:%d | U:%d | S:%d | M:%d | F:%d" % (e, u, s, m, f))
    
    def _get_current_table(self):
        """Get the currently visible table."""
        idx = self.tabs.getSelectedIndex()
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        if 0 <= idx < len(keys):
            return self.tables.get(keys[idx])
        return None
    
    def _get_current_key(self):
        """Get the current category key."""
        idx = self.tabs.getSelectedIndex()
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        if 0 <= idx < len(keys):
            return keys[idx]
        return None
    
    def copy_selected(self):
        """Copy selected row's value to clipboard."""
        table = self._get_current_table()
        if not table:
            return
        
        row = table.getSelectedRow()
        if row >= 0:
            model_row = table.convertRowIndexToModel(row)
            value = table.getModel().getValueAt(model_row, 0)
            self._copy_to_clipboard(str(value))
    
    def copy_all_visible(self):
        """Copy all visible values in current tab to clipboard."""
        table = self._get_current_table()
        if not table:
            return
        
        model = table.getModel()
        values = []
        for i in range(model.getRowCount()):
            values.append(str(model.getValueAt(i, 0)))
        
        if values:
            self._copy_to_clipboard("\n".join(values))
    
    def _copy_to_clipboard(self, text):
        """Copy text to system clipboard."""
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text), None)
        except:
            pass
    
    def clear_all(self):
        """Clear all results."""
        for key in self.findings:
            self.findings[key] = []
        self.sources = set()
        
        self.source_filter.removeAllItems()
        self.source_filter.addItem("All")
        self.search_field.setText("")
        
        self.extender.clear_results()
        self._refresh_tables()
    
    def export_all(self):
        """Export to JSON."""
        from javax.swing import JFileChooser
        from java.io import File
        
        chooser = JFileChooser()
        chooser.setSelectedFile(File("js_findings.json"))
        
        if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            
            export = {
                "endpoints": [f["value"] for f in self.findings.get("endpoints", [])],
                "urls": [f["value"] for f in self.findings.get("urls", [])],
                "secrets": [f["value"] for f in self.findings.get("secrets", [])],
                "emails": [f["value"] for f in self.findings.get("emails", [])],
                "files": [f["value"] for f in self.findings.get("files", [])],
            }
            
            fp = open(path, 'w')
            try:
                json.dump(export, fp, indent=2)
            finally:
                fp.close()


class NonEditableTableModel(DefaultTableModel):
    def __init__(self, columns, rows):
        DefaultTableModel.__init__(self, columns, rows)
    
    def isCellEditable(self, row, column):
        return False


class SearchKeyListener(KeyListener):
    """Filters on each keystroke."""
    def __init__(self, panel):
        self.panel = panel
    def keyPressed(self, event):
        pass
    def keyReleased(self, event):
        self.panel._refresh_tables()
    def keyTyped(self, event):
        pass


class FilterAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel._refresh_tables()


class CopyAction(ActionListener):
    """Copy selected row."""
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_selected()


class CopyAllAction(ActionListener):
    """Copy all visible rows."""
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_all_visible()


class ClearAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.clear_all()


class ExportAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.export_all()
