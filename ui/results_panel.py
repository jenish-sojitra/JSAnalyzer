# -*- coding: utf-8 -*-
"""
JS Analyzer - Results Panel
Modernized UI with Split Pane, Preview, and Source Viewer.
"""

from javax.swing import (
    JPanel, JScrollPane, JTabbedPane, JButton, JLabel,
    JTable, JComboBox, JTextField, BorderFactory, JSplitPane,
    JTextArea, Box, JDialog, JFrame, SwingUtilities
)
from javax.swing.event import ListSelectionListener
from javax.swing.table import DefaultTableModel
from java.awt import (
    BorderLayout, FlowLayout, Font, Dimension, Toolkit, 
    Color, GridBagLayout, GridBagConstraints, Insets
)
from java.awt.datatransfer import StringSelection
from java.awt.event import ActionListener, KeyListener, KeyEvent, MouseAdapter
import json


class ResultsPanel(JPanel):
    """Modernized results panel with search, filtering, and source viewer."""
    
    def __init__(self, callbacks, extender):
        JPanel.__init__(self)
        self.callbacks = callbacks
        self.extender = extender
        
        # Dark Theme Colors
        self.BACKGROUND_DARK = Color(30, 30, 30)
        self.BACKGROUND_LIGHT = Color(45, 45, 45)
        self.TEXT_PRIMARY = Color(220, 220, 200)
        self.TEXT_SECONDARY = Color(180, 180, 180)
        self.ACCENT_COLOR = Color(100, 180, 255)
        self.SELECTION_COLOR = Color(60, 60, 70)
        self.BORDER_COLOR = Color(60, 60, 60)
        
        self.TITLE_FONT = Font("SansSerif", Font.BOLD, 14)
        self.LABEL_FONT = Font("SansSerif", Font.PLAIN, 12)
        self.MONO_FONT = Font("Monospaced", Font.PLAIN, 12)
        
        # Findings by category
        self.findings = {
            "endpoints": [],
            "urls": [],
            "secrets": [],
            "emails": [],
            "files": [],
        }
        
        self.sources = set()
        self._init_ui()
    
    def _init_ui(self):
        """Build the modernized Dark Mode UI."""
        self.setLayout(BorderLayout(0, 0))
        self.setBackground(self.BACKGROUND_DARK)
        
        # ===== TOP BAR: Header & Search =====
        top_panel = JPanel(BorderLayout(10, 5))
        top_panel.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, self.BORDER_COLOR))
        top_panel.setBackground(self.BACKGROUND_LIGHT)
        
        # Title and Stats
        title_box = Box.createHorizontalBox()
        app_title = JLabel("JS ANALYZER")
        app_title.setFont(self.TITLE_FONT)
        app_title.setForeground(self.ACCENT_COLOR)
        title_box.add(app_title)
        title_box.add(Box.createHorizontalStrut(15))
        
        self.stats_label = JLabel("E:0 | U:0 | S:0 | M:0 | F:0")
        self.stats_label.setFont(self.LABEL_FONT)
        self.stats_label.setForeground(self.TEXT_SECONDARY)
        title_box.add(self.stats_label)
        top_panel.add(title_box, BorderLayout.WEST)
        
        # Filters
        filter_box = Box.createHorizontalBox()
        l_search = JLabel("Search: ")
        l_search.setForeground(self.TEXT_PRIMARY)
        filter_box.add(l_search)
        
        self.search_field = JTextField(20)
        self.search_field.setBackground(Color(60, 60, 60))
        self.search_field.setForeground(Color.WHITE)
        self.search_field.setCaretColor(Color.WHITE)
        self.search_field.setBorder(BorderFactory.createLineBorder(self.BORDER_COLOR))
        self.search_field.addKeyListener(SearchKeyListener(self))
        filter_box.add(self.search_field)
        
        filter_box.add(Box.createHorizontalStrut(15))
        l_source = JLabel("Source: ")
        l_source.setForeground(self.TEXT_PRIMARY)
        filter_box.add(l_source)
        
        self.source_filter = JComboBox(["All Sources"])
        self.source_filter.setPreferredSize(Dimension(200, 25))
        self.source_filter.setBackground(Color(60, 60, 60))
        self.source_filter.setForeground(Color.WHITE)
        self.source_filter.addActionListener(FilterAction(self))
        filter_box.add(self.source_filter)
        top_panel.add(filter_box, BorderLayout.EAST)
        
        self.add(top_panel, BorderLayout.NORTH)
        
        # ===== CENTER: Split Pane with Tabs & Preview =====
        self.tabs = JTabbedPane()
        self.tabs.setFont(self.LABEL_FONT)
        
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
            panel.setBackground(self.BACKGROUND_DARK)
            columns = ["Value", "Source"]
            model = NonEditableTableModel(columns, 0)
            self.models[key] = model
            
            table = JTable(model)
            table.setAutoCreateRowSorter(True)
            table.setFont(self.MONO_FONT)
            table.setRowHeight(25)
            table.setBackground(self.BACKGROUND_DARK)
            table.setForeground(self.TEXT_PRIMARY)
            table.setGridColor(self.BORDER_COLOR)
            table.setSelectionBackground(self.SELECTION_COLOR)
            table.setSelectionForeground(Color.WHITE)
            table.setIntercellSpacing(Dimension(10, 5))
            
            # Header styling
            header = table.getTableHeader()
            header.setBackground(self.BACKGROUND_LIGHT)
            header.setForeground(self.TEXT_PRIMARY)
            header.setFont(self.LABEL_FONT)
            
            # Selection event for preview
            table.getSelectionModel().addListSelectionListener(TableSelectionListener(self, table))
            
            # Double-click listener for source viewer
            table.addMouseListener(TableMouseListener(self, table))
            
            # Column widths
            table.getColumnModel().getColumn(0).setPreferredWidth(600)
            table.getColumnModel().getColumn(1).setPreferredWidth(200)
            
            self.tables[key] = table
            scroll = JScrollPane(table)
            scroll.setBackground(self.BACKGROUND_DARK)
            scroll.getViewport().setBackground(self.BACKGROUND_DARK)
            scroll.setBorder(BorderFactory.createEmptyBorder())
            panel.add(scroll, BorderLayout.CENTER)
            self.tabs.addTab(title + " (0)", panel)

        # Preview Panel
        preview_container = JPanel(BorderLayout())
        preview_container.setBackground(self.BACKGROUND_DARK)
        btn_border = BorderFactory.createTitledBorder(
            BorderFactory.createLineBorder(self.BORDER_COLOR), "Detail Preview"
        )
        btn_border.setTitleColor(self.ACCENT_COLOR)
        preview_container.setBorder(btn_border)
        
        self.preview_area = JTextArea(5, 50)
        self.preview_area.setEditable(False)
        self.preview_area.setFont(self.MONO_FONT)
        self.preview_area.setBackground(Color(25, 25, 25))
        self.preview_area.setForeground(self.TEXT_PRIMARY)
        self.preview_area.setCaretColor(Color.WHITE)
        self.preview_area.setLineWrap(True)
        self.preview_area.setWrapStyleWord(True)
        
        scroll_preview = JScrollPane(self.preview_area)
        scroll_preview.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        scroll_preview.setBackground(Color(25, 25, 25))
        preview_container.add(scroll_preview, BorderLayout.CENTER)
        
        # Split Pane
        self.split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, self.tabs, preview_container)
        self.split_pane.setDividerLocation(400)
        self.split_pane.setResizeWeight(0.8)
        self.split_pane.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5))
        
        self.add(self.split_pane, BorderLayout.CENTER)
        
        # ===== BOTTOM BAR: Actions =====
        bottom_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 10, 10))
        bottom_panel.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, self.BORDER_COLOR))
        bottom_panel.setBackground(self.BACKGROUND_LIGHT)
        
        def style_btn(btn):
            btn.setBackground(Color(60, 60, 60))
            btn.setForeground(Color.WHITE)
            btn.setFocusPainted(False)
            btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(self.BORDER_COLOR),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)
            ))
        
        view_btn = JButton("View Source Code")
        style_btn(view_btn)
        view_btn.addActionListener(ViewSourceAction(self))
        bottom_panel.add(view_btn)
        
        copy_btn = JButton("Copy Selected")
        style_btn(copy_btn)
        copy_btn.addActionListener(CopyAction(self))
        bottom_panel.add(copy_btn)
        
        copy_all_btn = JButton("Copy All Visible")
        style_btn(copy_all_btn)
        copy_all_btn.addActionListener(CopyAllAction(self))
        bottom_panel.add(copy_all_btn)
        
        clear_btn = JButton("Clear Results")
        style_btn(clear_btn)
        clear_btn.addActionListener(ClearAction(self))
        bottom_panel.add(clear_btn)
        
        export_btn = JButton("Export JSON")
        style_btn(export_btn)
        export_btn.addActionListener(ExportAction(self))
        bottom_panel.add(export_btn)
        
        self.add(bottom_panel, BorderLayout.SOUTH)
    
    def add_findings(self, new_findings, source_name):
        """Add new findings and update UI."""
        if source_name and source_name not in self.sources:
            self.sources.add(source_name)
            self.source_filter.addItem(source_name)
        
        for finding in new_findings:
            category = finding.get("category", "")
            if category in self.findings:
                self.findings[category].append({
                    "value": finding.get("value", ""),
                    "source": finding.get("source", source_name),
                    "offset": finding.get("offset", 0),
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
            # Store metadata in a hidden way or use index mapping
            filtered_items = []
            for item in self.findings.get(key, []):
                # Source filter
                if selected_source != "All Sources" and item.get("source") != selected_source:
                    continue
                
                # Search filter
                if search_text:
                    if search_text not in item.get("value", "").lower():
                        continue
                
                model.addRow([item.get("value", ""), item.get("source", "")])
                count += 1
            
            self.tabs.setTitleAt(i, "%s (%d)" % (title, count))
        
        self._update_stats()
    
    def _update_stats(self):
        """Update metrics label."""
        e = len(self.findings.get("endpoints", []))
        u = len(self.findings.get("urls", []))
        s = len(self.findings.get("secrets", []))
        m = len(self.findings.get("emails", []))
        f = len(self.findings.get("files", []))
        self.stats_label.setText("E:%d | U:%d | S:%d | M:%d | F:%d" % (e, u, s, m, f))
    
    def update_preview(self, text):
        """Update the preview text area."""
        self.preview_area.setText(text)
        self.preview_area.setCaretPosition(0)

    def view_source_for_selected(self):
        """Open source viewer for selected finding."""
        table = self._get_current_table()
        if not table or table.getSelectedRow() < 0:
            return
            
        row = table.convertRowIndexToModel(table.getSelectedRow())
        key = self._get_current_key()
        
        # Re-apply filters to find the correct item in self.findings
        selected_source = str(self.source_filter.getSelectedItem())
        search_text = self.search_field.getText().lower().strip()
        
        filtered_results = []
        for item in self.findings.get(key, []):
            if selected_source != "All Sources" and item.get("source") != selected_source:
                continue
            if search_text and search_text not in item.get("value", "").lower():
                continue
            filtered_results.append(item)
            
        if row < len(filtered_results):
            item = filtered_results[row]
            source_content = self.extender.get_source_code(item["source"])
            if source_content:
                # Use None for parent if getExtenderWindowFrame is missing
                SourceViewerDialog(None, 
                                 item["source"], source_content, 
                                 item["offset"], len(item["value"])).setVisible(True)

    def _get_current_table(self):
        idx = self.tabs.getSelectedIndex()
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        if 0 <= idx < len(keys):
            return self.tables.get(keys[idx])
        return None

    def _get_current_key(self):
        idx = self.tabs.getSelectedIndex()
        keys = ["endpoints", "urls", "secrets", "emails", "files"]
        if 0 <= idx < len(keys):
            return keys[idx]
        return None

    def _copy_to_clipboard(self, text):
        try:
            clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(StringSelection(text), None)
        except:
            pass

    def copy_selected(self):
        table = self._get_current_table()
        if table and table.getSelectedRow() >= 0:
            row = table.convertRowIndexToModel(table.getSelectedRow())
            value = table.getModel().getValueAt(row, 0)
            self._copy_to_clipboard(str(value))

    def copy_all_visible(self):
        table = self._get_current_table()
        if table:
            model = table.getModel()
            values = [str(model.getValueAt(i, 0)) for i in range(model.getRowCount())]
            if values:
                self._copy_to_clipboard("\n".join(values))

    def clear_all(self):
        for key in self.findings:
            self.findings[key] = []
        self.sources = set()
        self.source_filter.removeAllItems()
        self.source_filter.addItem("All Sources")
        self.search_field.setText("")
        self.preview_area.setText("")
        self.extender.clear_results()
        self._refresh_tables()

    def export_all(self):
        from javax.swing import JFileChooser
        from java.io import File
        chooser = JFileChooser()
        chooser.setSelectedFile(File("js_findings.json"))
        if chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            path = chooser.getSelectedFile().getAbsolutePath()
            export = {k: [f["value"] for f in v] for k, v in self.findings.items()}
            with open(path, 'w') as f:
                json.dump(export, f, indent=2)


class NonEditableTableModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class SourceViewerDialog(JDialog):
    """Dialog to view source code and highlight finding."""
    def __init__(self, parent, title, content, offset, length):
        JDialog.__init__(self, parent, "Source Viewer - " + title, True)
        self.setSize(900, 700)
        self.setLocationRelativeTo(parent)
        self.setLayout(BorderLayout())
        
        # Colors (Dark Mode)
        bg = Color(30, 30, 30)
        fg = Color(220, 220, 200)
        highlight = Color(0, 102, 204, 100) # Semi-transparent blue
        
        area = JTextArea(content)
        area.setEditable(False)
        area.setBackground(bg)
        area.setForeground(fg)
        area.setFont(Font("Monospaced", Font.PLAIN, 12))
        area.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        area.setCaretColor(Color.WHITE)
        
        # Highlight and Scroll
        try:
            if offset >= 0:
                # Custom painter for more visible highlight
                from javax.swing.text import DefaultHighlighter
                painter = DefaultHighlighter.DefaultHighlightPainter(Color(255, 255, 0, 80)) # Translucent yellow
                area.getHighlighter().addHighlight(offset, offset + length, painter)
                
                # Scroll to location reliably
                def scroll_to():
                    area.setCaretPosition(offset)
                    # Manually ensure visibility
                    rect = area.modelToView(offset)
                    if rect:
                        area.scrollRectToVisible(rect)
                
                SwingUtilities.invokeLater(scroll_to)
        except Exception as e:
            pass
            
        scroll = JScrollPane(area)
        scroll.setBorder(None)
        self.add(scroll, BorderLayout.CENTER)
        
        # Bottom bar info
        line_num = content[:offset].count('\n') + 1
        info = JLabel(" Location: Line %d, Offset %d" % (line_num, offset))
        info.setForeground(Color.LIGHT_GRAY)
        info.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self.add(info, BorderLayout.SOUTH)


class TableSelectionListener(ListSelectionListener):
    """Updates preview when a row is selected."""
    def __init__(self, panel, table):
        self.panel = panel
        self.table = table
    def valueChanged(self, event):
        if not event.getValueIsAdjusting():
            row = self.table.getSelectedRow()
            if row >= 0:
                model_row = self.table.convertRowIndexToModel(row)
                value = self.table.getModel().getValueAt(model_row, 0)
                self.panel.update_preview(str(value))


class TableMouseListener(MouseAdapter):
    """Detect double-click on table rows."""
    def __init__(self, panel, table):
        self.panel = panel
        self.table = table
    def mouseClicked(self, event):
        if event.getClickCount() == 2:
            self.panel.view_source_for_selected()


class SearchKeyListener(KeyListener):
    def __init__(self, panel):
        self.panel = panel
    def keyReleased(self, event):
        self.panel._refresh_tables()
    def keyPressed(self, event): pass
    def keyTyped(self, event): pass


class FilterAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel._refresh_tables()


class ViewSourceAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.view_source_for_selected()


class CopyAction(ActionListener):
    def __init__(self, panel):
        self.panel = panel
    def actionPerformed(self, event):
        self.panel.copy_selected()


class CopyAllAction(ActionListener):
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
