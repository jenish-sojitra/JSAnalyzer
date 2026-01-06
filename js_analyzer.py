# -*- coding: utf-8 -*-
"""
JS Analyzer - Burp Suite Extension
Focused JavaScript analysis with strict endpoint filtering to reduce noise.
"""

from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import JMenuItem
from java.awt.event import ActionListener
from java.util import ArrayList
from java.io import PrintWriter

import sys
import os
import re
import inspect

# Add extension directory to path
try:
    _frame = inspect.currentframe()
    if _frame and hasattr(_frame, 'f_code'):
        ext_dir = os.path.dirname(os.path.abspath(_frame.f_code.co_filename))
    else:
        ext_dir = os.getcwd()
except:
    ext_dir = os.getcwd()

if ext_dir and ext_dir not in sys.path:
    sys.path.insert(0, ext_dir)

from ui.results_panel import ResultsPanel


# ==================== ENDPOINT PATTERNS ====================
# Focus on high-value API endpoints only

ENDPOINT_PATTERNS = [
    # API endpoints
    re.compile(r'["\']((?:https?:)?//[^"\']+/api/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v?\d*/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[a-zA-Z0-9/_-]{2,})["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    
    # OAuth/Auth endpoints
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    
    # Sensitive paths
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    
    # Well-known paths
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
]

# URL patterns - full URLs
URL_PATTERNS = [
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    # Cloud storage
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
]

# Secret patterns
SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16})'), "AWS Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35})'), "Google API"),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live"),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), "GitHub PAT"),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token"),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'), "JWT"),
    (re.compile(r'(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)'), "Private Key"),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]+)'), "MongoDB"),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'<>]+)'), "PostgreSQL"),
    (re.compile(r'(?i)algolia.{0,32}([a-z0-9]{32})\b'), "Algolia Admin API Key"),
    (re.compile(r'(?i)algolia.{0,16}([A-Z0-9]{10})\b'), "Algolia Application ID"),
    (re.compile(r'(?i)cloudflare.{0,32}(?:secret|private|access|key|token).{0,32}([a-z0-9_-]{38,42})\b'), "Cloudflare API Token"),
    (re.compile(r'(?i)(?:cloudflare|x-auth-user-service-key).{0,64}(v1\.0-[a-z0-9._-]{160,})\b'), "Cloudflare Service Key"),
    (re.compile(r'(mysql:\/\/[a-z0-9._%+\-]+:[^\s:@]+@(?:\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::\d{2,5})?(?:\/[^\s"\'?:]+)?(?:\?[^\s"\']*)?)'), "MySQL URI with Credentials"),
    (re.compile(r'\b(sgp_[A-Z0-9_-]{60,70})\b'), "Segment Public API Token"),
    (re.compile(r'(?i)(?:segment|sgmt).{0,16}(?:secret|private|access|key|token).{0,16}([A-Z0-9_-]{40,50}\.[A-Z0-9_-]{40,50})'), "Segment API Key"),
    (re.compile(r'(?i)(?:facebook|fb).{0,8}(?:app|application).{0,16}(\d{15})\b'), "Facebook App ID"),
    (re.compile(r'(?i)(?:facebook|fb).{0,32}(?:api|app|application|client|consumer|secret|key).{0,32}([a-z0-9]{32})\b'), "Facebook Secret Key"),
    (re.compile(r'(EAACEdEose0cBA[A-Z0-9]{20,})\b'), "Facebook Access Token"),
    (re.compile(r'\b(ya29\.[a-z0-9_-]{30,})\b'), "Google OAuth2 Access Token"),
]

# Email pattern
EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# File patterns - detect references to sensitive file types
FILE_PATTERNS = re.compile(
    r'["\']([a-zA-Z0-9_/.-]+\.(?:'
    r'sql|csv|xlsx|xls|json|xml|yaml|yml|'  # Data files
    r'txt|log|conf|config|cfg|ini|env|'      # Config/logs
    r'bak|backup|old|orig|copy|'              # Backups
    r'key|pem|crt|cer|p12|pfx|'               # Certificates
    r'doc|docx|pdf|'                          # Documents
    r'zip|tar|gz|rar|7z|'                     # Archives
    r'sh|bat|ps1|py|rb|pl'                    # Scripts
    r'))["\']',
    re.IGNORECASE
)

# ==================== NOISE FILTERS ====================
# Extensive list of patterns to EXCLUDE

# Domains to exclude from URLs (XML namespaces, standards, etc.)
NOISE_DOMAINS = {
    'www.w3.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com',
    'purl.org', 'purl.oclc.org', 'openoffice.org', 'docs.oasis-open.org',
    'sheetjs.openxmlformats.org', 'ns.adobe.com', 'www.xml.org',
    'example.com', 'test.com', 'localhost', '127.0.0.1',
    'fusioncharts.com', 'jspdf.default.namespaceuri',
    'npmjs.org', 'registry.npmjs.org',
    'github.com/indutny', 'github.com/crypto-browserify',
    'jqwidgets.com', 'ag-grid.com',
}

# Path prefixes that indicate module imports (NOT real endpoints)
MODULE_PREFIXES = (
    './', '../', '.../', 
    './lib', '../lib', './utils', '../utils',
    './node_modules', '../node_modules',
    './src', '../src', './dist', '../dist',
)

# Patterns that are clearly internal JS/build artifacts
NOISE_PATTERNS = [
    # Module/library imports
    re.compile(r'^\.\.?/'),  # Starts with ./ or ../
    re.compile(r'^[a-z]{2}(-[a-z]{2})?\.js$'),  # Locale files: en.js, en-gb.js
    re.compile(r'^[a-z]{2}(-[a-z]{2})?$'),  # Just locale: en, en-gb
    re.compile(r'-xform$'),  # Excel xform modules
    re.compile(r'^sha\d*$'),  # sha, sha1, sha256
    re.compile(r'^aes$|^des$|^md5$'),  # Crypto modules
    
    # PDF internal structure
    re.compile(r'^/[A-Z][a-z]+\s'),  # /Type /Font, /Filter /Standard
    re.compile(r'^/[A-Z][a-z]+$'),  # /Parent, /Kids, /Resources
    re.compile(r'^\d+ \d+ R$'),  # PDF object references
    
    # Excel/XML internal paths
    re.compile(r'^xl/'),  # Excel internal
    re.compile(r'^docProps/'),  # Document properties
    re.compile(r'^_rels/'),  # Relationships
    re.compile(r'^META-INF/'),  # Manifest
    re.compile(r'\.xml$'),  # XML files
    re.compile(r'^worksheets/'),
    re.compile(r'^theme/'),
    
    # Build/bundler artifacts
    re.compile(r'^webpack'),
    re.compile(r'^zone\.js$'),
    re.compile(r'^readable-stream/'),
    re.compile(r'^process/'),
    re.compile(r'^stream/'),
    re.compile(r'^buffer$'),
    re.compile(r'^events$'),
    re.compile(r'^util$'),
    re.compile(r'^path$'),
    
    # Generic noise
    re.compile(r'^\+'),  # Starts with +
    re.compile(r'^\$\{'),  # Template literal
    re.compile(r'^#'),  # Fragment only
    re.compile(r'^\?\ref='),
    re.compile(r'^/[a-z]$'),  # Single letter paths
    re.compile(r'^/[A-Z]$'),  # Single letter paths
    re.compile(r'^http://$'),  # Empty http://
    re.compile(r'_ngcontent'),  # Angular internals
]

# Specific strings to exclude
NOISE_STRINGS = {
    'http://', 'https://', '/a', '/P', '/R', '/V', '/W',
    'zone.js', 'bn.js', 'hash.js', 'md5.js', 'sha.js', 'des.js',
    'asn1.js', 'declare.js', 'elliptic.js',
}


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):
    """JS Analyzer with noise-reduced endpoint detection."""
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        callbacks.setExtensionName("JS Analyzer")
        
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Results storage
        self.all_findings = []
        self.seen_values = set()
        
        # Initialize UI
        self.panel = ResultsPanel(callbacks, self)
        
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        
        self._log("JS Analyzer loaded - Right-click JS responses to analyze")
    
    def _log(self, msg):
        self._stdout.println("[JS Analyzer] " + str(msg))
    
    def getTabCaption(self):
        return "JS Analyzer"
    
    def getUiComponent(self):
        return self.panel
    
    def createMenuItems(self, invocation):
        menu = ArrayList()
        try:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                item = JMenuItem("Analyze JS with JS Analyzer")
                item.addActionListener(AnalyzeAction(self, invocation))
                menu.add(item)
        except Exception as e:
            self._log("Menu error: " + str(e))
        return menu
    
    def analyze_response(self, message_info):
        """Analyze a response."""
        response = message_info.getResponse()
        if not response:
            return
        
        # Get source URL
        try:
            req_info = self._helpers.analyzeRequest(message_info)
            url = str(req_info.getUrl())
            source_name = url.split('/')[-1].split('?')[0] if '/' in url else url
            if len(source_name) > 40:
                source_name = source_name[:40] + "..."
        except:
            url = "Unknown"
            source_name = "Unknown"
        
        # Get response body
        resp_info = self._helpers.analyzeResponse(response)
        body_offset = resp_info.getBodyOffset()
        body = self._helpers.bytesToString(response[body_offset:])
        
        if len(body) < 50:
            return
        
        self._log("Analyzing: " + source_name)
        
        new_findings = []
        
        # 1. Extract endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._is_valid_endpoint(value):
                    finding = self._add_finding("endpoints", value, source_name)
                    if finding:
                        new_findings.append(finding)
        
        # 2. URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                if self._is_valid_url(value):
                    finding = self._add_finding("urls", value, source_name)
                    if finding:
                        new_findings.append(finding)
        
        # 3. Secrets
        for pattern, _ in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._is_valid_secret(value):
                    masked = value[:10] + "..." + value[-4:] if len(value) > 20 else value
                    finding = self._add_finding("secrets", masked, source_name)
                    if finding:
                        new_findings.append(finding)
        
        # 4. Emails
        for match in EMAIL_PATTERN.finditer(body):
            value = match.group(1).strip()
            if self._is_valid_email(value):
                finding = self._add_finding("emails", value, source_name)
                if finding:
                    new_findings.append(finding)
        
        # 5. Files (sensitive file references)
        for match in FILE_PATTERNS.finditer(body):
            value = match.group(1).strip()
            if self._is_valid_file(value):
                finding = self._add_finding("files", value, source_name)
                if finding:
                    new_findings.append(finding)
        
        # Update UI
        if new_findings:
            self._log("Found %d new items" % len(new_findings))
            self.panel.add_findings(new_findings, source_name)
        else:
            self._log("No new findings")
    
    def _add_finding(self, category, value, source):
        """Add a finding if not duplicate."""
        key = category + ":" + value
        if key in self.seen_values:
            return None
        
        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source,
        }
        self.all_findings.append(finding)
        return finding
    
    def _is_valid_endpoint(self, value):
        """Strict endpoint validation - reject noise."""
        if not value or len(value) < 3:
            return False
        
        # Check exact matches first
        if value in NOISE_STRINGS:
            return False
        
        # Check noise patterns
        for pattern in NOISE_PATTERNS:
            if pattern.search(value):
                return False
        
        # Must start with / and have some path
        if not value.startswith('/'):
            return False
        
        # Skip if just a single segment with no meaning
        parts = value.split('/')
        if len(parts) < 2 or all(len(p) < 2 for p in parts if p):
            return False
        
        return True
    
    def _is_valid_url(self, value):
        """Strict URL validation."""
        if not value or len(value) < 15:
            return False
        
        val_lower = value.lower()
        
        # Check for noise domains
        for domain in NOISE_DOMAINS:
            if domain in val_lower:
                return False
        
        # Skip if contains placeholder patterns
        if '{' in value or 'undefined' in val_lower or 'null' in val_lower:
            return False
        
        # Skip data URIs
        if val_lower.startswith('data:'):
            return False
        
        # Skip if ends with common static extensions
        if any(val_lower.endswith(ext) for ext in ['.css', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf']):
            return False
        
        return True
    
    def _is_valid_secret(self, value):
        """Validate secrets."""
        if not value or len(value) < 10:
            return False
        
        val_lower = value.lower()
        if any(x in val_lower for x in ['example', 'placeholder', 'your', 'xxxx', 'test']):
            return False
        
        return True
    
    def _is_valid_email(self, value):
        """Validate emails."""
        if not value or '@' not in value:
            return False
        
        val_lower = value.lower()
        domain = value.split('@')[-1].lower()
        
        if domain in {'example.com', 'test.com', 'domain.com', 'placeholder.com'}:
            return False
        
        if any(x in val_lower for x in ['example', 'test', 'placeholder', 'noreply']):
            return False
        
        return True
    
    def _is_valid_file(self, value):
        """Validate file references."""
        if not value or len(value) < 3:
            return False
        
        val_lower = value.lower()
        
        # Skip common JS/build files
        if any(x in val_lower for x in [
            'package.json', 'tsconfig.json', 'webpack', 'babel',
            'eslint', 'prettier', 'node_modules', '.min.',
            'polyfill', 'vendor', 'chunk', 'bundle'
        ]):
            return False
        
        # Skip source maps
        if val_lower.endswith('.map'):
            return False
        
        # Skip common locale/language files
        if val_lower.endswith('.json') and len(value.split('/')[-1]) <= 7:
            return False
        
        return True
    
    def clear_results(self):
        self.all_findings = []
        self.seen_values = set()
    
    def get_all_findings(self):
        return self.all_findings


class AnalyzeAction(ActionListener):
    def __init__(self, extender, invocation):
        self.extender = extender
        self.invocation = invocation
    
    def actionPerformed(self, event):
        messages = self.invocation.getSelectedMessages()
        for msg in messages:
            self.extender.analyze_response(msg)
