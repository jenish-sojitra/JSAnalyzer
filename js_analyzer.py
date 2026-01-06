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
    re.compile(r'["\'](/grpc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/soap[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/rpc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/json-rpc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Versioned API endpoints
    re.compile(r'["\'](/v[0-9]+(?:\.[0-9]+)?/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v[0-9]+(?:\.[0-9]+)?/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/version/[0-9]+/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),

    # OAuth/Auth endpoints
    re.compile(r'["\'](/oauth[0-9]*/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/auth[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/login[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/token[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/authorize[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/authenticate[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/register[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/signup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/signin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/signout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/callback[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/refresh[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/sso[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/saml[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/openid[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Sensitive paths - Extended
    re.compile(r'["\'](/admin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dashboard[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/internal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/debug[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/config[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/backup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/private[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/upload[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/download[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/secret[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/secure[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/hidden[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/test[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/staging[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/dev[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/prod[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/uat[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/qa[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Data management endpoints
    re.compile(r'["\'](/data[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/database[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/db[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/export[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/import[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/migrate[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/sql[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # File operations
    re.compile(r'["\'](/file[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/files[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/document[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/documents[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/archive[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/static/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/media/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/assets/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),

    # User management endpoints
    re.compile(r'["\'](/user[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/users[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/account[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/accounts[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/profile[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/profiles[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/member[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/members[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/customer[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/customers[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # System/Admin operations
    re.compile(r'["\'](/system[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/server[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/servers[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/status[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/health[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/metrics[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/monitoring[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logs[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/logging[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/console[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/shell[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/terminal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Payment/Transaction endpoints
    re.compile(r'["\'](/payment[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/payments[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/transaction[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/transactions[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/billing[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/invoice[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/invoices[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/checkout[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Webhook endpoints
    re.compile(r'["\'](/webhook[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/webhooks[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/hook[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/hooks[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/callback/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/notify[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/notification[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Well-known paths - Extended
    re.compile(r'["\'](/\.well-known/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/idp/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.git/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.svn/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/\.hg/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),

    # Framework-specific endpoints
    re.compile(r'["\'](/actuator[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),  # Spring Boot
    re.compile(r'["\'](/rails[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),  # Ruby on Rails
    re.compile(r'["\'](/wp-[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-content/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-admin/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-includes/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress
    re.compile(r'["\'](/wp-json/[a-zA-Z0-9/_-]+)["\']', re.IGNORECASE),  # WordPress REST API

    # Development/Testing endpoints
    re.compile(r'["\'](/swagger[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/openapi[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/docs[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/documentation[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/redoc[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/playground[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/explorer[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Search endpoints
    re.compile(r'["\'](/search[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/query[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/lookup[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # External service integrations
    re.compile(r'["\'](/slack[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/discord[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/github[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/gitlab[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/bitbucket[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/stripe[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/paypal[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Email endpoints
    re.compile(r'["\'](/email[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/mail[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/newsletter[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/subscribe[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/unsubscribe[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # API Gateway patterns
    re.compile(r'["\'](/gateway[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/proxy[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/route[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Cache endpoints
    re.compile(r'["\'](/cache[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/flush[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/purge[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Queue/Job endpoints
    re.compile(r'["\'](/queue[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/job[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/jobs[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/task[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/tasks[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # Database specific endpoints (for admin tools)
    re.compile(r'["\'](/phpmyadmin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/adminer[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/pgadmin[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/mongodb[a-zA-Z0-9/_-]*)["\']', re.IGNORECASE),

    # File extension patterns for sensitive files
    re.compile(r'["\'](.*\.(?:git|svn|hg|bak|old|backup|swp))["\']', re.IGNORECASE),
    re.compile(r'["\'](.*\.(?:sql|dump|tar|gz|zip|7z|rar))["\']', re.IGNORECASE),
    re.compile(r'["\'](.*\.(?:env|config|conf|ini|properties|yml|yaml|json))["\']', re.IGNORECASE),
]

# URL patterns - full URLs
URL_PATTERNS = [
    # Standard URL patterns
    re.compile(r'["\'](https?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](sftp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ftp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ftps://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ws://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](wss://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ssh://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](telnet://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](smtp://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ldap://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](ldaps://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](mongo://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](mongodb(?:\+srv)?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](redis://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](rediss://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](postgres(?:ql)?://[^\s"\'<>]{10,})["\']'),
    re.compile(r'["\'](mysql://[^\s"\'<>]{10,})["\']'),
    
    # Cloud storage - Extended
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://s3-[a-zA-Z0-9-]+\.amazonaws\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.s3-website-[a-zA-Z0-9-]+\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.blob\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.file\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.queue\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.table\.core\.windows\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.storage\.googleapis\.com/[^\s"\'<>]*)'),
    re.compile(r'(https?://firebasestorage\.googleapis\.com/[^\s"\'<>]*)'),
    
    # Cloud services URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.execute-api\.[a-zA-Z0-9.-]+\.amazonaws\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.lambda-url\.[a-zA-Z0-9.-]+\.on\.aws[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfront\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.azurewebsites\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.appspot\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfunctions\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.run\.app[^\s"\'<>]*)'),
    
    # Database URLs with credentials
    re.compile(r'(https?://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(postgres(?:ql)?://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(mysql://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(mongodb(?:\+srv)?://[^\s"\'<>]*:[^\s"\'<>]*@[^\s"\'<>]+)'),
    re.compile(r'(redis://:[^\s"\'<>]*@[^\s"\'<>]+)'),
    
    # Internal/Private network URLs
    re.compile(r'(https?://(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[^\s"\'<>]+)'),
    re.compile(r'(https?://localhost[^\s"\'<>]*)'),
    re.compile(r'(https?://127\.0\.0\.1[^\s"\'<>]*)'),
    re.compile(r'(https?://\[::1\][^\s"\'<>]*)'),
    re.compile(r'(https?://(?:local|dev|test|staging|uat)\.[^\s"\'<>]+)'),
    
    # API Gateway/Proxy URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/v[0-9]+/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/api/v[0-9]+/[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.[^\s"\'<>]+)'),
    re.compile(r'(https?://graphql\.[^\s"\'<>]+)'),
    re.compile(r'(https?://rest\.[^\s"\'<>]+)'),
    
    # Authentication/Identity URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/oauth/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/auth/[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/login[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/\.well-known/[^\s"\'<>]*)'),
    re.compile(r'(https?://accounts\.[^\s"\'<>]+)'),
    re.compile(r'(https?://auth\.[^\s"\'<>]+)'),
    re.compile(r'(https?://sso\.[^\s"\'<>]+)'),
    re.compile(r'(https?://identity\.[^\s"\'<>]+)'),
    
    # Monitoring/Logging URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/metrics[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/health[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/status[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/debug[^\s"\'<>]*)'),
    re.compile(r'(https?://grafana\.[^\s"\'<>]+)'),
    re.compile(r'(https?://prometheus\.[^\s"\'<>]+)'),
    re.compile(r'(https?://kibana\.[^\s"\'<>]+)'),
    re.compile(r'(https?://elk\.[^\s"\'<>]+)'),
    
    # Admin/Management URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/admin[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/dashboard[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/console[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/phpmyadmin[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/pgadmin[^\s"\'<>]*)'),
    re.compile(r'(https?://admin\.[^\s"\'<>]+)'),
    re.compile(r'(https?://dashboard\.[^\s"\'<>]+)'),
    re.compile(r'(https?://manager\.[^\s"\'<>]+)'),
    
    # CI/CD/DevOps URLs
    re.compile(r'(https?://jenkins\.[^\s"\'<>]+)'),
    re.compile(r'(https?://gitlab\.[^\s"\'<>]+)'),
    re.compile(r'(https?://github\.[^\s"\'<>]+)'),
    re.compile(r'(https?://bitbucket\.[^\s"\'<>]+)'),
    re.compile(r'(https?://circleci\.[^\s"\'<>]+)'),
    re.compile(r'(https?://travis-ci\.[^\s"\'<>]+)'),
    re.compile(r'(https?://drone\.[^\s"\'<>]+)'),
    re.compile(r'(https?://argo\.[^\s"\'<>]+)'),
    
    # Documentation/API Docs URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/docs[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/swagger[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/openapi[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/redoc[^\s"\'<>]*)'),
    re.compile(r'(https?://docs\.[^\s"\'<>]+)'),
    re.compile(r'(https?://api-docs\.[^\s"\'<>]+)'),
    
    # Webhook/Notification URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/webhook[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/hook[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/callback[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/notify[^\s"\'<>]*)'),
    re.compile(r'(https?://webhook\.[^\s"\'<>]+)'),
    
    # File/Storage URLs with sensitive extensions
    re.compile(r'(https?://[^\s"\'<>]*\.(?:git|svn|hg)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:bak|old|backup|swp)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:sql|dump)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:tar|gz|zip|7z|rar)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:env|config|conf|ini)[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\.(?:pem|key|cer|crt|pfx)[^\s"\'<>]*)'),
    
    # Mail/Email URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/mail[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/email[^\s"\'<>]*)'),
    re.compile(r'(https?://mail\.[^\s"\'<>]+)'),
    re.compile(r'(https?://smtp\.[^\s"\'<>]+)'),
    re.compile(r'(https?://imap\.[^\s"\'<>]+)'),
    re.compile(r'(https?://pop\.[^\s"\'<>]+)'),
    
    # Message Queue/Broker URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/rabbitmq[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/kafka[^\s"\'<>]*)'),
    re.compile(r'(https?://rabbitmq\.[^\s"\'<>]+)'),
    re.compile(r'(https?://kafka\.[^\s"\'<>]+)'),
    re.compile(r'(https?://mq\.[^\s"\'<>]+)'),
    
    # Cache URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/redis[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/memcached[^\s"\'<>]*)'),
    re.compile(r'(https?://redis\.[^\s"\'<>]+)'),
    re.compile(r'(https?://memcached\.[^\s"\'<>]+)'),
    re.compile(r'(https?://cache\.[^\s"\'<>]+)'),
    
    # Testing/Staging URLs
    re.compile(r'(https?://(?:test|staging|uat|qa|dev|preprod)\.[^\s"\'<>]+)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.test[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.staging[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+-test[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+-staging[^\s"\'<>]*)'),
    
    # CDN URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cloudfront\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.akamaihd\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.fastly\.net[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+\.cdn\.cloudflare\.net[^\s"\'<>]*)'),
    
    # Analytics/Tracking URLs
    re.compile(r'(https?://analytics\.[^\s"\'<>]+)'),
    re.compile(r'(https?://stats\.[^\s"\'<>]+)'),
    re.compile(r'(https?://metrics\.[^\s"\'<>]+)'),
    re.compile(r'(https?://tracking\.[^\s"\'<>]+)'),
    
    # Payment/Checkout URLs
    re.compile(r'(https?://[a-zA-Z0-9.-]+/checkout[^\s"\'<>]*)'),
    re.compile(r'(https?://[a-zA-Z0-9.-]+/payment[^\s"\'<>]*)'),
    re.compile(r'(https?://checkout\.[^\s"\'<>]+)'),
    re.compile(r'(https?://payment\.[^\s"\'<>]+)'),
    re.compile(r'(https?://pay\.[^\s"\'<>]+)'),
    
    # Third-party service URLs
    re.compile(r'(https?://hooks\.slack\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://discord\.com/api/webhooks[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.telegram\.org[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.whatsapp\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.stripe\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.paypal\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.twilio\.com[^\s"\'<>]*)'),
    re.compile(r'(https?://api\.sendgrid\.com[^\s"\'<>]*)'),
    
    # Generic suspicious URL patterns
    re.compile(r'(https?://[^\s"\'<>]*[=&?](?:password|token|key|secret|auth)=[^\s"\'<>]*)'),
    re.compile(r'(https?://[^\s"\'<>]*\?(?:[^&\s]*&){3,}[^\s"\'<>]*)'),  # URLs with many parameters
    re.compile(r'(https?://[^\s"\'<>]*@[^\s"\'<>]+)'),  # URLs with username/password
    
    # IP address URLs (not in private ranges)
    re.compile(r'(https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^\s"\'<>]*)'),
    
    # Shortened/obfuscated URLs
    re.compile(r'(https?://[a-zA-Z0-9]{6,12}\.[a-zA-Z]{2,6}[^\s"\'<>]*)'),  # Short domain names
    re.compile(r'(https?://[a-f0-9]{8,}\.[a-zA-Z]{2,6}[^\s"\'<>]*)'),  # Hex domain names
]

# Secret patterns
SECRET_PATTERNS = [
    (re.compile(r'(AKIA[0-9A-Z]{16,20})'), "AWS Access Key"),
    (re.compile(r'(ASIA[0-9A-Z]{16,20})'), "AWS Temporary Access Key"),
    (re.compile(r'(AIza[0-9A-Za-z\-_]{35,45})'), "Google API Key"),
    (re.compile(r'(sk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Secret Key"),
    (re.compile(r'(gh[pousr]_[0-9a-zA-Z]{36,})'), "GitHub Token"),
    (re.compile(r'(xox[baprs]-[0-9a-zA-Z\-]{10,48})'), "Slack Token"),
    (re.compile(r'(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})'), "JWT"),
    (re.compile(r'(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----)'), "Private Key"),
    (re.compile(r'(mongodb(?:\+srv)?://[^\s"\'\<>{}\[\]]+)'), "MongoDB URI"),
    (re.compile(r'(postgres(?:ql)?://[^\s"\'\<>{}\[\]]+)'), "PostgreSQL URI"),
    
    # Cloud Provider Secrets - Extended
    (re.compile(r'(AZURE_CLIENT_SECRET[=\s:]+["\']?[0-9a-zA-Z\-_]{40,}["\']?)'), "Azure Client Secret"),
    (re.compile(r'(DefaultAzureCredential[=\s:]+["\']?[0-9a-zA-Z\-_]{40,}["\']?)'), "Azure Default Credential"),
    (re.compile(r'(heroku_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'), "Heroku API Key"),
    (re.compile(r'(digitalocean_[0-9a-f]{64})'), "DigitalOcean Token"),
    (re.compile(r'(linode_token[=\s:]+["\']?[0-9a-f]{64}["\']?)'), "Linode Token"),
    (re.compile(r'(vultr_api_key[=\s:]+["\']?[0-9a-f]{64}["\']?)'), "Vultr API Key"),
    (re.compile(r'(gcp_service_account[=\s:]+["\']?[0-9a-zA-Z\-_]{24,}["\']?)'), "GCP Service Account"),
    
    # Payment Processors - Extended
    (re.compile(r'(sk_test_[0-9a-zA-Z]{24,})'), "Stripe Test Secret Key"),
    (re.compile(r'(pk_live_[0-9a-zA-Z]{24,})'), "Stripe Live Publishable Key"),
    (re.compile(r'(rk_live_[0-9a-zA-Z]{24,})'), "Razorpay Live Key"),
    (re.compile(r'(rk_test_[0-9a-zA-Z]{24,})'), "Razorpay Test Key"),
    (re.compile(r'(paypal_client_id[=\s:]+["\']?[A-Za-z0-9_]{80,}["\']?)'), "PayPal Client ID"),
    (re.compile(r'(paypal_client_secret[=\s:]+["\']?[A-Za-z0-9_]{80,}["\']?)'), "PayPal Client Secret"),
    (re.compile(r'(square_access_token[=\s:]+["\']?EAAA[0-9a-zA-Z\-_]{80,}["\']?)'), "Square Access Token"),
    (re.compile(r'(braintree_private_key[=\s:]+["\']?[0-9a-zA-Z]{32}["\']?)'), "Braintree Private Key"),
    
    # Social Media/Platforms - Extended
    (re.compile(r'(twitter[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z]{25,}["\']?)'), "Twitter API Key"),
    (re.compile(r'(twitter[-\s]?api[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z]{50,}["\']?)'), "Twitter API Secret"),
    (re.compile(r'(facebook[-\s]?app[-\s]?secret[=\s:]+["\']?[0-9a-f]{32,}["\']?)'), "Facebook App Secret"),
    (re.compile(r'(facebook[-\s]?access[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{200,}["\']?)'), "Facebook Access Token"),
    (re.compile(r'(discord[-\s]?bot[-\s]?token[=\s:]+["\']?[A-Za-z0-9\.\-_]{59,}["\']?)'), "Discord Bot Token"),
    (re.compile(r'(discord[-\s]?client[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z\-_]{32}["\']?)'), "Discord Client Secret"),
    (re.compile(r'(instagram[-\s]?access[-\s]?token[=\s:]+["\']?[0-9a-f]{200,}["\']?)'), "Instagram Access Token"),
    (re.compile(r'(linkedin[-\s]?client[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z]{16}["\']?)'), "LinkedIn Client Secret"),
    (re.compile(r'(reddit[-\s]?secret[=\s:]+["\']?[0-9a-zA-Z\-_]{30,}["\']?)'), "Reddit Secret"),
    
    # Communication Services - Extended
    (re.compile(r'(twilio[-\s]?account[-\s]?sid[=\s:]+["\']?AC[0-9a-f]{32}["\']?)'), "Twilio Account SID"),
    (re.compile(r'(twilio[-\s]?auth[-\s]?token[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "Twilio Auth Token"),
    (re.compile(r'(sendgrid[-\s]?api[-\s]?key[=\s:]+["\']?SG\.[0-9a-zA-Z\-_]{66,}["\']?)'), "SendGrid API Key"),
    (re.compile(r'(nexmo[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{8}["\']?)'), "Nexmo/Vonage API Key"),
    (re.compile(r'(nexmo[-\s]?api[-\s]?secret[=\s:]+["\']?[0-9a-f]{16}["\']?)'), "Nexmo/Vonage API Secret"),
    (re.compile(r'(plivo[-\s]?auth[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{40}["\']?)'), "Plivo Auth Token"),
    (re.compile(r'(messagebird[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z]{25}["\']?)'), "MessageBird API Key"),
    
    # CI/CD & DevOps
    (re.compile(r'(dockerhub[-\s]?token[=\s:]+["\']?[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?)'), "DockerHub Token"),
    (re.compile(r'(circleci[-\s]?token[=\s:]+["\']?[0-9a-f]{40}["\']?)'), "CircleCI Token"),
    (re.compile(r'(travisci[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{22,}["\']?)'), "Travis CI Token"),
    (re.compile(r'(jenkins[-\s]?token[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "Jenkins Token"),
    (re.compile(r'(gitlab[-\s]?token[=\s:]+["\']?glpat-[0-9a-zA-Z\-_]{20,}["\']?)'), "GitLab Personal Access Token"),
    (re.compile(r'(bitbucket[-\s]?token[=\s:]+["\']?[0-9a-zA-Z]{64}["\']?)'), "Bitbucket Token"),
    (re.compile(r'(npm[-\s]?token[=\s:]+["\']?npm_[0-9a-zA-Z\-_]{36}["\']?)'), "NPM Token"),  # Fixed line
    (re.compile(r'(pypi[-\s]?token[=\s:]+["\']?pypi-[0-9a-zA-Z\-_]{40,}["\']?)'), "PyPI Token"),
    
    # Database & Storage - Extended
    (re.compile(r'(redis://:[^\s@]+@[^\s"\']+)'), "Redis URI with Password"),
    (re.compile(r'(redis[-\s]?password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "Redis Password"),
    (re.compile(r'(mysql://[^\s"\']+:[^\s"\']+@[^\s"\']+)'), "MySQL URI with Credentials"),
    (re.compile(r'(mysql[-\s]?password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "MySQL Password"),
    (re.compile(r'(cassandra[-\s]?password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "Cassandra Password"),
    (re.compile(r'(amazonaws\.com/[^\s"\']*[=\s:]+["\']?[0-9a-zA-Z/+]{40,}["\']?)'), "AWS S3/CloudFront"),
    (re.compile(r'(firebase[-\s]?api[-\s]?key[=\s:]+["\']?AIza[0-9A-Za-z\-_]{35}["\']?)'), "Firebase API Key"),
    (re.compile(r'(firebase[-\s]?database[-\s]?url[=\s:]+["\']?https://[^\s"\']+firebaseio\.com["\']?)'), "Firebase Database URL"),
    
    # Monitoring & Analytics
    (re.compile(r'(newrelic[-\s]?license[-\s]?key[=\s:]+["\']?[0-9a-f]{40}["\']?)'), "New Relic License Key"),
    (re.compile(r'(sentry[-\s]?dsn[=\s:]+["\']?https://[0-9a-f]{32}@[^\s"\']+["\']?)'), "Sentry DSN"),
    (re.compile(r'(datadog[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "Datadog API Key"),
    (re.compile(r'(splunk[-\s]?token[=\s:]+["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?)'), "Splunk Token"),
    (re.compile(r'(logdna[-\s]?ingestion[-\s]?key[=\s:]+["\']?[0-9a-f]{32}["\']?)'), "LogDNA Ingestion Key"),
    
    # Email Services - Extended
    (re.compile(r'(mailgun[-\s]?api[-\s]?key[=\s:]+["\']?key-[0-9a-f]{32}["\']?)'), "Mailgun API Key"),
    (re.compile(r'(ses[-\s]?smtp[-\s]?password[=\s:]+["\']?[0-9a-zA-Z/+]{20,}["\']?)'), "AWS SES SMTP Password"),
    (re.compile(r'(sparkpost[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{40}["\']?)'), "SparkPost API Key"),
    (re.compile(r'(postmark[-\s]?server[-\s]?token[=\s:]+["\']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}["\']?)'), "Postmark Server Token"),
    (re.compile(r'(mailchimp[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{32}-us[0-9]{1,2}["\']?)'), "Mailchimp API Key"),
    
    # Content Delivery & CDN
    (re.compile(r'(cloudflare[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-f]{37}["\']?)'), "Cloudflare API Key"),
    (re.compile(r'(cloudflare[-\s]?auth[-\s]?key[=\s:]+["\']?[0-9a-f]{37}["\']?)'), "Cloudflare Auth Key"),
    (re.compile(r'(fastly[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z]{32}["\']?)'), "Fastly API Key"),
    
    # Map & Location Services
    (re.compile(r'(mapbox[-\s]?access[-\s]?token[=\s:]+["\']?pk\.[0-9a-zA-Z\-_]{100,}["\']?)'), "Mapbox Access Token"),
    (re.compile(r'(google[-\s]?maps[-\s]?api[-\s]?key[=\s:]+["\']?AIza[0-9A-Za-z\-_]{35}["\']?)'), "Google Maps API Key"),
    (re.compile(r'(here[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z\-_]{43}["\']?)'), "HERE API Key"),
    
    # AI/ML Services
    (re.compile(r'(openai[-\s]?api[-\s]?key[=\s:]+["\']?sk-[0-9a-zA-Z]{48}["\']?)'), "OpenAI API Key"),
    (re.compile(r'(anthropic[-\s]?api[-\s]?key[=\s:]+["\']?sk-ant-[0-9a-zA-Z\-_]{95}["\']?)'), "Anthropic API Key"),
    (re.compile(r'(cohere[-\s]?api[-\s]?key[=\s:]+["\']?[0-9a-zA-Z]{40}["\']?)'), "Cohere API Key"),
    (re.compile(r'(huggingface[-\s]?token[=\s:]+["\']?hf_[0-9a-zA-Z]{34}["\']?)'), "Hugging Face Token"),
    (re.compile(r'(replicate[-\s]?api[-\s]?token[=\s:]+["\']?r8_[0-9a-zA-Z]{37}["\']?)'), "Replicate API Token"),
    
    # Generic Patterns - Enhanced
    (re.compile(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'), "UUID"),
    (re.compile(r'([0-9a-zA-Z]{32,})'), "Generic Long Token"),
    (re.compile(r'(api[-\s_]?key[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Generic API Key"),
    (re.compile(r'(secret[-\s_]?key[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Generic Secret Key"),
    (re.compile(r'(password[=\s:]+["\']?[^\s"\']{6,}["\']?)'), "Password Field"),
    (re.compile(r'(token[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Generic Token"),
    (re.compile(r'(access[-\s_]?token[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Access Token"),
    (re.compile(r'(refresh[-\s_]?token[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Refresh Token"),
    
    # File-specific patterns
    (re.compile(r'(\.pem$|\.key$|\.priv$|\.cert$|\.crt$)', re.IGNORECASE), "Certificate/Key File"),
    (re.compile(r'(\.env$|\.env\.\w+$)', re.IGNORECASE), "Environment File"),
    
    # High entropy strings (increased length to reduce noise)
    (re.compile(r'([A-Za-z0-9+/]{64,}[=]{0,2})'), "Potential Base64 Secret"),
    
    # Config file specific
    (re.compile(r'(\$[A-Z_]{5,}[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Config Variable with Secret"),
    (re.compile(r'([A-Z_]{5,}_SECRET[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Secret Environment Variable"),
    (re.compile(r'([A-Z_]{5,}_KEY[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Key Environment Variable"),
    (re.compile(r'([A-Z_]{5,}_TOKEN[=\s:]+["\']?[0-9a-zA-Z\-_]{20,}["\']?)'), "Token Environment Variable"),
]

# Email pattern
EMAIL_PATTERN = re.compile(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})')

# File patterns - detect references to sensitive file types
FILE_PATTERNS = [
    # Comprehensive file extension patterns
    re.compile(
        r'["\']([a-zA-Z0-9_/.-]+\.(?:'
        # Data files
        r'sql|db|sqlite|sqlite3|mdb|accdb|dbf|mdf|'
        r'csv|tsv|tab|dat|data|'
        r'xlsx|xls|xlsm|xlsb|ods|'
        r'json|jsonl|ndjson|'
        r'xml|xhtml|xsd|xslt|rss|atom|'
        r'yaml|yml|toml|properties|'
        r'avro|parquet|orc|feather|'
        r'h5|hdf5|hdf|mat|'
        r'pkl|pickle|joblib|'
        r'tfrecord|recordio|'
        r'arrow|'
        # Config/logs
        r'conf|config|cfg|ini|inf|reg|'
        r'env|properties|settings|prefs|'
        r'log|logs|txt|text|md|markdown|rst|'
        r'xml|json|yaml|yml|'
        r'htaccess|htpasswd|'
        r'gitignore|gitattributes|gitmodules|'
        r'dockerignore|dockerfile|'
        r'editorconfig|'
        # Backups
        r'bak|backup|old|orig|copy|temp|tmp|'
        r'swp|swo|swn|'
        r'~|\$|'
        # Certificates/Keys
        r'key|pem|crt|cer|csr|der|'
        r'p12|pfx|p7b|p7c|spc|'
        r'jks|keystore|truststore|'
        r'gpg|pgp|asc|'
        r'pub|priv|'
        # Documents
        r'doc|docx|docm|odt|rtf|'
        r'pdf|'
        r'ppt|pptx|pptm|odp|'
        r'pages|numbers|key|'
        r'epub|mobi|azw|'
        r'html|htm|'
        # Archives
        r'zip|tar|gz|tgz|bz2|tbz2|xz|txz|'
        r'rar|7z|z|Z|lz|lzma|lzo|'
        r'iso|img|dmg|vhd|vdi|vmdk|'
        r'war|jar|ear|aar|'
        # Scripts/Executables
        r'sh|bash|zsh|fish|csh|tcsh|ksh|'
        r'bat|cmd|ps1|psm1|psd1|vbs|wsf|'
        r'py|pyc|pyo|pyd|pyw|pyx|'
        r'rb|erb|rake|gemspec|'
        r'pl|pm|t|'
        r'js|jsx|mjs|cjs|ts|tsx|'
        r'php|phtml|php3|php4|php5|php7|phps|'
        r'java|class|jar|'
        r'go|'
        r'rs|'
        r'cpp|c|cc|cxx|h|hpp|hh|hxx|'
        r'cs|vb|fs|'
        r'swift|m|mm|'
        r'kt|kts|'
        r'scala|'
        r'lua|'
        r'erl|hrl|'
        r'ex|exs|'
        r'clj|cljs|cljc|edn|'
        r'hs|lhs|'
        # Media files (potentially sensitive)
        r'jpg|jpeg|png|gif|bmp|tiff|tif|webp|'
        r'mp3|wav|flac|aac|ogg|m4a|'
        r'mp4|avi|mov|wmv|flv|mkv|webm|'
        r'svg|ico|icns|'
        # Database dumps
        r'dump|export|backup|restore|'
        # Virtual environments
        r'venv|virtualenv|env|'
        # Lock files
        r'lock|pid|'
        # Build/Compiled files
        r'exe|dll|so|dylib|a|lib|'
        r'o|obj|'
        r'bin|elf|'
        # Network/config
        r'pcap|cap|'
        r'pem|der|'
        # Cloud/Infrastructure
        r'tf|tfstate|tfvars|'
        r'yml|yaml|'
        r'json|'
        r'hcl|'
        # Other sensitive
        r'secret|private|hidden|'
        r'password|credential|token|'
        r'license|licence|'
        r'history|bash_history|'
        r'known_hosts|authorized_keys|'
        r'id_rsa|id_dsa|id_ecdsa|id_ed25519|'
        r'ssh|'
        r'vault|'
        r'kubeconfig|'
        r'terraform|'
        r'dockerconfig|'
        r'aws|azure|gcp|'
        r'secret|key|token'
        r'))["\']',
        re.IGNORECASE
    ),
    
    # Specific sensitive file name patterns (without extensions)
    re.compile(r'["\']((?:'
        r'\.env(?:\.\w+)?|'
        r'\.dockerignore|\.gitignore|\.npmignore|'
        r'\.htaccess|\.htpasswd|'
        r'\.bashrc|\.bash_profile|\.profile|\.zshrc|'
        r'\.ssh/config|\.ssh/authorized_keys|\.ssh/known_hosts|'
        r'\.aws/config|\.aws/credentials|'
        r'\.kube/config|'
        r'\.docker/config\.json|'
        r'\.npmrc|\.yarnrc|'
        r'\.pypirc|'
        r'\.gitconfig|\.git-credentials|'
        r'\.netrc|'
        r'\.pgpass|'
        r'\.my\.cnf|'
        r'\.plan|\.project|'
        r'\.travis\.yml|\.circleci/config\.yml|'
        r'\.github/workflows/.*\.yml|'
        r'\.vscode/settings\.json|'
        r'\.idea/.*|'
        r'\.DS_Store|'
        r'\.Trash|\.Trashes|'
        r'\.Spotlight-V100|'
        r'\.fseventsd|'
        r'\.metadata|'
        r'\.svn/.*|\.git/.*|\.hg/.*|'
        r'\.cache/.*|'
        r'\.config/.*|'
        r'\.local/.*|'
        r'\.m2/settings\.xml|'
        r'\.gradle/gradle\.properties|'
        r'\.composer/auth\.json|'
        r'\.npm/_auth|'
        r'\.pip/pip\.conf|'
        r'\.condarc|'
        r'\.bowerrc|'
        r'\.jfrog|'
        r'\.snyk|'
        r'\.sops\.yaml|'
        r'\.pre-commit-config\.yaml|'
        r'\.renovaterc|'
        r'\.babelrc|'
        r'\.eslintrc|\.eslintrc\.json|\.eslintrc\.js|'
        r'\.prettierrc|\.prettierrc\.json|\.prettierrc\.js|'
        r'\.stylelintrc|'
        r'\.commitlintrc|'
        r'\.lintstagedrc|'
        r'\.huskyrc|'
        r'\.npmignore|'
        r'\.yarnrc\.yml|'
        r'\.yarn-integrity|'
        r'\.pnp\.js|'
        r'\.yarn/.*|'
        r'\.node_repl_history|'
        r'\.wget-hsts|'
        r'\.lesshst|'
        r'\.mysql_history|\.psql_history|\.sqlite_history|'
        r'\.rediscli_history|'
        r'\.dbshell|'
        r'\.mongorc\.js|\.mongoshrc\.js|'
        r'\.irb_history|'
        r'\.python_history|'
        r'\.jupyter/.*|'
        r'\.ipython/.*|'
        r'\.Rhistory|'
        r'\.bash_history|\.zsh_history|\.fish_history|'
        r'\.inputrc|'
        r'\.tmux\.conf|'
        r'\.screenrc|'
        r'\.viminfo|\.vimrc|\.gvimrc|'
        r'\.emacs|\.emacs\.d/.*|'
        r'\.gnupg/.*|'
        r'\.password-store/.*|'
        r'\.keepass|\.kdbx|'
        r'\.1password|'
        r'\.lastpass|'
        r'\.bitwarden|'
        r'\.vault-token|'
        r'\.terraformrc|\.terraform\.d/.*|'
        r'\.packer\.d/.*|'
        r'\.vagrant\.d/.*|'
        r'\.ansible/.*|'
        r'\.chef/.*|'
        r'\.puppet/.*|'
        r'\.salt/.*|'
        r'\.mina/.*|'
        r'\.capistrano/.*|'
        r'\.mina/.*|'
        r'\.mina_deploy/.*|'
        r'\.mina\.rb|'
        r'\.deploy/.*|'
        r'\.pm2/.*|'
        r'\.forever/.*|'
        r'\.pm2/.*|'
        r'\.systemd/.*|'
        r'\.init\.d/.*|'
        r'\.cron\.d/.*|'
        r'\.logrotate\.d/.*|'
        r'\.rsyslog\.d/.*|'
        r'\.nginx/.*|'
        r'\.apache2/.*|'
        r'\.httpd/.*|'
        r'\.tomcat/.*|'
        r'\.jetty/.*|'
        r'\.wildfly/.*|'
        r'\.jboss/.*|'
        r'\.weblogic/.*|'
        r'\.websphere/.*|'
        r'\.iis/.*|'
        r'\.phusion/.*|'
        r'\.passenger/.*|'
        r'\.unicorn/.*|'
        r'\.puma/.*|'
        r'\.thin/.*|'
        r'\.god/.*|'
        r'\.bluepill/.*|'
        r'\.eye/.*|'
        r'\.supervisor/.*|'
        r'\.monit/.*|'
        r'\.runit/.*|'
        r'\.s6/.*|'
        r'\.daemontools/.*|'
        r'\.launchd/.*|'
        r'\.upstart/.*|'
        r'\.systemd/.*|'
        r'\.init/.*|'
        r'\.rc\.d/.*|'
        r'\.profile\.d/.*|'
        r'\.bashrc\.d/.*|'
        r'\.zshrc\.d/.*|'
        r'\.config/.*|'
        r'\.local/.*|'
        r'\.cache/.*|'
        r'\.tmp/.*|'
        r'\.temp/.*|'
        r'\.trash/.*|'
        r'\.Trash/.*|'
        r'\.recycle/.*|'
        r'\.Recycle\.Bin/.*|'
        r'\.\$RECYCLE\.BIN/.*|'
        r'\.found\.\d+/.*|'
        r'\.lost\+found/.*|'
        r'\.fseventsd/.*|'
        r'\.Spotlight-V100/.*|'
        r'\.TemporaryItems/.*|'
        r'\.Trashes/.*|'
        r'\.VolumeIcon\.icns|'
        r'\.DS_Store|'
        r'\.AppleDouble|'
        r'\.LSOverride|'
        r'\.AppleDB|'
        r'\.AppleDesktop|'
        r'\.AppleProfile|'
        r'\.ParentalControls|'
        r'\.DocumentRevisions-V100|'
        r'\.MobileBackups|'
        r'\.PKInstallSandboxManager|'
        r'\.file|'
        r'\.metadata|'
        r'\.idea|'
        r'\.vscode|'
        r'\.atom|'
        r'\.sublime-project|\.sublime-workspace|'
        r'\.vs/.*|'
        r'\.project|\.classpath|'
        r'\.settings/.*|'
        r'\.buildpath|'
        r'\.factorypath|'
        r'\.springBeans|'
        r'\.externalToolBuilders/.*|'
        r'\.recommenders/.*|'
        r'\.eclipse/.*|'
        r'\.metadata/.*|'
        r'\.mvn/.*|'
        r'\.gradle/.*|'
        r'\.sbt/.*|'
        r'\.bloop/.*|'
        r'\.mill/.*|'
        r'\.coursier/.*|'
        r'\.ivy2/.*|'
        r'\.sbt\.boot/.*|'
        r'\.activator/.*|'
        r'\.play/.*|'
        r'\.npm/.*|'
        r'\.node-gyp/.*|'
        r'\.node_repl_history|'
        r'\.yarn/.*|'
        r'\.bower/.*|'
        r'\.jspm/.*|'
        r'\.typings/.*|'
        r'\.tsd/.*|'
        r'\.dart/.*|'
        r'\.pub-cache/.*|'
        r'\.flutter/.*|'
        r'\.cargo/.*|'
        r'\.rustup/.*|'
        r'\.go/.*|'
        r'\.gopath/.*|'
        r'\.glide/.*|'
        r'\.dep/.*|'
        r'\.vendor/.*|'
        r'\.vendor-cache/.*|'
        r'\.bundle/.*|'
        r'\.rvm/.*|'
        r'\.rbenv/.*|'
        r'\.gem/.*|'
        r'\.gems/.*|'
        r'\.bundler/.*|'
        r'\.rake/.*|'
        r'\.rails/.*|'
        r'\.migrations/.*|'
        r'\.seeds\.rb|'
        r'\.schema\.rb|'
        r'\.fixtures\.yml|'
        r'\.factories\.rb|'
        r'\.spec_helper\.rb|'
        r'\.rails_helper\.rb|'
        r'\.rspec|'
        r'\.guard\.rb|'
        r'\.simplecov|'
        r'\.coverage/.*|'
        r'\.yardoc/.*|'
        r'\.ri/.*|'
        r'\.rdoc/.*|'
        r'\.pryrc|\.irbrc|'
        r'\.ruby-version|\.ruby-gemset|'
        r'\.python-version|'
        r'\.requirements\.txt|'
        r'\.pip-tools/.*|'
        r'\.pipenv/.*|'
        r'\.poetry/.*|'
        r'\.venv/.*|\.virtualenv/.*|'
        r'\.conda/.*|'
        r'\.anaconda/.*|'
        r'\.jupyter/.*|'
        r'\.ipython/.*|'
        r'\.python_history|'
        r'\.node_version|'
        r'\.nvmrc|'
        r'\.npmrc|'
        r'\.yarnrc|'
        r'\.bowerrc|'
        r'\.composer/.*|'
        r'\.phar|'
        r'\.pearrc|'
        r'\.php-version|'
        r'\.phpenv/.*|'
        r'\.hhvm/.*|'
        r'\.wp-cli/.*|'
        r'\.drush/.*|'
        r'\.drupal/.*|'
        r'\.wordpress/.*|'
        r'\.joomla/.*|'
        r'\.magento/.*|'
        r'\.prestashop/.*|'
        r'\.opencart/.*|'
        r'\.woocommerce/.*|'
        r'\.shopify/.*|'
        r'\.bigcommerce/.*|'
        r'\.squarespace/.*|'
        r'\.wix/.*|'
        r'\.weebly/.*|'
        r'\.webflow/.*|'
        r'\.ghost/.*|'
        r'\.jekyll/.*|'
        r'\.hugo/.*|'
        r'\.gatsby/.*|'
        r'\.next/.*|'
        r'\.nuxt/.*|'
        r'\.vue/.*|'
        r'\.react/.*|'
        r'\.angular/.*|'
        r'\.ember/.*|'
        r'\.backbone/.*|'
        r'\.meteor/.*|'
        r'\.sails/.*|'
        r'\.loopback/.*|'
        r'\.nestjs/.*|'
        r'\.adonis/.*|'
        r'\.laravel/.*|'
        r'\.symfony/.*|'
        r'\.zend/.*|'
        r'\.cakephp/.*|'
        r'\.codeigniter/.*|'
        r'\.yii/.*|'
        r'\.phalcon/.*|'
        r'\.slim/.*|'
        r'\.lumen/.*|'
        r'\.fuelphp/.*|'
        r'\.kohana/.*|'
        r'\.aura/.*|'
        r'\.bearframework/.*|'
        r'\.bolt/.*|'
        r'\.cms/.*|'
        r'\.concrete5/.*|'
        r'\.contao/.*|'
        r'\.craftcms/.*|'
        r'\.dokuwiki/.*|'
        r'\.drupal/.*|'
        r'\.expressionengine/.*|'
        r'\.grav/.*|'
        r'\.joomla/.*|'
        r'\.kirby/.*|'
        r'\.magento/.*|'
        r'\.mediawiki/.*|'
        r'\.modx/.*|'
        r'\.octobercms/.*|'
        r'\.opencart/.*|'
        r'\.pagekit/.*|'
        r'\.phpbb/.*|'
        r'\.pimcore/.*|'
        r'\.prestashop/.*|'
        r'\.processwire/.*|'
        r'\.pyrocms/.*|'
        r'\.redaxo/.*|'
        r'\.silverstripe/.*|'
        r'\.spip/.*|'
        r'\.squiz/.*|'
        r'\.statamic/.*|'
        r'\.subrion/.*|'
        r'\.textpattern/.*|'
        r'\.typo3/.*|'
        r'\.umbraco/.*|'
        r'\.vbulletin/.*|'
        r'\.wolfcms/.*|'
        r'\.wordpress/.*|'
        r'\.xenforo/.*|'
        r'\.zikula/.*|'
        r'secret|private|confidential|'
        r'passwords|credentials|tokens|keys|'
        r'\.swp|\.swo|\.swn|'
        r'\.DS_Store|'
        r'Thumbs\.db|'
        r'desktop\.ini|'
        r'\$\$.*\$\$'
    r'))["\']', re.IGNORECASE),
    
    # Pattern for files with sensitive names (regardless of extension)
    re.compile(
        r'["\']([a-zA-Z0-9_/.-]*(?:'
        r'password|credential|secret|token|key|'
        r'private|confidential|hidden|internal|'
        r'backup|dump|archive|snapshot|'
        r'config|setting|profile|preference|'
        r'log|debug|trace|audit|'
        r'database|db|data|'
        r'admin|root|superuser|'
        r'license|licence|'
        r'\.old|\.new|\.orig|\.copy|\.tmp|\.temp|\.bak'
        r')[a-zA-Z0-9_/.-]*\.[a-zA-Z0-9]+)["\']',
        re.IGNORECASE
    ),
    
    # Pattern for files in sensitive directories
    re.compile(
        r'["\'](?:'
        r'\.(?:git|svn|hg)/.*|'
        r'\.?config/.*|'
        r'\.?secrets/.*|'
        r'\.?private/.*|'
        r'\.?secure/.*|'
        r'\.?backup/.*|'
        r'\.?archive/.*|'
        r'\.?log/.*|'
        r'\.?tmp/.*|'
        r'\.?temp/.*|'
        r'\.?cache/.*|'
        r'\.?trash/.*|'
        r'\.?recycle/.*|'
        r'\.?dump/.*|'
        r'\.?snapshot/.*'
        r')["\']',
        re.IGNORECASE
    ),
    
    # Pattern for suspicious file paths (Windows)
    re.compile(r'["\']([A-Za-z]:\\[^\s"\']+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|reg|pif|scr|msi|msp))["\']', re.IGNORECASE),
    
    # Pattern for suspicious file paths (Unix)
    re.compile(r'["\'](/etc/[^\s"\']+|/var/log/[^\s"\']+|/tmp/[^\s"\']+|/root/[^\s"\']+|/home/[^/]+/[^\s"\']+)["\']'),
    
    # Pattern for files with version numbers (potentially backups)
    re.compile(r'["\']([a-zA-Z0-9_/.-]+\.(?:v\d+|version\d+|_\d{8}|_\d{6}|-\d{8}|-\d{6}|\d{14}|\d{8}))["\']', re.IGNORECASE),
]

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
        self.source_map = {}  # Store source body by name
        
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
        
        # Store source body for later viewing
        self.source_map[source_name] = body
        
        # 1. Extract endpoints
        for pattern in ENDPOINT_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip()
                if self._is_valid_endpoint(value):
                    finding = self._add_finding("endpoints", value, source_name, match.start(1))
                    if finding:
                        new_findings.append(finding)
        
        # 2. URLs
        for pattern in URL_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                start_offset = match.start(1) if match.lastindex else match.start(0)
                if self._is_valid_url(value):
                    finding = self._add_finding("urls", value, source_name, start_offset)
                    if finding:
                        new_findings.append(finding)
        
        # 3. Secrets
        for pattern, _ in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                start_offset = match.start(1) if match.lastindex else match.start(0)
                if self._is_valid_secret(value):
                    # Show full secret as requested by user
                    finding = self._add_finding("secrets", value, source_name, start_offset)
                    if finding:
                        new_findings.append(finding)
        
        # 4. Emails
        for match in EMAIL_PATTERN.finditer(body):
            value = match.group(1).strip()
            if self._is_valid_email(value):
                finding = self._add_finding("emails", value, source_name, match.start(1))
                if finding:
                    new_findings.append(finding)
        
        # 5. Files (sensitive file references)
        for pattern in FILE_PATTERNS:
            for match in pattern.finditer(body):
                value = match.group(1).strip() if match.lastindex else match.group(0).strip()
                start_offset = match.start(1) if match.lastindex else match.start(0)
                if self._is_valid_file(value):
                    finding = self._add_finding("files", value, source_name, start_offset)
                    if finding:
                        new_findings.append(finding)
        
        # Update UI
        if new_findings:
            self._log("Found %d new items" % len(new_findings))
            self.panel.add_findings(new_findings, source_name)
        else:
            self._log("No new findings")
    
    def _add_finding(self, category, value, source, offset=0):
        """Add a finding if not duplicate."""
        key = category + ":" + value
        if key in self.seen_values:
            return None
        
        self.seen_values.add(key)
        finding = {
            "category": category,
            "value": value,
            "source": source,
            "offset": offset,
        }
        self.all_findings.append(finding)
        return finding
    
    def get_source_code(self, source_name):
        """Retrieve source code for a given source name."""
        return self.source_map.get(source_name, "")
    
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
        
        # Filter placeholders
        if any(x in val_lower for x in ['example', 'placeholder', 'your', 'xxxx', 'test', 'your-']):
            return False
            
        # Filter common character sets
        if 'abcdefg' in val_lower or '0123456' in val_lower:
            return False
            
        # Filter GTM/CamelCase noise (Google Tag Manager, common JS events)
        if any(value.startswith(x) for x in [
            'enableAuto', 'unsubscribe', 'onElement', 'onForm', 
            'onYouTube', 'crossContainer', 'js'
        ]):
            return False
            
        # Filter strings that are too "regular" (mostly repetition)
        if len(set(value)) < 6:
            return False
            
        # Skip if it looks like a hex string that is too regular (like a color or padding)
        if all(c in '0123456789abcdefABCDEF' for c in value) and len(set(value)) < 4:
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
        self.source_map = {}
    
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
