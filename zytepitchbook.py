diff --git a/zytepitchbook.py b/zytepitchbook.py
--- a/zytepitchbook.py
+++ b/zytepitchbook.py
@@ -1,1963 +1,1333 @@
-diff --git a/zytepitchbook.py b/zytepitchbook.py
---- a/zytepitchbook.py
-+++ b/zytepitchbook.py
-@@ -1,998 +1,959 @@
--# pip install requests beautifulsoup4 tenacity
--
--import os
--import csv
--import time
--import random
--import re
--import uuid
--import hashlib
--from dataclasses import dataclass, field
--from typing import Callable, Dict, Iterable, List, Optional, Tuple
--from urllib.parse import urljoin, urlencode, urlparse
--
--import requests
--from bs4 import BeautifulSoup
--from bs4.element import Tag
--from tenacity import retry, wait_exponential_jitter, stop_after_attempt
--
--
--def _strip_or_none(value: Optional[str]) -> Optional[str]:
--    if value is None:
--        return None
--    value = value.strip()
--    return value or None
--
--
--ZYTE_API_KEY = os.getenv("ZYTE_API_KEY")
--if not ZYTE_API_KEY:
--    raise RuntimeError("ZYTE_API_KEY env var is not set. In PowerShell: $env:ZYTE_API_KEY='YOUR_KEY'")
--
--ZYTE_ENDPOINT = "https://api.zyte.com/v1/extract"
--PITCHBOOK_LOGIN_URL_DEFAULT = "https://pitchbook.com/account/login"
--
--
--def _origin(url: Optional[str]) -> Optional[str]:
--    if not url:
--        return None
--    parsed = urlparse(url)
--    if not parsed.scheme or not parsed.netloc:
--        return None
--    return f"{parsed.scheme}://{parsed.netloc}"
--
--
--def _registrable_domain(host: Optional[str]) -> Optional[str]:
--    if not host:
--        return None
--    parts = host.split(".")
--    if len(parts) < 2:
--        return host
--    return ".".join(parts[-2:])
--
--
--def _sec_fetch_site(target_url: Optional[str], referer: Optional[str]) -> str:
--    if not referer:
--        return "none"
--    target = urlparse(target_url or "")
--    ref = urlparse(referer)
--    if not target.netloc or not ref.netloc:
--        return "none"
--    if target.netloc == ref.netloc:
--        return "same-origin"
--    if _registrable_domain(target.hostname) == _registrable_domain(ref.hostname):
--        return "same-site"
--    return "cross-site"
--
--
--def _ensure_tuple(value: Optional[Iterable[str]]) -> Tuple[str, ...]:
--    if value is None:
--        return tuple()
--    if isinstance(value, (list, tuple)):
--        return tuple(value)
--    return (value,)
--
--
--@dataclass(frozen=True)
--class BrowserIdentity:
--    label: str
--    user_agent: str
--    accept_language: str
--    sec_ch_ua: str
--    sec_ch_ua_mobile: str
--    sec_ch_ua_platform: str
--
--    def document_headers(
--        self,
--        target_url: Optional[str],
--        referer: Optional[str] = None,
--        navigation: str = "navigate",
--        dest: str = "document",
--    ) -> Dict[str, str]:
--        headers = {
--            "User-Agent": self.user_agent,
--            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
--            "Accept-Language": self.accept_language,
--            "Accept-Encoding": "gzip, deflate, br",
--            "Connection": "keep-alive",
--            "sec-ch-ua": self.sec_ch_ua,
--            "sec-ch-ua-mobile": self.sec_ch_ua_mobile,
--            "sec-ch-ua-platform": self.sec_ch_ua_platform,
--            "Sec-Fetch-Mode": navigation,
--            "Sec-Fetch-Dest": dest,
--            "Sec-Fetch-Site": _sec_fetch_site(target_url, referer),
--        }
--        if navigation == "navigate":
--            headers["Sec-Fetch-User"] = "?1"
--            headers["Upgrade-Insecure-Requests"] = "1"
--        if referer:
--            headers["Referer"] = referer
--        return headers
--
--    def form_headers(self, target_url: Optional[str], referer: Optional[str]) -> Dict[str, str]:
--        headers = self.document_headers(target_url, referer)
--        origin = _origin(target_url)
--        if origin:
--            headers["Origin"] = origin
--        headers["Content-Type"] = "application/x-www-form-urlencoded"
--        return headers
--
--
--IDENTITY_POOL: Tuple[BrowserIdentity, ...] = (
--    BrowserIdentity(
--        label="win-chrome-124",
--        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
--        accept_language="en-US,en;q=0.9",
--        sec_ch_ua='"Not/A)Brand";v="24", "Chromium";v="124", "Google Chrome";v="124"',
--        sec_ch_ua_mobile="?0",
--        sec_ch_ua_platform='"Windows"',
--    ),
--    BrowserIdentity(
--        label="mac-chrome-123",
--        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
--        accept_language="en-US,en;q=0.9",
--        sec_ch_ua='"Not.A/Brand";v="8", "Chromium";v="123", "Google Chrome";v="123"',
--        sec_ch_ua_mobile="?0",
--        sec_ch_ua_platform='"macOS"',
--    ),
--    BrowserIdentity(
--        label="win-edge-124",
--        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
--        accept_language="en-US,en;q=0.9",
--        sec_ch_ua='"Not/A)Brand";v="24", "Chromium";v="124", "Microsoft Edge";v="124"',
--        sec_ch_ua_mobile="?0",
--        sec_ch_ua_platform='"Windows"',
--    ),
--)
--
--
--def _resolve_identity(session_id: str, override_ua: Optional[str]) -> BrowserIdentity:
--    if override_ua:
--        return BrowserIdentity(
--            label="custom",
--            user_agent=override_ua,
--            accept_language="en-US,en;q=0.9",
--            sec_ch_ua='"Not/A)Brand";v="24", "Chromium";v="124", "Google Chrome";v="124"',
--            sec_ch_ua_mobile="?0",
--            sec_ch_ua_platform='"Windows"',
--        )
--    digest = hashlib.sha256(session_id.encode("utf-8")).digest()
--    idx = digest[0] % len(IDENTITY_POOL)
--    return IDENTITY_POOL[idx]
--
--
--class AuthenticationError(RuntimeError):
--    pass
--
--
--class ChallengeError(RuntimeError):
--    pass
--
--
--class ThrottleError(RuntimeError):
--    pass
--
--
--@dataclass
--class PageContent:
--    url: str
--    html: str
--    soup: BeautifulSoup
--    status: Optional[int] = None
--
--
--@dataclass
--class ListConfig:
--    name: str
--    base: str
--    build_search_url: Callable[[str], str]
--    row_selectors: Iterable[str]
--    field_selectors: Dict[str, Iterable[str]]
--    optional_fields: Dict[str, Iterable[str]] = field(default_factory=dict)
--    next_selectors: Iterable[str] = field(default_factory=lambda: ("li.next a",))
--    columns: List[str] = field(default_factory=list)
--    max_pages: int = 500
--    page_sleep_range: Tuple[float, float] = (0.6, 2.0)
--    requires_login: bool = True
--    empty_result_markers: Tuple[str, ...] = ("No results found", "Try adjusting your filters")
--
--    def __post_init__(self) -> None:
--        self.row_selectors = _ensure_tuple(self.row_selectors)
--        self.next_selectors = _ensure_tuple(self.next_selectors)
--        self.field_selectors = {key: _ensure_tuple(value) for key, value in self.field_selectors.items()}
--        self.optional_fields = {key: _ensure_tuple(value) for key, value in self.optional_fields.items()}
--        if not self.columns:
--            ordered: List[str] = list(self.field_selectors.keys())
--            for col in self.optional_fields.keys():
--                if col not in ordered:
--                    ordered.append(col)
--            self.columns = ordered
--
--
--@dataclass
--class PitchbookAuthOptions:
--    email: Optional[str] = None
--    password: Optional[str] = None
--    session_id: Optional[str] = None
--    user_agent: Optional[str] = None
--    login_url: Optional[str] = None
--    login_form_selector: Optional[str] = None
--    email_field: Optional[str] = None
--    password_field: Optional[str] = None
--
--    def __post_init__(self) -> None:
--        self.email = _strip_or_none(self.email)
--        self.password = _strip_or_none(self.password)
--        self.session_id = _strip_or_none(self.session_id)
--        self.user_agent = _strip_or_none(self.user_agent)
--        self.login_url = _strip_or_none(self.login_url)
--        self.login_form_selector = _strip_or_none(self.login_form_selector)
--        self.email_field = _strip_or_none(self.email_field)
--        self.password_field = _strip_or_none(self.password_field)
--
--    def resolved_login_url(self) -> str:
--        return self.login_url or PITCHBOOK_LOGIN_URL_DEFAULT
--
--    def resolved_session_id(self) -> str:
--        return self.session_id or f"pitchbook-{uuid.uuid4().hex}"
--
--    def has_credentials(self) -> bool:
--        return bool(self.email and self.password)
--
--
--class AdaptiveThrottle:
--    def __init__(self, base_range: Tuple[float, float]):
--        self.base_low, self.base_high = base_range
--        self.penalty = random.uniform(0.2, 1.0)
--
--    def propose_delay(self, modifier: float = 0.0) -> float:
--        jitter_low = max(0.2, self.base_low + random.uniform(-0.5, 0.5))
--        jitter_high = max(jitter_low + 0.6, self.base_high + random.uniform(-0.3, 0.9))
--        delay = random.uniform(jitter_low, jitter_high) + self.penalty + modifier + random.uniform(0, 0.4)
--        return max(0.2, delay)
--
--    def record_success(self) -> None:
--        if self.penalty > 0:
--            self.penalty = max(0.0, self.penalty - random.uniform(0.1, 0.4))
--
--    def record_penalty(self, severity: float = 1.5) -> None:
--        self.penalty = min(18.0, self.penalty + severity)
--class ZyteSessionClient:
--    def __init__(self, api_key: str, auth: Optional[PitchbookAuthOptions] = None):
--        self.api_key = api_key
--        self.auth = auth or PitchbookAuthOptions()
--        self.session_id = self.auth.resolved_session_id()
--        self.identity = _resolve_identity(self.session_id, self.auth.user_agent)
--        self.login_url = self.auth.resolved_login_url()
--        self._authenticated = False
--        self._auth_failures = 0
--        self._last_url: Optional[str] = None
--
--    @retry(wait=wait_exponential_jitter(initial=1, max=12), stop=stop_after_attempt(5))
--    def _request_zyte(self, payload: Dict) -> Dict:
--        response = requests.post(
--            ZYTE_ENDPOINT,
--            auth=(self.api_key, ""),
--            json=payload,
--            timeout=70,
--            headers={"Content-Type": "application/json"},
--        )
--        if response.status_code == 400:
--            try:
--                print("Zyte 400:", response.json())
--            except Exception:
--                print("Zyte 400 raw:", response.text[:500])
--        response.raise_for_status()
--        return response.json()
--
--    def _extract_status(self, data: Dict) -> Optional[int]:
--        for key in ("statusCode", "httpResponseStatusCode", "httpResponseStatus"):
--            value = data.get(key)
--            if isinstance(value, int):
--                return value
--            try:
--                return int(value)  # type: ignore[arg-type]
--            except (TypeError, ValueError):
--                continue
--        return None
--
--    def _html_from(self, data: Dict) -> str:
--        return data.get("browserHtml") or data.get("httpResponseBody") or ""
--
--    def _classify_page(self, soup: BeautifulSoup) -> Optional[str]:
--        if soup is None:
--            return None
--        login_form: Optional[Tag] = None
--        for form in soup.find_all("form"):
--            action = (form.get("action") or "").lower()
--            form_id = (form.get("id") or "").lower()
--            form_classes = " ".join(form.get("class", [])).lower()
--            if any(trigger in action for trigger in ("login", "signin")) or "login" in form_id or "login" in form_classes:
--                login_form = form
--                break
--        if login_form is None:
--            password_input = soup.find("input", {"type": "password"})
--            if password_input:
--                parent_form = password_input.find_parent("form")
--                if parent_form:
--                    login_form = parent_form
--        if login_form:
--            form_text = login_form.get_text(" ", strip=True).lower()
--            if any(trigger in form_text for trigger in ("verification code", "multi-factor", "mfa", "one-time code", "security code")):
--                return "challenge"
--            return "login"
--        text = soup.get_text(" ", strip=True).lower()
--        text = text[:8000]
--        if any(token in text for token in ("verify you are human", "captcha", "security check", "robot check", "please enable javascript")):
--            return "challenge"
--        if any(token in text for token in ("too many requests", "rate limit", "temporarily blocked", "unusual traffic", "request limit", "throttled", "quota exceeded")):
--            return "throttle"
--        return None
--
--    def _locate_login_form(self, soup: BeautifulSoup) -> Optional[Tag]:
--        if self.auth.login_form_selector:
--            form = soup.select_one(self.auth.login_form_selector)
--            if form:
--                return form
--        candidates = soup.find_all("form")
--        for form in candidates:
--            action = (form.get("action") or "").lower()
--            form_id = (form.get("id") or "").lower()
--            form_classes = " ".join(form.get("class", [])).lower()
--            if any(trigger in action for trigger in ("login", "signin")) or "login" in form_id or "login" in form_classes:
--                return form
--        return candidates[0] if candidates else None
--
--    def _guess_input_name(self, form: Tag, keywords: List[str], input_type: Optional[str]) -> Optional[str]:
--        if input_type:
--            input_tag = form.find("input", {"type": input_type})
--            if input_tag and input_tag.get("name"):
--                return input_tag["name"]
--        for keyword in keywords:
--            candidate = form.find("input", {"name": keyword})
--            if candidate:
--                return keyword
--        for input_tag in form.find_all("input"):
--            name = input_tag.get("name")
--            if not name:
--                continue
--            lower_name = name.lower()
--            if any(keyword in lower_name for keyword in keywords):
--                return name
--        return None
--
--    def _build_form_payload(self, form: Tag) -> Tuple[str, str, Dict[str, str]]:
--        payload: Dict[str, str] = {}
--        for input_tag in form.find_all("input"):
--            name = input_tag.get("name")
--            if not name:
--                continue
--            value = input_tag.get("value")
--            payload[name] = value if value is not None else ""
--        email_field = self.auth.email_field or self._guess_input_name(form, ["email", "username", "user"], "email")
--        password_field = self.auth.password_field or self._guess_input_name(form, ["password", "pass"], "password")
--        if not email_field or not password_field:
--            raise RuntimeError("Unable to infer email/password fields on the PitchBook login form.")
--        payload[email_field] = self.auth.email or ""
--        payload[password_field] = self.auth.password or ""
--        action_attr = form.get("action") or ""
--        method = (form.get("method") or "post").upper()
--        return action_attr, method, payload
--
--    def _submit_form(self, action_url: str, method: str, payload: Dict[str, str], referer: str) -> PageContent:
--        cleaned_url = action_url or self.login_url
--        absolute_url = urljoin(referer, cleaned_url)
--        if method == "GET":
--            query = urlencode(payload)
--            full_url = absolute_url
--            if query:
--                delimiter = "&" if "?" in full_url else "?"
--                full_url = f"{full_url}{delimiter}{query}"
--            request_payload = {
--                "url": full_url,
--                "browserHtml": True,
--            }
--            return self._render(request_payload, allow_login=False, referer=referer)
--        request_payload = {
--            "url": absolute_url,
--            "browserHtml": True,
--            "httpRequestMethod": method,
--            "httpRequestBody": urlencode(payload),
--            "httpRequestHeaders": self.identity.form_headers(absolute_url, referer),
--        }
--        return self._render(request_payload, allow_login=False, referer=referer)
--
--    def _render(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
--        request_payload = dict(payload)
--        target_url = request_payload.get("url")
--        base_headers = self.identity.document_headers(target_url, referer)
--        extra_headers = request_payload.get("httpRequestHeaders") or {}
--        if extra_headers:
--            base_headers.update(extra_headers)
--        request_payload["httpRequestHeaders"] = base_headers
--        session_spec = request_payload.setdefault("session", {})
--        session_spec.setdefault("id", self.session_id)
--
--        data = self._request_zyte(request_payload)
--        html = self._html_from(data)
--        soup = BeautifulSoup(html, "html.parser") if html else BeautifulSoup("", "html.parser")
--        classification = self._classify_page(soup)
--        if classification == "login" and not allow_login:
--            self._authenticated = False
--            raise AuthenticationError("PitchBook responded with a login form.")
--        if classification == "challenge":
--            self._authenticated = False
--            raise ChallengeError("PitchBook responded with a verification challenge.")
--        if classification == "throttle":
--            raise ThrottleError("PitchBook reported throttling or quota limits.")
--        status_code = self._extract_status(data)
--        return PageContent(url=target_url, html=html, soup=soup, status=status_code)
--
--    def ensure_logged_in(self, require: bool = False) -> None:
--        if self._authenticated:
--            return
--        if not self.auth.has_credentials():
--            if require:
--                raise RuntimeError(
--                    "PitchBook authentication required but no credentials provided. "
--                    "Set PITCHBOOK_EMAIL/PITCHBOOK_PASSWORD or pass --pitchbook-email/--pitchbook-password."
--                )
--            return
--        if self._auth_failures >= 3:
--            if require:
--                raise RuntimeError("PitchBook authentication failed after multiple attempts.")
--            return
--        try:
--            self._login_with_form()
--        except RuntimeError:
--            self._auth_failures += 1
--            raise
--        else:
--            self._auth_failures = 0
--
--    def _login_with_form(self) -> None:
--        if not self.auth.has_credentials():
--            raise RuntimeError("PitchBook credentials are required for login.")
--        for attempt in range(3):
--            page = self._render(
--                {"url": self.login_url, "browserHtml": True},
--                allow_login=True,
--                referer=None,
--            )
--            form = self._locate_login_form(page.soup)
--            if form is None:
--                raise RuntimeError("Could not locate a login form on the PitchBook login page.")
--            action_attr, method, payload = self._build_form_payload(form)
--            try:
--                result = self._submit_form(action_attr, method, payload, referer=page.url or self.login_url)
--            except AuthenticationError:
--                continue
--            except ChallengeError as exc:
--                raise RuntimeError(
--                    "PitchBook requested additional verification (for example MFA or device confirmation); manual login is required."
--                ) from exc
--            except ThrottleError:
--                backoff = random.uniform(4.0, 7.0)
--                print(f"[pitchbook_login] Throttle detected while logging in; waiting {backoff:.1f}s.")
--                time.sleep(backoff)
--                continue
--            self._authenticated = True
--            self._last_url = result.url
--            return
--        self._authenticated = False
--        raise RuntimeError("PitchBook login did not succeed after multiple attempts; check credentials or complete verification manually.")
--
--    def fetch_page(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> PageContent:
--        if require_login:
--            self.ensure_logged_in(require=True)
--        effective_referer = referer or self._last_url
--        page = self._render(
--            {"url": url, "browserHtml": True},
--            allow_login=False,
--            referer=effective_referer,
--        )
--        self._authenticated = True
--        self._last_url = url
--        return page
--
--    def fetch_html(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> str:
--        return self.fetch_page(url, require_login=require_login, referer=referer).html
--class ListScraper:
--    def __init__(
--        self,
--        cfg: ListConfig,
--        out_csv: str = "results.csv",
--        max_pages: Optional[int] = None,
--        page_sleep_range: Optional[Tuple[float, float]] = None,
--        client: Optional[ZyteSessionClient] = None,
--    ):
--        self.cfg = cfg
--        self.out_csv = out_csv
--        self.max_pages = max_pages if max_pages is not None else cfg.max_pages
--        if self.max_pages is not None and self.max_pages <= 0:
--            raise ValueError("max_pages must be a positive integer")
--        sleep_range = tuple(page_sleep_range or cfg.page_sleep_range)
--        if len(sleep_range) != 2:
--            raise ValueError("page_sleep_range must contain exactly two values")
--        low, high = sleep_range
--        if low < 0 or high < 0 or low > high:
--            raise ValueError("page_sleep_range must be non-negative and increasing")
--        self.page_sleep_range = (low, high)
--        self.client = client or ZyteSessionClient(ZYTE_API_KEY)
--        self.throttle = AdaptiveThrottle(self.page_sleep_range)
--        self.max_empty_pages = 1
--
--    def build_search_url(self, query: str) -> str:
--        return self.cfg.build_search_url(query)
--
--    def parse_rows(self, soup: BeautifulSoup, page_url: str) -> List[dict]:
--        row_groups: List[Tag] = []
--        for selector in self.cfg.row_selectors:
--            row_groups = list(soup.select(selector))
--            if row_groups:
--                break
--        if not row_groups:
--            return []
--        rows: List[dict] = []
--        for row in row_groups:
--            record: Dict[str, str] = {}
--            for col, selectors in self.cfg.field_selectors.items():
--                record[col] = self._extract_value(row, selectors, page_url)
--            for col, selectors in self.cfg.optional_fields.items():
--                value = self._extract_value(row, selectors, page_url)
--                if value:
--                    record[col] = value
--            rows.append(record)
--        return rows
--
--    def _extract_value(self, row: Tag, selectors: Iterable[str], page_url: str) -> str:
--        for sel in selectors:
--            if not sel:
--                continue
--            el = row.select_one(sel)
--            if not el:
--                continue
--            if el.name == "a" and el.get("href"):
--                href = el.get("href")
--                if href:
--                    return urljoin(page_url, href.strip())
--            text = el.get("title") or el.get_text(" ", strip=True)
--            if text:
--                return text
--        return ""
--
--    def _looks_like_empty_results(self, soup: BeautifulSoup) -> bool:
--        text = soup.get_text(" ", strip=True).lower()
--        for marker in self.cfg.empty_result_markers:
--            if marker.lower() in text:
--                return True
--        return False
--
--    def next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
--        for selector in self.cfg.next_selectors:
--            nxt = soup.select_one(selector)
--            if nxt and nxt.get("href"):
--                return urljoin(current_url, nxt["href"])
--        return None
--
--    def append_csv(self, batch: List[dict]) -> None:
--        file_exists = os.path.exists(self.out_csv)
--        with open(self.out_csv, "a", newline="", encoding="utf-8") as f:
--            writer = csv.DictWriter(f, fieldnames=self.cfg.columns)
--            if not file_exists:
--                writer.writeheader()
--            for record in batch:
--                writer.writerow({k: record.get(k, "") for k in self.cfg.columns})
--
--    def crawl(self, query: str) -> None:
--        require_login = getattr(self.cfg, "requires_login", True)
--        if require_login:
--            self.client.ensure_logged_in(require=True)
--        url = self.build_search_url(query)
--        total = 0
--        pages = 0
--        referer: Optional[str] = None
--        consecutive_empty = 0
--        initial_pause = random.uniform(1.0, 3.0)
--        print(f"[{self.cfg.name}] Initial pause {initial_pause:.2f}s before first request.")
--        time.sleep(initial_pause)
--        while url and (self.max_pages is None or pages < self.max_pages):
--            page_attempt = 0
--            while True:
--                page_attempt += 1
--                try:
--                    page = self.client.fetch_page(url, require_login=require_login, referer=referer)
--                    break
--                except AuthenticationError as exc:
--                    if not require_login or page_attempt >= 3:
--                        print(f"[{self.cfg.name}] Authentication failure: {exc}")
--                        return
--                    print(f"[{self.cfg.name}] Session refreshed, re-authenticating ({page_attempt}/3).")
--                    self.client.ensure_logged_in(require=True)
--                    continue
--                except ThrottleError as exc:
--                    penalty = 2.0 + page_attempt
--                    self.throttle.record_penalty(severity=penalty)
--                    wait_for = self.throttle.propose_delay(modifier=penalty)
--                    print(f"[{self.cfg.name}] Throttled ({exc}); cooling down {wait_for:.2f}s before retry.")
--                    time.sleep(wait_for)
--                    if page_attempt >= 4:
--                        print(f"[{self.cfg.name}] Stopping after repeated throttling.")
--                        return
--                    continue
--                except ChallengeError as exc:
--                    print(f"[{self.cfg.name}] Challenge detected ({exc}); stopping to avoid repeated fetches.")
--                    return
--            soup = page.soup
--            rows = self.parse_rows(soup, page.url)
--            if not rows:
--                referer = page.url
--                consecutive_empty += 1
--                if self._looks_like_empty_results(soup):
--                    print(f"[{self.cfg.name}] Page {pages + 1}: search returned no visible results. Stopping.")
--                    break
--                if consecutive_empty > self.max_empty_pages:
--                    print(f"[{self.cfg.name}] Page {pages + 1}: selectors yielded no rows twice; stopping to avoid detection.")
--                    break
--                self.throttle.record_penalty(severity=2.5)
--                wait_for = self.throttle.propose_delay(modifier=random.uniform(4.0, 7.0))
--                print(f"[{self.cfg.name}] Page {pages + 1}: no rows parsed; waiting {wait_for:.2f}s before refetch.")
--                time.sleep(wait_for)
--                continue
--            consecutive_empty = 0
--            self.append_csv(rows)
--            total += len(rows)
--            pages += 1
--            print(f"[{self.cfg.name}] Page {pages}: saved {len(rows)} rows (total={total}) -> {self.out_csv}")
--            referer = page.url
--            next_url = self.next_page(soup, page.url)
--            if not next_url:
--                break
--            url = next_url
--            wait_for = self.throttle.propose_delay()
--            self.throttle.record_success()
--            print(f"[{self.cfg.name}] Next request in {wait_for:.2f}s")
--            time.sleep(wait_for)
--        print(f"[{self.cfg.name}] Done. Pages: {pages}, Rows: {total}, File: {self.out_csv}")
--
--
--def _pitchbook_search_url(entity: str, query: str, base: str) -> str:
--    params = {"q": query, "entity": entity}
--    return urljoin(base, f"profiles/search/?{urlencode(params)}")
--def pitchbook_company_cfg() -> ListConfig:
--    base = "https://pitchbook.com/"
--
--    def build_url(query: str) -> str:
--        return _pitchbook_search_url("company", query, base)
--
--    columns = [
--        "name",
--        "headline",
--        "location",
--        "industries",
--        "last_update",
--        "profile_url",
--        "website",
--    ]
--
--    return ListConfig(
--        name="pitchbook_companies",
--        base=base,
--        build_search_url=build_url,
--        row_selectors=(
--            'div[data-qa="search-results__result"]',
--            "div.search-results__result",
--            "article.result-card",
--        ),
--        field_selectors={
--            "name": (
--                'a[data-qa="result-card__title-link"]',
--                "a.result-card__title-link",
--                "h3 a",
--            ),
--            "headline": (
--                'div[data-qa="result-card__description"]',
--                "div.result-card__description",
--                "p.result-card__description",
--            ),
--            "location": (
--                'span[data-qa="result-card__location"]',
--                "span.result-card__location",
--                "div.result-card__location",
--            ),
--            "industries": (
--                'span[data-qa="result-card__industries"]',
--                "span.result-card__industries",
--                "div.result-card__industries",
--            ),
--            "last_update": (
--                'span[data-qa="result-card__last-update"]',
--                "span.result-card__last-update",
--                "time.result-card__last-update",
--            ),
--            "profile_url": (
--                'a[data-qa="result-card__title-link"]',
--                "a.result-card__title-link",
--            ),
--        },
--        optional_fields={
--            "website": (
--                'a[data-qa="result-card__website"]',
--                "a.result-card__website",
--            ),
--        },
--        next_selectors=(
--            'a[data-qa="pager__next"]',
--            "a.pager__button--next",
--            "li.next a",
--        ),
--        columns=columns,
--        max_pages=500,
--        page_sleep_range=(2.0, 6.0),
--        empty_result_markers=(
--            "No companies found",
--            "We couldn't find any results",
--            "Try adjusting your filters",
--        ),
--    )
--
--
--def pitchbook_people_cfg() -> ListConfig:
--    base = "https://pitchbook.com/"
--
--    def build_url(query: str) -> str:
--        return _pitchbook_search_url("person", query, base)
--
--    columns = [
--        "name",
--        "title",
--        "affiliation",
--        "location",
--        "last_update",
--        "profile_url",
--        "linkedin",
--    ]
--
--    return ListConfig(
--        name="pitchbook_people",
--        base=base,
--        build_search_url=build_url,
--        row_selectors=(
--            'div[data-qa="search-results__result"]',
--            "div.search-results__result",
--            "article.result-card",
--        ),
--        field_selectors={
--            "name": (
--                'a[data-qa="result-card__title-link"]',
--                "a.result-card__title-link",
--                "h3 a",
--            ),
--            "title": (
--                'span[data-qa="result-card__subtitle"]',
--                "span.result-card__subtitle",
--                "div.result-card__subtitle",
--            ),
--            "affiliation": (
--                'span[data-qa="result-card__affiliation"]',
--                "span.result-card__affiliation",
--                "div.result-card__affiliation",
--            ),
--            "location": (
--                'span[data-qa="result-card__location"]',
--                "span.result-card__location",
--                "div.result-card__location",
--            ),
--            "last_update": (
--                'span[data-qa="result-card__last-update"]',
--                "span.result-card__last-update",
--                "time.result-card__last-update",
--            ),
--            "profile_url": (
--                'a[data-qa="result-card__title-link"]',
--                "a.result-card__title-link",
--            ),
--        },
--        optional_fields={
--            "linkedin": (
--                'a[data-qa="result-card__linkedin"]',
--                "a.result-card__linkedin",
--                'a[href*="linkedin.com"]',
--            ),
--        },
--        next_selectors=(
--            'a[data-qa="pager__next"]',
--            "a.pager__button--next",
--            "li.next a",
--        ),
--        columns=columns,
--        max_pages=500,
--        page_sleep_range=(2.0, 6.0),
--        empty_result_markers=(
--            "No people found",
--            "Try adjusting your filters",
--            "We couldn't find any results",
--        ),
--    )
--
--
--def pitchbook_investor_cfg() -> ListConfig:
--    base = "https://pitchbook.com/"
--
--    def build_url(query: str) -> str:
--        return _pitchbook_search_url("investor", query, base)
--
--    columns = [
--        "name",
--        "investor_type",
--        "focus",
--        "location",
--        "last_update",
--        "profile_url",
--        "website",
--    ]
--
--    return ListConfig(
--        name="pitchbook_investors",
--        base=base,
--        build_search_url=build_url,
--        row_selectors=(
--            'div[data-qa="search-results__result"]',
--            "div.search-results__result",
--            "article.result-card",
--        ),
--        field_selectors={
--            "name": (
--                'a[data-qa="result-card__title-link"]',
--                "a.result-card__title-link",
--                "h3 a",
--            ),
--            "investor_type": (
--                'span[data-qa="result-card__subtitle"]',
--                "span.result-card__subtitle",
--                "div.result-card__subtitle",
--            ),
--            "focus": (
--                'span[data-qa="result-card__focus"]',
--                "span.result-card__focus",
--                "div.result-card__focus",
--            ),
--            "location": (
--                'span[data-qa="result-card__location"]',
--                "span.result-card__location",
--                "div.result-card__location",
--            ),
--            "last_update": (
--                'span[data-qa="result-card__last-update"]',
--                "span.result-card__last-update",
--                "time.result-card__last-update",
--            ),
--            "profile_url": (
--                'a[data-qa="result-card__title-link"]',
--                "a.result-card__title-link",
--            ),
--        },
--        optional_fields={
--            "website": (
--                'a[data-qa="result-card__website"]',
--                "a.result-card__website",
--            ),
--        },
--        next_selectors=(
--            'a[data-qa="pager__next"]',
--            "a.pager__button--next",
--            "li.next a",
--        ),
--        columns=columns,
--        max_pages=500,
--        page_sleep_range=(2.0, 6.0),
--        empty_result_markers=(
--            "No investors found",
--            "We couldn't find any results",
--            "Try adjusting your filters",
--        ),
--    )
--def _default_output_name(entity: str, query: str) -> str:
--    safe_query = re.sub(r"[^A-Za-z0-9._-]+", "_", query.strip()) or "query"
--    return f"pitchbook_{entity}_{safe_query}.csv"
--
--
--def _build_auth_options_from_args(args) -> PitchbookAuthOptions:
--    return PitchbookAuthOptions(
--        email=args.pitchbook_email or os.getenv("PITCHBOOK_EMAIL"),
--        password=args.pitchbook_password or os.getenv("PITCHBOOK_PASSWORD"),
--        session_id=args.zyte_session_id or os.getenv("ZYTE_SESSION_ID"),
--        user_agent=args.user_agent or os.getenv("PITCHBOOK_USER_AGENT"),
--        login_url=args.login_url or os.getenv("PITCHBOOK_LOGIN_URL"),
--        login_form_selector=args.login_form_selector or os.getenv("PITCHBOOK_LOGIN_FORM_SELECTOR"),
--        email_field=args.pitchbook_email_field or os.getenv("PITCHBOOK_EMAIL_FIELD"),
--        password_field=args.pitchbook_password_field or os.getenv("PITCHBOOK_PASSWORD_FIELD"),
--    )
--
--
--if __name__ == "__main__":
--    import argparse
--
--    parser = argparse.ArgumentParser(description="Scrape PitchBook search results with Zyte")
--    parser.add_argument(
--        "entity",
--        choices=["companies", "people", "investors"],
--        help="Which PitchBook directory to crawl",
--    )
--    parser.add_argument("query", help="Search query to run on PitchBook")
--    parser.add_argument("--output", "-o", help="Output CSV path")
--    parser.add_argument(
--        "--max-pages",
--        type=int,
--        help="Maximum number of result pages to crawl (defaults to the entity configuration)",
--    )
--    parser.add_argument(
--        "--min-delay",
--        type=float,
--        help="Minimum pause in seconds between page requests",
--    )
--    parser.add_argument(
--        "--max-delay",
--        type=float,
--        help="Maximum pause in seconds between page requests",
--    )
--    parser.add_argument("--pitchbook-email", help="PitchBook email/username for login")
--    parser.add_argument("--pitchbook-password", help="PitchBook password for login")
--    parser.add_argument(
--        "--zyte-session-id",
--        help="Sticky Zyte session identifier to persist login across runs",
--    )
--    parser.add_argument(
--        "--user-agent",
--        help="Override the browser user-agent; defaults to a rotating profile",
--    )
--    parser.add_argument("--login-url", help="Override the login form URL")
--    parser.add_argument(
--        "--login-form-selector",
--        help="CSS selector for the login form if it cannot be auto-detected",
--    )
--    parser.add_argument(
--        "--pitchbook-email-field",
--        help="Explicit login form field name for the email/username",
--    )
--    parser.add_argument(
--        "--pitchbook-password-field",
--        help="Explicit login form field name for the password",
--    )
--    parser.add_argument(
--        "--skip-login",
--        action="store_true",
--        help="Skip login even if the selected directory normally requires it",
--    )
--    args = parser.parse_args()
--
--    cfg_factory = {
--        "companies": pitchbook_company_cfg,
--        "people": pitchbook_people_cfg,
--        "investors": pitchbook_investor_cfg,
--    }
--
--    cfg = cfg_factory[args.entity]()
--    if args.skip_login:
--        cfg.requires_login = False
--
--    output_path = args.output or _default_output_name(args.entity, args.query)
--
--    sleep_range: Optional[Tuple[float, float]] = None
--    if args.min_delay is not None or args.max_delay is not None:
--        if args.min_delay is None or args.max_delay is None:
--            raise SystemExit("Both --min-delay and --max-delay must be supplied together.")
--        sleep_range = (args.min_delay, args.max_delay)
--
--    auth_options = _build_auth_options_from_args(args)
--    client = ZyteSessionClient(ZYTE_API_KEY, auth_options)
--
--    scraper = ListScraper(
--        cfg=cfg,
--        out_csv=output_path,
--        max_pages=args.max_pages,
--        page_sleep_range=sleep_range,
--        client=client,
--    )
--    scraper.crawl(query=args.query)
--
--
-+# pip install requests beautifulsoup4 tenacity
-+
-+import os
-+import csv
-+import time
-+import random
-+import re
-+import uuid
-+import hashlib
-+from dataclasses import dataclass, field
-+from typing import Callable, Dict, Iterable, List, Optional, Tuple
-+from urllib.parse import urljoin, urlencode, urlparse
-+import glob
-+
-+import requests
-+from urllib.parse import urlsplit
-+from urllib import robotparser
-+from bs4 import BeautifulSoup
-+from bs4.element import Tag
-+from tenacity import retry, wait_exponential_jitter, stop_after_attempt
-+
-+
-+def _strip_or_none(value: Optional[str]) -> Optional[str]:
-+    if value is None:
-+        return None
-+    value = value.strip()
-+    return value or None
-+
-+
-+ZYTE_API_KEY = os.getenv("ZYTE_API_KEY")
-+
-+ZYTE_ENDPOINT = "https://api.zyte.com/v1/extract"
-+PITCHBOOK_LOGIN_URL_DEFAULT = "https://pitchbook.com/account/login"
-+
-+
-+def _origin(url: Optional[str]) -> Optional[str]:
-+    if not url:
-+        return None
-+    parsed = urlparse(url)
-+    if not parsed.scheme or not parsed.netloc:
-+        return None
-+    return f"{parsed.scheme}://{parsed.netloc}"
-+
-+
-+def _registrable_domain(host: Optional[str]) -> Optional[str]:
-+    if not host:
-+        return None
-+    parts = host.split(".")
-+    if len(parts) < 2:
-+        return host
-+    return ".".join(parts[-2:])
-+
-+
-+def _sec_fetch_site(target_url: Optional[str], referer: Optional[str]) -> str:
-+    if not referer:
-+        return "none"
-+    target = urlparse(target_url or "")
-+    ref = urlparse(referer)
-+    if not target.netloc or not ref.netloc:
-+        return "none"
-+    if target.netloc == ref.netloc:
-+        return "same-origin"
-+    if _registrable_domain(target.hostname) == _registrable_domain(ref.hostname):
-+        return "same-site"
-+    return "cross-site"
-+
-+
-+def _ensure_tuple(value: Optional[Iterable[str]]) -> Tuple[str, ...]:
-+    if value is None:
-+        return tuple()
-+    if isinstance(value, (list, tuple)):
-+        return tuple(value)
-+    return (value,)
-+
-+
-+@dataclass(frozen=True)
-+class BrowserIdentity:
-+    label: str
-+    user_agent: str
-+    accept_language: str
-+
-+    def document_headers(
-+        self,
-+        target_url: Optional[str],
-+        referer: Optional[str] = None,
-+        navigation: str = "navigate",
-+        dest: str = "document",
-+    ) -> Dict[str, str]:
-+        # Minimize synthetic, high-entropy headers to avoid mismatches
-+        headers = {
-+            "User-Agent": self.user_agent,
-+            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
-+            "Accept-Language": self.accept_language,
-+        }
-+        if referer:
-+            headers["Referer"] = referer
-+        return headers
-+
-+    def form_headers(self, target_url: Optional[str], referer: Optional[str]) -> Dict[str, str]:
-+        headers = self.document_headers(target_url, referer)
-+        origin = _origin(target_url)
-+        if origin:
-+            headers["Origin"] = origin
-+        headers["Content-Type"] = "application/x-www-form-urlencoded"
-+        return headers
-+
-+
-+IDENTITY_POOL: Tuple[BrowserIdentity, ...] = (
-+    BrowserIdentity(
-+        label="win-chrome-124",
-+        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
-+        accept_language="en-US,en;q=0.9",
-+    ),
-+    BrowserIdentity(
-+        label="mac-chrome-123",
-+        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
-+        accept_language="en-US,en;q=0.9",
-+    ),
-+    BrowserIdentity(
-+        label="win-edge-124",
-+        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
-+        accept_language="en-US,en;q=0.9",
-+    ),
-+)
-+
-+
-+def _resolve_identity(session_id: str, override_ua: Optional[str]) -> BrowserIdentity:
-+    if override_ua:
-+        return BrowserIdentity(
-+            label="custom",
-+            user_agent=override_ua,
-+            accept_language="en-US,en;q=0.9",
-+        )
-+    digest = hashlib.sha256(session_id.encode("utf-8")).digest()
-+    idx = digest[0] % len(IDENTITY_POOL)
-+    return IDENTITY_POOL[idx]
-+
-+
-+class AuthenticationError(RuntimeError):
-+    pass
-+
-+
-+class ChallengeError(RuntimeError):
-+    pass
-+
-+
-+class ThrottleError(RuntimeError):
-+    pass
-+
-+
-+@dataclass
-+class PageContent:
-+    url: str
-+    html: str
-+    soup: BeautifulSoup
-+    status: Optional[int] = None
-+
-+
-+@dataclass
-+class ListConfig:
-+    name: str
-+    base: str
-+    build_search_url: Callable[[str], str]
-+    row_selectors: Iterable[str]
-+    field_selectors: Dict[str, Iterable[str]]
-+    optional_fields: Dict[str, Iterable[str]] = field(default_factory=dict)
-+    next_selectors: Iterable[str] = field(default_factory=lambda: ("li.next a",))
-+    columns: List[str] = field(default_factory=list)
-+    max_pages: int = 50
-+    page_sleep_range: Tuple[float, float] = (6.0, 18.0)
-+    requires_login: bool = True
-+    empty_result_markers: Tuple[str, ...] = ("No results found", "Try adjusting your filters")
-+
-+    def __post_init__(self) -> None:
-+        self.row_selectors = _ensure_tuple(self.row_selectors)
-+        self.next_selectors = _ensure_tuple(self.next_selectors)
-+        self.field_selectors = {key: _ensure_tuple(value) for key, value in self.field_selectors.items()}
-+        self.optional_fields = {key: _ensure_tuple(value) for key, value in self.optional_fields.items()}
-+        if not self.columns:
-+            ordered: List[str] = list(self.field_selectors.keys())
-+            for col in self.optional_fields.keys():
-+                if col not in ordered:
-+                    ordered.append(col)
-+            self.columns = ordered
-+
-+
-+@dataclass
-+class PitchbookAuthOptions:
-+    email: Optional[str] = None
-+    password: Optional[str] = None
-+    session_id: Optional[str] = None
-+    user_agent: Optional[str] = None
-+    login_url: Optional[str] = None
-+    login_form_selector: Optional[str] = None
-+    email_field: Optional[str] = None
-+    password_field: Optional[str] = None
-+    cookie_header: Optional[str] = None
-+    cookies_file: Optional[str] = None
-+
-+    def __post_init__(self) -> None:
-+        self.email = _strip_or_none(self.email)
-+        self.password = _strip_or_none(self.password)
-+        self.session_id = _strip_or_none(self.session_id)
-+        self.user_agent = _strip_or_none(self.user_agent)
-+        self.login_url = _strip_or_none(self.login_url)
-+        self.login_form_selector = _strip_or_none(self.login_form_selector)
-+        self.email_field = _strip_or_none(self.email_field)
-+        self.password_field = _strip_or_none(self.password_field)
-+        self.cookie_header = _strip_or_none(self.cookie_header)
-+        self.cookies_file = _strip_or_none(self.cookies_file)
-+
-+    def resolved_login_url(self) -> str:
-+        return self.login_url or PITCHBOOK_LOGIN_URL_DEFAULT
-+
-+    def resolved_session_id(self) -> str:
-+        return self.session_id or f"pitchbook-{uuid.uuid4().hex}"
-+
-+    def has_credentials(self) -> bool:
-+        return bool(self.email and self.password)
-+
-+
-+class AdaptiveThrottle:
-+    def __init__(self, base_range: Tuple[float, float]):
-+        self.base_low, self.base_high = base_range
-+        self.penalty = random.uniform(0.2, 1.0)
-+
-+    def propose_delay(self, modifier: float = 0.0) -> float:
-+        # Heavy-tailed randomization with occasional longer pauses
-+        base = random.uniform(self.base_low, self.base_high) + modifier + self.penalty
-+        # Add a small lognormal jitter
-+        base += random.lognormvariate(0.0, 0.25) - 1.0
-+        # 5% chance to take a longer break
-+        if random.random() < 0.05:
-+            base += random.uniform(20.0, 75.0)
-+        return max(0.5, base)
-+
-+    def record_success(self) -> None:
-+        if self.penalty > 0:
-+            self.penalty = max(0.0, self.penalty - random.uniform(0.1, 0.4))
-+
-+    def record_penalty(self, severity: float = 1.5) -> None:
-+        self.penalty = min(18.0, self.penalty + severity)
-+class ZyteSessionClient:
-+    def __init__(self, api_key: str, auth: Optional[PitchbookAuthOptions] = None, render_mode: str = "auto"):
-+        self.api_key = api_key
-+        self.auth = auth or PitchbookAuthOptions()
-+        # Default to ephemeral sessions unless the user explicitly sets one
-+        self.session_id = self.auth.resolved_session_id()
-+        self.identity = _resolve_identity(self.session_id, self.auth.user_agent)
-+        self.login_url = self.auth.resolved_login_url()
-+        self._authenticated = False
-+        self._auth_failures = 0
-+        self._last_url: Optional[str] = None
-+        self._cookie_header: Optional[str] = self._load_cookie_header()
-+        self._render_mode: str = render_mode  # auto | browser | http
-+        self._cache: Dict[str, PageContent] = {}
-+        self._cache_order: List[str] = []
-+        self._cache_capacity: int = 32
-+
-+    @retry(wait=wait_exponential_jitter(initial=1, max=12), stop=stop_after_attempt(5))
-+    def _request_zyte(self, payload: Dict) -> Dict:
-+        response = requests.post(
-+            ZYTE_ENDPOINT,
-+            auth=(self.api_key, ""),
-+            json=payload,
-+            timeout=70,
-+            headers={"Content-Type": "application/json"},
-+        )
-+        if response.status_code == 400:
-+            try:
-+                print("Zyte 400:", response.json())
-+            except Exception:
-+                print("Zyte 400 raw:", response.text[:500])
-+        response.raise_for_status()
-+        return response.json()
-+
-+    def _extract_status(self, data: Dict) -> Optional[int]:
-+        for key in ("statusCode", "httpResponseStatusCode", "httpResponseStatus"):
-+            value = data.get(key)
-+            if isinstance(value, int):
-+                return value
-+            try:
-+                return int(value)  # type: ignore[arg-type]
-+            except (TypeError, ValueError):
-+                continue
-+        return None
-+
-+    def _html_from(self, data: Dict) -> str:
-+        return data.get("browserHtml") or data.get("httpResponseBody") or ""
-+
-+    def _classify_page(self, soup: BeautifulSoup) -> Optional[str]:
-+        if soup is None:
-+            return None
-+        # Minimal classification; avoid explicit fingerprints
-+        # Detect authentication prompts or JS verification pages
-+        text = soup.get_text(" ", strip=True).lower()
-+        text = text[:8000]
-+        if any(token in text for token in ("log in", "sign in", "login", "please sign in", "session expired")):
-+            return "login"
-+        text = soup.get_text(" ", strip=True).lower()
-+        text = text[:8000]
-+        if any(token in text for token in ("verify you are human", "captcha", "security check", "robot check", "please enable javascript")):
-+            return "challenge"
-+        if any(token in text for token in ("too many requests", "rate limit", "temporarily blocked", "unusual traffic", "request limit", "throttled", "quota exceeded")):
-+            return "throttle"
-+        return None
-+
-+    def _load_cookie_header(self) -> Optional[str]:
-+        if self.auth.cookie_header:
-+            return self.auth.cookie_header
-+        # Simple Netscape cookie file support: use as-is if provided (user-managed)
-+        if self.auth.cookies_file and os.path.exists(self.auth.cookies_file):
-+            try:
-+                with open(self.auth.cookies_file, "r", encoding="utf-8") as fh:
-+                    content = fh.read().strip()
-+                    if content:
-+                        return content
-+            except Exception:
-+                pass
-+        return None
-+
-+    def _render_once(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
-+        request_payload = dict(payload)
-+        target_url = request_payload.get("url")
-+        # Lightweight GET cache keyed by URL when no body/method overrides are set
-+        if (
-+            not request_payload.get("httpRequestMethod")
-+            and not request_payload.get("httpRequestBody")
-+            and isinstance(target_url, str)
-+            and target_url in self._cache
-+        ):
-+            return self._cache[target_url]
-+        base_headers = self.identity.document_headers(target_url, referer)
-+        # Attach user-provided cookie header if available
-+        if self._cookie_header:
-+            base_headers["Cookie"] = self._cookie_header
-+        extra_headers = request_payload.get("httpRequestHeaders") or {}
-+        if extra_headers:
-+            base_headers.update(extra_headers)
-+        request_payload["httpRequestHeaders"] = base_headers
-+        session_spec = request_payload.setdefault("session", {})
-+        session_spec.setdefault("id", self.session_id)
-+
-+        data = self._request_zyte(request_payload)
-+        html = self._html_from(data)
-+        soup = BeautifulSoup(html, "html.parser") if html else BeautifulSoup("", "html.parser")
-+        classification = self._classify_page(soup)
-+        if classification == "login" and not allow_login:
-+            self._authenticated = False
-+            raise AuthenticationError("Authentication required. Provide a valid cookie via --cookie-header or --cookies-file, or use --skip-login.")
-+        if classification == "challenge":
-+            self._authenticated = False
-+            raise ChallengeError("Access verification required.")
-+        if classification == "throttle":
-+            raise ThrottleError("Service reported temporary rate limits.")
-+        status_code = self._extract_status(data)
-+        page = PageContent(url=target_url, html=html, soup=soup, status=status_code)
-+        # Populate cache for plain GETs
-+        if (
-+            not request_payload.get("httpRequestMethod")
-+            and not request_payload.get("httpRequestBody")
-+            and isinstance(target_url, str)
-+        ):
-+            self._cache[target_url] = page
-+            self._cache_order.append(target_url)
-+            if len(self._cache_order) > self._cache_capacity:
-+                evict = self._cache_order.pop(0)
-+                self._cache.pop(evict, None)
-+        return page
-+
-+    def _render(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
-+        # Auto rendering: try HTTP body first, fall back to browser if needed
-+        mode = self._render_mode
-+        if mode == "browser":
-+            payload = dict(payload)
-+            payload["browserHtml"] = True
-+            return self._render_once(payload, allow_login=allow_login, referer=referer)
-+        if mode == "http":
-+            payload = dict(payload)
-+            payload.pop("browserHtml", None)
-+            return self._render_once(payload, allow_login=allow_login, referer=referer)
-+        # auto
-+        first_payload = dict(payload)
-+        first_payload.pop("browserHtml", None)
-+        try:
-+            result = self._render_once(first_payload, allow_login=allow_login, referer=referer)
-+        except (AuthenticationError, ChallengeError, ThrottleError):
-+            # Propagate auth/throttle decisions without switching rendering
-+            raise
-+        # If body seems empty or lacks any rows/links, retry with browser
-+        looks_empty = not result.html or len(result.html) < 512 or len(result.soup.get_text(" ", strip=True)) < 80
-+        if looks_empty:
-+            second_payload = dict(payload)
-+            second_payload["browserHtml"] = True
-+            return self._render_once(second_payload, allow_login=allow_login, referer=referer)
-+        return result
-+
-+    def ensure_logged_in(self, require: bool = False) -> None:
-+        if not require:
-+            return
-+        if self._authenticated:
-+            return
-+        if not self._cookie_header:
-+            raise RuntimeError(
-+                "Authentication is required. Provide a cookie via --cookie-header or --cookies-file, or run with --skip-login."
-+            )
-+        # We assume the provided cookie is valid; any failure will be detected on first request
-+        self._authenticated = True
-+
-+    # Form-based login removed to avoid mechanized credential submission flows
-+
-+    def fetch_page(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> PageContent:
-+        if require_login:
-+            self.ensure_logged_in(require=True)
-+        effective_referer = referer or self._last_url
-+        page = self._render(
-+            {"url": url},
-+            allow_login=False,
-+            referer=effective_referer,
-+        )
-+        self._authenticated = True
-+        self._last_url = url
-+        return page
-+
-+    def fetch_html(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> str:
-+        return self.fetch_page(url, require_login=require_login, referer=referer).html
-+class ListScraper:
-+    def __init__(
-+        self,
-+        cfg: ListConfig,
-+        out_csv: str = "results.csv",
-+        max_pages: Optional[int] = None,
-+        page_sleep_range: Optional[Tuple[float, float]] = None,
-+        client: Optional[ZyteSessionClient] = None,
-+    ):
-+        self.cfg = cfg
-+        self.out_csv = out_csv
-+        self.max_pages = max_pages if max_pages is not None else cfg.max_pages
-+        if self.max_pages is not None and self.max_pages <= 0:
-+            raise ValueError("max_pages must be a positive integer")
-+        sleep_range = tuple(page_sleep_range or cfg.page_sleep_range)
-+        if len(sleep_range) != 2:
-+            raise ValueError("page_sleep_range must contain exactly two values")
-+        low, high = sleep_range
-+        if low < 0 or high < 0 or low > high:
-+            raise ValueError("page_sleep_range must be non-negative and increasing")
-+        self.page_sleep_range = (low, high)
-+        self.client = client
-+        self.throttle = AdaptiveThrottle(self.page_sleep_range)
-+        self.max_empty_pages = 1
-+
-+    def build_search_url(self, query: str) -> str:
-+        return self.cfg.build_search_url(query)
-+
-+    def parse_rows(self, soup: BeautifulSoup, page_url: str) -> List[dict]:
-+        row_groups: List[Tag] = []
-+        for selector in self.cfg.row_selectors:
-+            row_groups = list(soup.select(selector))
-+            if row_groups:
-+                break
-+        if not row_groups:
-+            return []
-+        rows: List[dict] = []
-+        for row in row_groups:
-+            record: Dict[str, str] = {}
-+            for col, selectors in self.cfg.field_selectors.items():
-+                record[col] = self._extract_value(row, selectors, page_url)
-+            for col, selectors in self.cfg.optional_fields.items():
-+                value = self._extract_value(row, selectors, page_url)
-+                if value:
-+                    record[col] = value
-+            rows.append(record)
-+        return rows
-+
-+    def _extract_value(self, row: Tag, selectors: Iterable[str], page_url: str) -> str:
-+        for sel in selectors:
-+            if not sel:
-+                continue
-+            el = row.select_one(sel)
-+            if not el:
-+                continue
-+            if el.name == "a" and el.get("href"):
-+                href = el.get("href")
-+                if href:
-+                    return urljoin(page_url, href.strip())
-+            text = el.get("title") or el.get_text(" ", strip=True)
-+            if text:
-+                return text
-+        return ""
-+
-+    def _looks_like_empty_results(self, soup: BeautifulSoup) -> bool:
-+        text = soup.get_text(" ", strip=True).lower()
-+        for marker in self.cfg.empty_result_markers:
-+            if marker.lower() in text:
-+                return True
-+        return False
-+
-+    def next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
-+        for selector in self.cfg.next_selectors:
-+            nxt = soup.select_one(selector)
-+            if nxt and nxt.get("href"):
-+                return urljoin(current_url, nxt["href"])
-+        return None
-+
-+    def append_csv(self, batch: List[dict]) -> None:
-+        file_exists = os.path.exists(self.out_csv)
-+        with open(self.out_csv, "a", newline="", encoding="utf-8") as f:
-+            writer = csv.DictWriter(f, fieldnames=self.cfg.columns)
-+            if not file_exists:
-+                writer.writeheader()
-+            for record in batch:
-+                writer.writerow({k: record.get(k, "") for k in self.cfg.columns})
-+
-+    def _robots_allows(self, url: str) -> bool:
-+        try:
-+            parts = urlsplit(url)
-+            robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
-+            rp = robotparser.RobotFileParser()
-+            rp.set_url(robots_url)
-+            rp.read()
-+            return rp.can_fetch(self.client.identity.user_agent, url)
-+        except Exception:
-+            # If robots cannot be fetched, err on the safe side by allowing
-+            return True
-+
-+    def crawl(self, query: str) -> None:
-+        require_login = getattr(self.cfg, "requires_login", True)
-+        if require_login:
-+            self.client.ensure_logged_in(require=True)
-+        url = self.build_search_url(query)
-+        if not self._robots_allows(url):
-+            print(f"[{self.cfg.name}] robots.txt disallows this path for the configured User-Agent; exiting.")
-+            return
-+        total = 0
-+        pages = 0
-+        referer: Optional[str] = None
-+        consecutive_empty = 0
-+        initial_pause = random.uniform(2.0, 7.0)
-+        print(f"[{self.cfg.name}] Preparing... pausing {initial_pause:.2f}s before first request.")
-+        time.sleep(initial_pause)
-+        while url and (self.max_pages is None or pages < self.max_pages):
-+            page_attempt = 0
-+            while True:
-+                page_attempt += 1
-+                try:
-+                    page = self.client.fetch_page(url, require_login=require_login, referer=referer)
-+                    break
-+                except AuthenticationError as exc:
-+                    print(f"[{self.cfg.name}] Access requires authentication ({exc}).")
-+                    return
-+                except ThrottleError as exc:
-+                    penalty = 1.5 + page_attempt
-+                    self.throttle.record_penalty(severity=penalty)
-+                    wait_for = self.throttle.propose_delay(modifier=penalty)
-+                    print(f"[{self.cfg.name}] Temporarily unavailable; waiting {wait_for:.2f}s before retry.")
-+                    time.sleep(wait_for)
-+                    if page_attempt >= 4:
-+                        print(f"[{self.cfg.name}] Stopping after repeated temporary unavailability.")
-+                        return
-+                    continue
-+                except ChallengeError as exc:
-+                    print(f"[{self.cfg.name}] Access verification encountered; stopping.")
-+                    return
-+            soup = page.soup
-+            rows = self.parse_rows(soup, page.url)
-+            if not rows:
-+                referer = page.url
-+                consecutive_empty += 1
-+                if self._looks_like_empty_results(soup):
-+                    print(f"[{self.cfg.name}] Page {pages + 1}: no results visible. Stopping.")
-+                    break
-+                if consecutive_empty > self.max_empty_pages:
-+                    print(f"[{self.cfg.name}] Page {pages + 1}: no rows parsed on repeated attempts; stopping.")
-+                    break
-+                self.throttle.record_penalty(severity=2.5)
-+                wait_for = self.throttle.propose_delay(modifier=random.uniform(6.0, 12.0))
-+                print(f"[{self.cfg.name}] Page {pages + 1}: no rows parsed; waiting {wait_for:.2f}s before refetch.")
-+                time.sleep(wait_for)
-+                continue
-+            consecutive_empty = 0
-+            self.append_csv(rows)
-+            total += len(rows)
-+            pages += 1
-+            print(f"[{self.cfg.name}] Page {pages}: saved {len(rows)} rows (total={total}) -> {self.out_csv}")
-+            referer = page.url
-+            next_url = self.next_page(soup, page.url)
-+            if not next_url:
-+                break
-+            url = next_url
-+            wait_for = self.throttle.propose_delay()
-+            self.throttle.record_success()
-+            print(f"[{self.cfg.name}] Next request in {wait_for:.2f}s")
-+            time.sleep(wait_for)
-+        print(f"[{self.cfg.name}] Done. Pages: {pages}, Rows: {total}, File: {self.out_csv}")
-+
-+    def crawl_offline_files(self, html_files: List[str]) -> None:
-+        if not html_files:
-+            raise RuntimeError("No HTML files were provided for offline ingestion.")
-+        total = 0
-+        pages = 0
-+        for path in html_files:
-+            try:
-+                with open(path, "r", encoding="utf-8") as fh:
-+                    html = fh.read()
-+            except Exception as exc:
-+                print(f"[{self.cfg.name}] Skipping '{path}': {exc}")
-+                continue
-+            soup = BeautifulSoup(html, "html.parser")
-+            rows = self.parse_rows(soup, page_url=f"file://{os.path.abspath(path)}")
-+            if not rows:
-+                print(f"[{self.cfg.name}] {os.path.basename(path)}: no rows parsed.")
-+                continue
-+            self.append_csv(rows)
-+            total += len(rows)
-+            pages += 1
-+            print(f"[{self.cfg.name}] Parsed file {os.path.basename(path)}: saved {len(rows)} rows (total={total}) -> {self.out_csv}")
-+        print(f"[{self.cfg.name}] Offline ingestion complete. Files: {pages}, Rows: {total}, File: {self.out_csv}")
-+
-+
-+def _pitchbook_search_url(entity: str, query: str, base: str) -> str:
-+    params = {"q": query, "entity": entity}
-+    return urljoin(base, f"profiles/search/?{urlencode(params)}")
-+def pitchbook_company_cfg() -> ListConfig:
-+    base = "https://pitchbook.com/"
-+
-+    def build_url(query: str) -> str:
-+        return _pitchbook_search_url("company", query, base)
-+
-+    columns = [
-+        "name",
-+        "headline",
-+        "location",
-+        "industries",
-+        "last_update",
-+        "profile_url",
-+        "website",
-+    ]
-+
-+    return ListConfig(
-+        name="pitchbook_companies",
-+        base=base,
-+        build_search_url=build_url,
-+        row_selectors=(
-+            "div.search-results__result",
-+            "article.result-card",
-+            'div[data-qa="search-results__result"]',
-+        ),
-+        field_selectors={
-+            "name": (
-+                "a.result-card__title-link",
-+                "h3 a",
-+                'a[data-qa="result-card__title-link"]',
-+            ),
-+            "headline": (
-+                "div.result-card__description",
-+                "p.result-card__description",
-+                'div[data-qa="result-card__description"]',
-+            ),
-+            "location": (
-+                "span.result-card__location",
-+                "div.result-card__location",
-+                'span[data-qa="result-card__location"]',
-+            ),
-+            "industries": (
-+                "span.result-card__industries",
-+                "div.result-card__industries",
-+                'span[data-qa="result-card__industries"]',
-+            ),
-+            "last_update": (
-+                "span.result-card__last-update",
-+                "time.result-card__last-update",
-+                'span[data-qa="result-card__last-update"]',
-+            ),
-+            "profile_url": (
-+                "a.result-card__title-link",
-+                'a[data-qa="result-card__title-link"]',
-+            ),
-+        },
-+        optional_fields={
-+            "website": (
-+                "a.result-card__website",
-+                'a[data-qa="result-card__website"]',
-+            ),
-+        },
-+        next_selectors=(
-+            "a.pager__button--next",
-+            "li.next a",
-+            'a[data-qa="pager__next"]',
-+        ),
-+        columns=columns,
-+        max_pages=50,
-+        page_sleep_range=(6.0, 18.0),
-+        empty_result_markers=(
-+            "No companies found",
-+            "We couldn't find any results",
-+            "Try adjusting your filters",
-+        ),
-+    )
-+
-+
-+def pitchbook_people_cfg() -> ListConfig:
-+    base = "https://pitchbook.com/"
-+
-+    def build_url(query: str) -> str:
-+        return _pitchbook_search_url("person", query, base)
-+
-+    columns = [
-+        "name",
-+        "title",
-+        "affiliation",
-+        "location",
-+        "last_update",
-+        "profile_url",
-+        "linkedin",
-+    ]
-+
-+    return ListConfig(
-+        name="pitchbook_people",
-+        base=base,
-+        build_search_url=build_url,
-+        row_selectors=(
-+            "div.search-results__result",
-+            "article.result-card",
-+            'div[data-qa="search-results__result"]',
-+        ),
-+        field_selectors={
-+            "name": (
-+                "a.result-card__title-link",
-+                "h3 a",
-+                'a[data-qa="result-card__title-link"]',
-+            ),
-+            "title": (
-+                "span.result-card__subtitle",
-+                "div.result-card__subtitle",
-+                'span[data-qa="result-card__subtitle"]',
-+            ),
-+            "affiliation": (
-+                "span.result-card__affiliation",
-+                "div.result-card__affiliation",
-+                'span[data-qa="result-card__affiliation"]',
-+            ),
-+            "location": (
-+                "span.result-card__location",
-+                "div.result-card__location",
-+                'span[data-qa="result-card__location"]',
-+            ),
-+            "last_update": (
-+                "span.result-card__last-update",
-+                "time.result-card__last-update",
-+                'span[data-qa="result-card__last-update"]',
-+            ),
-+            "profile_url": (
-+                "a.result-card__title-link",
-+                'a[data-qa="result-card__title-link"]',
-+            ),
-+        },
-+        optional_fields={
-+            "linkedin": (
-+                "a.result-card__linkedin",
-+                'a[href*="linkedin.com"]',
-+                'a[data-qa="result-card__linkedin"]',
-+            ),
-+        },
-+        next_selectors=(
-+            "a.pager__button--next",
-+            "li.next a",
-+            'a[data-qa="pager__next"]',
-+        ),
-+        columns=columns,
-+        max_pages=50,
-+        page_sleep_range=(6.0, 18.0),
-+        empty_result_markers=(
-+            "No people found",
-+            "Try adjusting your filters",
-+            "We couldn't find any results",
-+        ),
-+    )
-+
-+
-+def pitchbook_investor_cfg() -> ListConfig:
-+    base = "https://pitchbook.com/"
-+
-+    def build_url(query: str) -> str:
-+        return _pitchbook_search_url("investor", query, base)
-+
-+    columns = [
-+        "name",
-+        "investor_type",
-+        "focus",
-+        "location",
-+        "last_update",
-+        "profile_url",
-+        "website",
-+    ]
-+
-+    return ListConfig(
-+        name="pitchbook_investors",
-+        base=base,
-+        build_search_url=build_url,
-+        row_selectors=(
-+            "div.search-results__result",
-+            "article.result-card",
-+            'div[data-qa="search-results__result"]',
-+        ),
-+        field_selectors={
-+            "name": (
-+                "a.result-card__title-link",
-+                "h3 a",
-+                'a[data-qa="result-card__title-link"]',
-+            ),
-+            "investor_type": (
-+                "span.result-card__subtitle",
-+                "div.result-card__subtitle",
-+                'span[data-qa="result-card__subtitle"]',
-+            ),
-+            "focus": (
-+                "span.result-card__focus",
-+                "div.result-card__focus",
-+                'span[data-qa="result-card__focus"]',
-+            ),
-+            "location": (
-+                "span.result-card__location",
-+                "div.result-card__location",
-+                'span[data-qa="result-card__location"]',
-+            ),
-+            "last_update": (
-+                "span.result-card__last-update",
-+                "time.result-card__last-update",
-+                'span[data-qa="result-card__last-update"]',
-+            ),
-+            "profile_url": (
-+                "a.result-card__title-link",
-+                'a[data-qa="result-card__title-link"]',
-+            ),
-+        },
-+        optional_fields={
-+            "website": (
-+                "a.result-card__website",
-+                'a[data-qa="result-card__website"]',
-+            ),
-+        },
-+        next_selectors=(
-+            "a.pager__button--next",
-+            "li.next a",
-+            'a[data-qa="pager__next"]',
-+        ),
-+        columns=columns,
-+        max_pages=50,
-+        page_sleep_range=(6.0, 18.0),
-+        empty_result_markers=(
-+            "No investors found",
-+            "We couldn't find any results",
-+            "Try adjusting your filters",
-+        ),
-+    )
-+def _default_output_name(entity: str, query: str) -> str:
-+    safe_query = re.sub(r"[^A-Za-z0-9._-]+", "_", query.strip()) or "query"
-+    return f"pitchbook_{entity}_{safe_query}.csv"
-+
-+
-+def _build_auth_options_from_args(args) -> PitchbookAuthOptions:
-+    return PitchbookAuthOptions(
-+        email=None,  # mechanized login removed
-+        password=None,
-+        session_id=os.getenv("ZYTE_SESSION_ID"),
-+        user_agent=args.user_agent or os.getenv("PITCHBOOK_USER_AGENT"),
-+        login_url=args.login_url or os.getenv("PITCHBOOK_LOGIN_URL"),
-+        login_form_selector=None,
-+        email_field=None,
-+        password_field=None,
-+        cookie_header=args.cookie_header or os.getenv("PITCHBOOK_COOKIE"),
-+        cookies_file=args.cookies_file or os.getenv("PITCHBOOK_COOKIES_FILE"),
-+    )
-+
-+
-+if __name__ == "__main__":
-+    import argparse
-+
-+    parser = argparse.ArgumentParser(description="PitchBook list exporter with offline modes and optional Zyte rendering")
-+    parser.add_argument(
-+        "entity",
-+        choices=["companies", "people", "investors"],
-+        help="Which PitchBook directory to crawl",
-+    )
-+    parser.add_argument("query", help="Search query to run on PitchBook or glob for offline HTML when --mode=offline")
-+    parser.add_argument("--output", "-o", help="Output CSV path")
-+    parser.add_argument(
-+        "--max-pages",
-+        type=int,
-+        help="Maximum number of result pages to crawl (defaults to the entity configuration)",
-+    )
-+    parser.add_argument(
-+        "--min-delay",
-+        type=float,
-+        help="Minimum pause in seconds between page requests",
-+    )
-+    parser.add_argument(
-+        "--max-delay",
-+        type=float,
-+        help="Maximum pause in seconds between page requests",
-+    )
-+    # Authentication: accept a cookie header instead of mechanized login
-+    parser.add_argument("--cookie-header", help="Cookie header string to authenticate to PitchBook")
-+    parser.add_argument("--cookies-file", help="Path to file containing a Cookie header")
-+    parser.add_argument(
-+        "--user-agent",
-+        help="Override the browser user-agent; defaults to a rotating profile",
-+    )
-+    parser.add_argument("--login-url", help="Override the login form URL")
-+    # Rendering mode and run mode
-+    parser.add_argument("--render", choices=["auto", "browser", "http"], default="auto", help="Rendering mode: auto (default), browser, or http")
-+    parser.add_argument("--mode", choices=["network", "offline"], default="offline", help="Run mode: offline (default) reads local HTML files; network uses Zyte API")
-+    parser.add_argument(
-+        "--skip-login",
-+        action="store_true",
-+        help="Skip login even if the selected directory normally requires it",
-+    )
-+    args = parser.parse_args()
-+
-+    cfg_factory = {
-+        "companies": pitchbook_company_cfg,
-+        "people": pitchbook_people_cfg,
-+        "investors": pitchbook_investor_cfg,
-+    }
-+
-+    cfg = cfg_factory[args.entity]()
-+    if args.skip_login:
-+        cfg.requires_login = False
-+
-+    output_path = args.output or _default_output_name(args.entity, args.query)
-+
-+    sleep_range: Optional[Tuple[float, float]] = None
-+    if args.min_delay is not None or args.max_delay is not None:
-+        if args.min_delay is None or args.max_delay is None:
-+            raise SystemExit("Both --min-delay and --max-delay must be supplied together.")
-+        sleep_range = (args.min_delay, args.max_delay)
-+
-+    auth_options = _build_auth_options_from_args(args)
-+    client: Optional[ZyteSessionClient] = None
-+    if args.mode == "network":
-+        if not ZYTE_API_KEY:
-+            raise SystemExit("ZYTE_API_KEY must be set for network mode.")
-+        client = ZyteSessionClient(ZYTE_API_KEY, auth_options, render_mode=args.render)
-+
-+    scraper = ListScraper(
-+        cfg=cfg,
-+        out_csv=output_path,
-+        max_pages=args.max_pages,
-+        page_sleep_range=sleep_range,
-+        client=client,
-+    )
-+    if args.mode == "offline":
-+        # Treat query as a glob of HTML files to parse
-+        html_files = sorted(glob.glob(args.query))
-+        scraper.crawl_offline_files(html_files)
-+    else:
-+        scraper.crawl(query=args.query)
-+
-+
-
-
+# pip install requests beautifulsoup4 tenacity
+
+import os
+import json
+import webbrowser
+import csv
+import time
+import random
+import re
+import uuid
+import hashlib
+import glob
+from dataclasses import dataclass, field
+from typing import Callable, Dict, Iterable, List, Optional, Tuple
+from urllib.parse import urljoin, urlencode, urlparse, urlsplit
+import http.cookiejar as cookiejar
+
+import requests
+from urllib import robotparser
+from bs4 import BeautifulSoup
+from bs4.element import Tag
+from tenacity import retry, wait_exponential_jitter, stop_after_attempt
+
+
+def _strip_or_none(value: Optional[str]) -> Optional[str]:
+    if value is None:
+        return None
+    value = value.strip()
+    return value or None
+
+
+ZYTE_API_KEY = os.getenv("ZYTE_API_KEY")
+ZYTE_ENDPOINT = "https://api.zyte.com/v1/extract"
+PITCHBOOK_LOGIN_URL_DEFAULT = "https://pitchbook.com/account/login"
+PROFILE_DIR = os.path.join(os.getcwd(), ".pb_profiles")
+
+
+def _origin(url: Optional[str]) -> Optional[str]:
+    if not url:
+        return None
+    parsed = urlparse(url)
+    if not parsed.scheme or not parsed.netloc:
+        return None
+    return f"{parsed.scheme}://{parsed.netloc}"
+
+
+def _registrable_domain(host: Optional[str]) -> Optional[str]:
+    if not host:
+        return None
+    parts = host.split(".")
+    if len(parts) < 2:
+        return host
+    return ".".join(parts[-2:])
+
+
+def _ensure_tuple(value: Optional[Iterable[str]]) -> Tuple[str, ...]:
+    if value is None:
+        return tuple()
+    if isinstance(value, (list, tuple)):
+        return tuple(value)
+    return (value,)
+
+
+@dataclass(frozen=True)
+class BrowserIdentity:
+    label: str
+    user_agent: str
+    accept_language: str
+
+    def document_headers(
+        self,
+        target_url: Optional[str],
+        referer: Optional[str] = None,
+        navigation: str = "navigate",
+        dest: str = "document",
+    ) -> Dict[str, str]:
+        # Minimize synthetic, high-entropy headers to avoid mismatches
+        headers = {
+            "User-Agent": self.user_agent,
+            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
+            "Accept-Language": self.accept_language,
+        }
+        if referer:
+            headers["Referer"] = referer
+        return headers
+
+    def form_headers(self, target_url: Optional[str], referer: Optional[str]) -> Dict[str, str]:
+        headers = self.document_headers(target_url, referer)
+        origin = _origin(target_url)
+        if origin:
+            headers["Origin"] = origin
+        headers["Content-Type"] = "application/x-www-form-urlencoded"
+        return headers
+
+
+BASE_IDENTITY_POOL: Tuple[BrowserIdentity, ...] = (
+    BrowserIdentity(
+        label="win-chrome-124",
+        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
+        accept_language="en-US,en;q=0.9",
+    ),
+    BrowserIdentity(
+        label="mac-chrome-123",
+        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
+        accept_language="en-US,en;q=0.9",
+    ),
+    BrowserIdentity(
+        label="win-edge-124",
+        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
+        accept_language="en-US,en;q=0.9",
+    ),
+    BrowserIdentity(
+        label="linux-chrome-123",
+        user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
+        accept_language="en-US,en;q=0.8",
+    ),
+    BrowserIdentity(
+        label="mac-safari-17",
+        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
+        accept_language="en-US,en;q=0.9",
+    ),
+    BrowserIdentity(
+        label="win-firefox-126",
+        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
+        accept_language="en-US,en;q=0.8",
+    ),
+    BrowserIdentity(
+        label="mac-firefox-126",
+        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:126.0) Gecko/20100101 Firefox/126.0",
+        accept_language="en-US,en;q=0.8",
+    ),
+)
+
+
+def _load_lines(path: Optional[str]) -> List[str]:
+    if not path:
+        return []
+    try:
+        with open(path, "r", encoding="utf-8") as fh:
+            lines = [ln.strip() for ln in fh.readlines()]
+        return [ln for ln in lines if ln and not ln.startswith("#")]
+    except Exception:
+        return []
+
+
+def _build_identity_pool(extra_user_agents: Optional[List[str]]) -> Tuple[BrowserIdentity, ...]:
+    pool: List[BrowserIdentity] = list(BASE_IDENTITY_POOL)
+    for idx, ua in enumerate(extra_user_agents or []):
+        if not ua:
+            continue
+        # Vary Accept-Language a bit across loaded UAs
+        lang = random.choice([
+            "en-US,en;q=0.9",
+            "en-GB,en;q=0.8",
+            "en-US;q=0.8,en;q=0.6",
+        ])
+        pool.append(BrowserIdentity(label=f"file-ua-{idx}", user_agent=ua, accept_language=lang))
+    return tuple(pool)
+
+
+def _profile_state_path(profile_name: str) -> str:
+    os.makedirs(PROFILE_DIR, exist_ok=True)
+    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", profile_name.strip()) or "default"
+    return os.path.join(PROFILE_DIR, f"{safe}.json")
+
+
+def _load_profile_state(profile_name: Optional[str]) -> Optional[Dict[str, str]]:
+    if not profile_name:
+        return None
+    path = _profile_state_path(profile_name)
+    if not os.path.exists(path):
+        return None
+    try:
+        with open(path, "r", encoding="utf-8") as fh:
+            return json.load(fh)
+    except Exception:
+        return None
+
+
+def _save_profile_state(profile_name: Optional[str], state: Dict[str, str]) -> None:
+    if not profile_name:
+        return
+    try:
+        path = _profile_state_path(profile_name)
+        with open(path, "w", encoding="utf-8") as fh:
+            json.dump(state, fh, indent=2, sort_keys=True)
+    except Exception:
+        pass
+
+
+def _resolve_identity(
+    session_id: str,
+    override_ua: Optional[str],
+    identity_pool: Optional[Tuple[BrowserIdentity, ...]] = None,
+) -> BrowserIdentity:
+    if override_ua:
+        return BrowserIdentity(
+            label="custom",
+            user_agent=override_ua,
+            accept_language="en-US,en;q=0.9",
+        )
+    pool = identity_pool or BASE_IDENTITY_POOL
+    digest = hashlib.sha256(session_id.encode("utf-8")).digest()
+    idx = digest[0] % len(pool)
+    return pool[idx]
+
+
+class AuthenticationError(RuntimeError):
+    pass
+
+
+class ChallengeError(RuntimeError):
+    pass
+
+
+class ThrottleError(RuntimeError):
+    pass
+
+
+@dataclass
+class PageContent:
+    url: str
+    html: str
+    soup: BeautifulSoup
+    status: Optional[int] = None
+
+
+@dataclass
+class ListConfig:
+    name: str
+    base: str
+    build_search_url: Callable[[str], str]
+    row_selectors: Iterable[str]
+    field_selectors: Dict[str, Iterable[str]]
+    optional_fields: Dict[str, Iterable[str]] = field(default_factory=dict)
+    next_selectors: Iterable[str] = field(default_factory=lambda: ("li.next a",))
+    columns: List[str] = field(default_factory=list)
+    max_pages: int = 50
+    page_sleep_range: Tuple[float, float] = (6.0, 18.0)
+    requires_login: bool = True
+    empty_result_markers: Tuple[str, ...] = ("No results found", "Try adjusting your filters")
+
+    def __post_init__(self) -> None:
+        self.row_selectors = _ensure_tuple(self.row_selectors)
+        self.next_selectors = _ensure_tuple(self.next_selectors)
+        self.field_selectors = {key: _ensure_tuple(value) for key, value in self.field_selectors.items()}
+        self.optional_fields = {key: _ensure_tuple(value) for key, value in self.optional_fields.items()}
+        if not self.columns:
+            ordered: List[str] = list(self.field_selectors.keys())
+            for col in self.optional_fields.keys():
+                if col not in ordered:
+                    ordered.append(col)
+            self.columns = ordered
+
+
+@dataclass
+class PitchbookAuthOptions:
+    email: Optional[str] = None
+    password: Optional[str] = None
+    session_id: Optional[str] = None
+    user_agent: Optional[str] = None
+    login_url: Optional[str] = None
+    login_form_selector: Optional[str] = None
+    email_field: Optional[str] = None
+    password_field: Optional[str] = None
+    cookie_header: Optional[str] = None
+    cookies_file: Optional[str] = None
+
+    def __post_init__(self) -> None:
+        self.email = _strip_or_none(self.email)
+        self.password = _strip_or_none(self.password)
+        self.session_id = _strip_or_none(self.session_id)
+        self.user_agent = _strip_or_none(self.user_agent)
+        self.login_url = _strip_or_none(self.login_url)
+        self.login_form_selector = _strip_or_none(self.login_form_selector)
+        self.email_field = _strip_or_none(self.email_field)
+        self.password_field = _strip_or_none(self.password_field)
+        self.cookie_header = _strip_or_none(self.cookie_header)
+        self.cookies_file = _strip_or_none(self.cookies_file)
+
+    def resolved_login_url(self) -> str:
+        return self.login_url or PITCHBOOK_LOGIN_URL_DEFAULT
+
+    def resolved_session_id(self) -> str:
+        return self.session_id or f"pitchbook-{uuid.uuid4().hex}"
+
+    def has_credentials(self) -> bool:
+        return bool(self.email and self.password)
+
+
+class AdaptiveThrottle:
+    def __init__(self, base_range: Tuple[float, float]):
+        self.base_low, self.base_high = base_range
+        self.penalty = random.uniform(0.2, 1.0)
+
+    def propose_delay(self, modifier: float = 0.0) -> float:
+        # Heavy-tailed randomization with occasional longer pauses
+        base = random.uniform(self.base_low, self.base_high) + modifier + self.penalty
+        # Add a small lognormal jitter
+        base += random.lognormvariate(0.0, 0.25) - 1.0
+        # 5% chance to take a longer break
+        if random.random() < 0.05:
+            base += random.uniform(20.0, 75.0)
+        return max(0.5, base)
+
+    def record_success(self) -> None:
+        if self.penalty > 0:
+            self.penalty = max(0.0, self.penalty - random.uniform(0.1, 0.4))
+
+    def record_penalty(self, severity: float = 1.5) -> None:
+        self.penalty = min(18.0, self.penalty + severity)
+
+
+class ZyteSessionClient:
+    def __init__(
+        self,
+        api_key: str,
+        auth: Optional[PitchbookAuthOptions] = None,
+        render_mode: str = "auto",
+        identity_pool: Optional[Tuple[BrowserIdentity, ...]] = None,
+        session_id: Optional[str] = None,
+    ):
+        self.api_key = api_key
+        self.auth = auth or PitchbookAuthOptions()
+        self.session_id = session_id or self.auth.resolved_session_id()
+        self.identity = _resolve_identity(self.session_id, self.auth.user_agent, identity_pool)
+        self.login_url = self.auth.resolved_login_url()
+        self._authenticated = False
+        self._auth_failures = 0
+        self._last_url: Optional[str] = None
+        self._cookie_header: Optional[str] = self._load_cookie_header()
+        self._render_mode: str = render_mode  # auto | browser | http
+        self._cache: Dict[str, PageContent] = {}
+        self._cache_order: List[str] = []
+        self._cache_capacity: int = 32
+
+    @retry(wait=wait_exponential_jitter(initial=1, max=12), stop=stop_after_attempt(5))
+    def _request_zyte(self, payload: Dict) -> Dict:
+        response = requests.post(
+            ZYTE_ENDPOINT,
+            auth=(self.api_key, ""),
+            json=payload,
+            timeout=70,
+            headers={"Content-Type": "application/json"},
+        )
+        if response.status_code == 400:
+            try:
+                print("Zyte 400:", response.json())
+            except Exception:
+                print("Zyte 400 raw:", response.text[:500])
+        response.raise_for_status()
+        return response.json()
+
+    def _extract_status(self, data: Dict) -> Optional[int]:
+        for key in ("statusCode", "httpResponseStatusCode", "httpResponseStatus"):
+            value = data.get(key)
+            if isinstance(value, int):
+                return value
+            try:
+                return int(value)  # type: ignore[arg-type]
+            except (TypeError, ValueError):
+                continue
+        return None
+
+    def _html_from(self, data: Dict) -> str:
+        return data.get("browserHtml") or data.get("httpResponseBody") or ""
+
+    @staticmethod
+    def _classify_page_text(text: str) -> Optional[str]:
+        t = text.lower()[:8000]
+        if any(token in t for token in ("log in", "sign in", "login", "please sign in", "session expired")):
+            return "login"
+        if any(token in t for token in ("verify you are human", "captcha", "security check", "robot check", "please enable javascript")):
+            return "challenge"
+        if any(token in t for token in ("too many requests", "rate limit", "temporarily blocked", "unusual traffic", "request limit", "throttled", "quota exceeded")):
+            return "throttle"
+        return None
+
+    def _load_cookie_header(self) -> Optional[str]:
+        if self.auth.cookie_header:
+            return self.auth.cookie_header
+        if self.auth.cookies_file and os.path.exists(self.auth.cookies_file):
+            try:
+                with open(self.auth.cookies_file, "r", encoding="utf-8") as fh:
+                    content = fh.read().strip()
+                if content.lower().startswith("cookie:"):
+                    content = content.split(":", 1)[1].strip()
+                return content or None
+            except Exception:
+                return None
+        return None
+
+    def _render_once(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
+        request_payload = dict(payload)
+        target_url = request_payload.get("url")
+        # Lightweight GET cache
+        if (
+            not request_payload.get("httpRequestMethod")
+            and not request_payload.get("httpRequestBody")
+            and isinstance(target_url, str)
+            and target_url in self._cache
+        ):
+            return self._cache[target_url]
+        base_headers = self.identity.document_headers(target_url, referer)
+        if self._cookie_header:
+            base_headers["Cookie"] = self._cookie_header
+        extra_headers = request_payload.get("httpRequestHeaders") or {}
+        if extra_headers:
+            base_headers.update(extra_headers)
+        request_payload["httpRequestHeaders"] = base_headers
+        session_spec = request_payload.setdefault("session", {})
+        session_spec.setdefault("id", self.session_id)
+
+        data = self._request_zyte(request_payload)
+        html = self._html_from(data)
+        soup = BeautifulSoup(html, "html.parser") if html else BeautifulSoup("", "html.parser")
+        classification = self._classify_page_text(soup.get_text(" ", strip=True))
+        if classification == "login" and not allow_login:
+            self._authenticated = False
+            raise AuthenticationError("Authentication required. Provide a valid cookie via --cookie-header or --cookies-file, or use --skip-login.")
+        if classification == "challenge":
+            self._authenticated = False
+            raise ChallengeError("Access verification required.")
+        if classification == "throttle":
+            raise ThrottleError("Service reported temporary rate limits.")
+        status_code = self._extract_status(data)
+        page = PageContent(url=target_url, html=html, soup=soup, status=status_code)
+        if (
+            not request_payload.get("httpRequestMethod")
+            and not request_payload.get("httpRequestBody")
+            and isinstance(target_url, str)
+        ):
+            self._cache[target_url] = page
+            self._cache_order.append(target_url)
+            if len(self._cache_order) > self._cache_capacity:
+                evict = self._cache_order.pop(0)
+                self._cache.pop(evict, None)
+        return page
+
+    def _render(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
+        mode = self._render_mode
+        if mode == "browser":
+            payload = dict(payload)
+            payload["browserHtml"] = True
+            return self._render_once(payload, allow_login=allow_login, referer=referer)
+        if mode == "http":
+            payload = dict(payload)
+            payload.pop("browserHtml", None)
+            return self._render_once(payload, allow_login=allow_login, referer=referer)
+        # auto
+        first_payload = dict(payload)
+        first_payload.pop("browserHtml", None)
+        try:
+            result = self._render_once(first_payload, allow_login=allow_login, referer=referer)
+        except (AuthenticationError, ChallengeError, ThrottleError):
+            raise
+        looks_empty = not result.html or len(result.html) < 512 or len(result.soup.get_text(" ", strip=True)) < 80
+        if looks_empty:
+            second_payload = dict(payload)
+            second_payload["browserHtml"] = True
+            return self._render_once(second_payload, allow_login=allow_login, referer=referer)
+        return result
+
+    def ensure_logged_in(self, require: bool = False) -> None:
+        if not require:
+            return
+        if self._authenticated:
+            return
+        if not self._cookie_header:
+            raise RuntimeError(
+                "Authentication is required. Provide a cookie via --cookie-header or --cookies-file, or run with --skip-login."
+            )
+        self._authenticated = True
+
+    def fetch_page(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> PageContent:
+        if require_login:
+            self.ensure_logged_in(require=True)
+        effective_referer = referer or self._last_url
+        page = self._render(
+            {"url": url},
+            allow_login=False,
+            referer=effective_referer,
+        )
+        self._authenticated = True
+        self._last_url = url
+        return page
+
+    def fetch_html(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> str:
+        return self.fetch_page(url, require_login=require_login, referer=referer).html
+
+
+class DirectSessionClient:
+    def __init__(
+        self,
+        auth: Optional[PitchbookAuthOptions] = None,
+        identity_pool: Optional[Tuple[BrowserIdentity, ...]] = None,
+        proxy_url: Optional[str] = None,
+        session_id: Optional[str] = None,
+        profile: Optional[str] = None,
+        proxy_pool: Optional[List[str]] = None,
+    ):
+        self.auth = auth or PitchbookAuthOptions()
+        self.session_id = session_id or self.auth.resolved_session_id()
+        self.identity = _resolve_identity(self.session_id, self.auth.user_agent, identity_pool)
+        self._last_url: Optional[str] = None
+        self._cookie_header: Optional[str] = None
+        self._session = requests.Session()
+        self._profile = profile
+        self._proxy_pool = proxy_pool or ([] if not proxy_url else [proxy_url])
+        self._current_proxy: Optional[str] = None
+        self._set_proxy(self._choose_proxy(initial=True))
+        # Load cookies: prefer Netscape/Mozilla cookie jar for domain/path scoping
+        if self.auth.cookies_file and os.path.exists(self.auth.cookies_file):
+            try:
+                with open(self.auth.cookies_file, "r", encoding="utf-8") as fh:
+                    peek = fh.read(128)
+                if "Netscape HTTP Cookie File" in peek or peek.strip().startswith("# Netscape"):
+                    jar = cookiejar.MozillaCookieJar()
+                    jar.load(self.auth.cookies_file, ignore_discard=True, ignore_expires=False)
+                    self._session.cookies = jar  # type: ignore[assignment]
+                else:
+                    with open(self.auth.cookies_file, "r", encoding="utf-8") as fh:
+                        content = fh.read().strip()
+                    if content.lower().startswith("cookie:"):
+                        content = content.split(":", 1)[1].strip()
+                    if content:
+                        self._cookie_header = content
+            except Exception:
+                pass
+        elif self.auth.cookie_header:
+            self._cookie_header = self.auth.cookie_header
+        # Load persisted state (proxy, extra headers) for profile
+        state = _load_profile_state(self._profile)
+        if state and not proxy_url and not self._proxy_pool:
+            saved_proxy = state.get("proxy")
+            if saved_proxy:
+                self._set_proxy(saved_proxy)
+
+    def ensure_logged_in(self, require: bool = False) -> None:
+        if not require:
+            return
+        if not (self._cookie_header or len(self._session.cookies) > 0):
+            raise RuntimeError(
+                "Authentication is required. Provide a cookies file in Netscape format or a Cookie header."
+            )
+
+    def fetch_page(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> PageContent:
+        if require_login:
+            self.ensure_logged_in(require=True)
+        headers = self.identity.document_headers(url, referer)
+        if self._cookie_header:
+            headers["Cookie"] = self._cookie_header
+        try:
+            resp = self._session.get(url, headers=headers, timeout=70, allow_redirects=True)
+        except requests.RequestException as exc:
+            # Rotate proxy on network-level errors
+            self._maybe_rotate_proxy(reason="network_error")
+            raise ThrottleError(str(exc))
+        html = resp.text or ""
+        soup = BeautifulSoup(html, "html.parser") if html else BeautifulSoup("", "html.parser")
+        classification = ZyteSessionClient._classify_page_text(soup.get_text(" ", strip=True))
+        if classification == "login" and not require_login:
+            self._persist_state()
+            raise AuthenticationError("Authentication required.")
+        if classification == "challenge":
+            self._maybe_rotate_proxy(reason="challenge")
+            self._persist_state()
+            raise ChallengeError("Access verification required.")
+        if classification == "throttle":
+            self._maybe_rotate_proxy(reason="throttle")
+            self._persist_state()
+            raise ThrottleError("Service reported temporary rate limits.")
+        self._last_url = url
+        self._persist_state()
+        return PageContent(url=url, html=html, soup=soup, status=resp.status_code)
+
+    def fetch_html(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> str:
+        return self.fetch_page(url, require_login=require_login, referer=referer).html
+
+    # --- Proxy rotation & state persistence ---
+    def _choose_proxy(self, initial: bool = False) -> Optional[str]:
+        if not self._proxy_pool:
+            return None
+        if initial and self._current_proxy:
+            return self._current_proxy
+        return random.choice(self._proxy_pool)
+
+    def _set_proxy(self, proxy_url: Optional[str]) -> None:
+        self._current_proxy = proxy_url
+        if proxy_url:
+            self._session.proxies = {"http": proxy_url, "https": proxy_url}
+        else:
+            self._session.proxies.clear()
+
+    def _maybe_rotate_proxy(self, reason: str) -> None:
+        # Rotate only if a pool is available
+        if not self._proxy_pool or len(self._proxy_pool) < 2:
+            return
+        # Small probability to rotate even on success to avoid long binding
+        should_rotate = reason in {"throttle", "challenge", "network_error"} or (random.random() < 0.07)
+        if should_rotate:
+            next_proxy = self._choose_proxy()
+            if next_proxy and next_proxy != self._current_proxy:
+                self._set_proxy(next_proxy)
+
+    def _persist_state(self) -> None:
+        state: Dict[str, str] = {}
+        if self._current_proxy:
+            state["proxy"] = self._current_proxy
+        _save_profile_state(self._profile, state)
+
+
+class ListScraper:
+    def __init__(
+        self,
+        cfg: ListConfig,
+        out_csv: str = "results.csv",
+        max_pages: Optional[int] = None,
+        page_sleep_range: Optional[Tuple[float, float]] = None,
+        client: Optional[object] = None,
+    ):
+        self.cfg = cfg
+        self.out_csv = out_csv
+        self.max_pages = max_pages if max_pages is not None else cfg.max_pages
+        if self.max_pages is not None and self.max_pages <= 0:
+            raise ValueError("max_pages must be a positive integer")
+        sleep_range = tuple(page_sleep_range or cfg.page_sleep_range)
+        if len(sleep_range) != 2:
+            raise ValueError("page_sleep_range must contain exactly two values")
+        low, high = sleep_range
+        if low < 0 or high < 0 or low > high:
+            raise ValueError("page_sleep_range must be non-negative and increasing")
+        self.page_sleep_range = (low, high)
+        self.client = client
+        self.throttle = AdaptiveThrottle(self.page_sleep_range)
+        self.max_empty_pages = 1
+
+    def build_search_url(self, query: str) -> str:
+        return self.cfg.build_search_url(query)
+
+    def parse_rows(self, soup: BeautifulSoup, page_url: str) -> List[dict]:
+        row_groups: List[Tag] = []
+        for selector in self.cfg.row_selectors:
+            row_groups = list(soup.select(selector))
+            if row_groups:
+                break
+        if not row_groups:
+            # Heuristic fallback: look for anchors likely pointing to profile pages
+            return self._heuristic_parse_rows(soup, page_url)
+        rows: List[dict] = []
+        for row in row_groups:
+            record: Dict[str, str] = {}
+            for col, selectors in self.cfg.field_selectors.items():
+                record[col] = self._extract_value(row, selectors, page_url)
+            for col, selectors in self.cfg.optional_fields.items():
+                value = self._extract_value(row, selectors, page_url)
+                if value:
+                    record[col] = value
+            rows.append(record)
+        return rows
+
+    def _extract_value(self, row: Tag, selectors: Iterable[str], page_url: str) -> str:
+        for sel in selectors:
+            if not sel:
+                continue
+            el = row.select_one(sel)
+            if not el:
+                continue
+            if el.name == "a" and el.get("href"):
+                href = el.get("href")
+                if href:
+                    return urljoin(page_url, href.strip())
+            text = el.get("title") or el.get_text(" ", strip=True)
+            if text:
+                return text
+        return ""
+
+    def _heuristic_parse_rows(self, soup: BeautifulSoup, page_url: str) -> List[dict]:
+        anchors = soup.select('a.result-card__title-link, a[href*="/profiles/"], a[href*="/profile/"]')
+        seen: set = set()
+        results: List[dict] = []
+        for a in anchors:
+            href = a.get("href")
+            if not href:
+                continue
+            abs_url = urljoin(page_url, href.strip())
+            if abs_url in seen:
+                continue
+            seen.add(abs_url)
+            container = a.find_parent("article") or a.find_parent("div") or a
+            name = (a.get("title") or a.get_text(" ", strip=True) or "").strip()
+            # Try to find nearby text blocks that could be description or location
+            headline = ""
+            location = ""
+            desc_el = container.select_one(
+                ".result-card__description, p, .subtitle, .summary, [data-qa*='description']"
+            )
+            if desc_el:
+                headline = desc_el.get_text(" ", strip=True)
+            loc_el = container.select_one(
+                ".result-card__location, .location, [data-qa*='location']"
+            )
+            if loc_el:
+                location = loc_el.get_text(" ", strip=True)
+            record: Dict[str, str] = {
+                "name": name,
+                "headline": headline,
+                "location": location,
+                "profile_url": abs_url,
+            }
+            results.append(record)
+        return results
+
+    def _robots_allows(self, url: str) -> bool:
+        try:
+            parts = urlsplit(url)
+            robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
+            rp = robotparser.RobotFileParser()
+            rp.set_url(robots_url)
+            rp.read()
+            # If we have no client (offline), allow by default
+            ua = self.client.identity.user_agent if getattr(self.client, "identity", None) else "*"
+            return rp.can_fetch(ua, url)
+        except Exception:
+            # If robots cannot be fetched, err on the safe side by allowing
+            return True
+
+    def crawl(self, query: str) -> None:
+        require_login = getattr(self.cfg, "requires_login", True)
+        if require_login and self.client:
+            self.client.ensure_logged_in(require=True)
+        url = self.build_search_url(query)
+        if self.client and not self._robots_allows(url):
+            print(f"[{self.cfg.name}] robots.txt disallows this path for the configured User-Agent; exiting.")
+            return
+        total = 0
+        pages = 0
+        referer: Optional[str] = None
+        consecutive_empty = 0
+        # Session warm up: optionally visit the site root and a random internal page
+        initial_pause = random.uniform(2.0, 7.0)
+        print(f"[{self.cfg.name}] Warming up ({initial_pause:.2f}s)...")
+        time.sleep(initial_pause)
+        if hasattr(self.client, "fetch_page") and random.random() < 0.65:
+            try:
+                base_visit = self.client.fetch_page(self.cfg.base, require_login=require_login)
+                time.sleep(random.uniform(1.0, 5.0))
+                # Random exploratory follow: pick any anchor from the base page
+                links = [a.get("href") for a in base_visit.soup.select("a[href]")]
+                random.shuffle(links)
+                picked: Optional[str] = None
+                for href in links[:50]:
+                    if not href:
+                        continue
+                    if href.startswith("#"):
+                        continue
+                    if href.startswith("javascript:"):
+                        continue
+                    picked = urljoin(self.cfg.base, href)
+                    break
+                if picked:
+                    self.client.fetch_page(picked, require_login=False, referer=self.cfg.base)
+                    time.sleep(random.uniform(1.0, 4.0))
+            except Exception:
+                pass
+        while url and (self.max_pages is None or pages < self.max_pages):
+            page_attempt = 0
+            while True:
+                page_attempt += 1
+                try:
+                    page = self.client.fetch_page(url, require_login=require_login, referer=referer)  # type: ignore[union-attr]
+                    break
+                except AuthenticationError:
+                    print(f"[{self.cfg.name}] Access requires authentication.")
+                    return
+                except ThrottleError:
+                    penalty = 1.5 + page_attempt
+                    self.throttle.record_penalty(severity=penalty)
+                    wait_for = self.throttle.propose_delay(modifier=penalty)
+                    print(f"[{self.cfg.name}] Backing off for {wait_for:.2f}s...")
+                    time.sleep(wait_for)
+                    if page_attempt >= 4:
+                        print(f"[{self.cfg.name}] Multiple backoffs encountered; wrapping up.")
+                        return
+                    continue
+                except ChallengeError:
+                    print(f"[{self.cfg.name}] Encountered a verification gate; stopping.")
+                    return
+            soup = page.soup
+            rows = self.parse_rows(soup, page.url)
+            if not rows:
+                referer = page.url
+                consecutive_empty += 1
+                if self._looks_like_empty_results(soup):
+                    print(f"[{self.cfg.name}] Page {pages + 1}: no visible results; ending.")
+                    break
+                if consecutive_empty > self.max_empty_pages:
+                    print(f"[{self.cfg.name}] Page {pages + 1}: unable to extract list items consistently; ending.")
+                    break
+                self.throttle.record_penalty(severity=2.5)
+                wait_for = self.throttle.propose_delay(modifier=random.uniform(6.0, 12.0))
+                print(f"[{self.cfg.name}] Page {pages + 1}: could not extract rows; retry in {wait_for:.2f}s.")
+                time.sleep(wait_for)
+                continue
+            consecutive_empty = 0
+            self.append_csv(rows)
+            total += len(rows)
+            pages += 1
+            print(f"[{self.cfg.name}] Page {pages}: saved {len(rows)} rows (total={total}) -> {self.out_csv}")
+            referer = page.url
+            next_url = self.next_page(soup, page.url)
+            if not next_url:
+                # Early stop probability to avoid full pagination sweeps
+                if random.random() < 0.12:
+                    print(f"[{self.cfg.name}] Stopping early by choice.")
+                    break
+                else:
+                    break
+            url = next_url
+            wait_for = self.throttle.propose_delay()
+            self.throttle.record_success()
+            print(f"[{self.cfg.name}] Next page in {wait_for:.2f}s")
+            time.sleep(wait_for)
+        print(f"[{self.cfg.name}] Done. Pages: {pages}, Rows: {total}, File: {self.out_csv}")
+
+    def _looks_like_empty_results(self, soup: BeautifulSoup) -> bool:
+        text = soup.get_text(" ", strip=True).lower()
+        for marker in self.cfg.empty_result_markers:
+            if marker.lower() in text:
+                return True
+        return False
+
+    def next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
+        for selector in self.cfg.next_selectors:
+            nxt = soup.select_one(selector)
+            if nxt and nxt.get("href"):
+                return urljoin(current_url, nxt["href"])
+        return None
+
+    def append_csv(self, batch: List[dict]) -> None:
+        file_exists = os.path.exists(self.out_csv)
+        with open(self.out_csv, "a", newline="", encoding="utf-8") as f:
+            writer = csv.DictWriter(f, fieldnames=self.cfg.columns)
+            if not file_exists:
+                writer.writeheader()
+            for record in batch:
+                writer.writerow({k: record.get(k, "") for k in self.cfg.columns})
+
+    def crawl_offline_files(self, html_files: List[str]) -> None:
+        if not html_files:
+            raise RuntimeError("No HTML files were provided for offline ingestion.")
+        total = 0
+        pages = 0
+        for path in html_files:
+            try:
+                with open(path, "r", encoding="utf-8") as fh:
+                    html = fh.read()
+            except Exception as exc:
+                print(f"[{self.cfg.name}] Skipping '{path}': {exc}")
+                continue
+            soup = BeautifulSoup(html, "html.parser")
+            rows = self.parse_rows(soup, page_url=f"file://{os.path.abspath(path)}")
+            if not rows:
+                print(f"[{self.cfg.name}] {os.path.basename(path)}: no rows parsed.")
+                continue
+            self.append_csv(rows)
+            total += len(rows)
+            pages += 1
+            print(f"[{self.cfg.name}] Parsed file {os.path.basename(path)}: saved {len(rows)} rows (total={total}) -> {self.out_csv}")
+        print(f"[{self.cfg.name}] Offline ingestion complete. Files: {pages}, Rows: {total}, File: {self.out_csv}")
+
+
+def _pitchbook_search_url(entity: str, query: str, base: str) -> str:
+    params = {"q": query, "entity": entity}
+    return urljoin(base, f"profiles/search/?{urlencode(params)}")
+
+
+def pitchbook_company_cfg() -> ListConfig:
+    base = "https://pitchbook.com/"
+
+    def build_url(query: str) -> str:
+        return _pitchbook_search_url("company", query, base)
+
+    columns = [
+        "name",
+        "headline",
+        "location",
+        "industries",
+        "last_update",
+        "profile_url",
+        "website",
+    ]
+
+    return ListConfig(
+        name="pitchbook_companies",
+        base=base,
+        build_search_url=build_url,
+        row_selectors=(
+            "div.search-results__result",
+            "article.result-card",
+            'div[data-qa="search-results__result"]',
+        ),
+        field_selectors={
+            "name": (
+                "a.result-card__title-link",
+                "h3 a",
+                'a[data-qa="result-card__title-link"]',
+            ),
+            "headline": (
+                "div.result-card__description",
+                "p.result-card__description",
+                'div[data-qa="result-card__description"]',
+            ),
+            "location": (
+                "span.result-card__location",
+                "div.result-card__location",
+                'span[data-qa="result-card__location"]',
+            ),
+            "industries": (
+                "span.result-card__industries",
+                "div.result-card__industries",
+                'span[data-qa="result-card__industries"]',
+            ),
+            "last_update": (
+                "span.result-card__last-update",
+                "time.result-card__last-update",
+                'span[data-qa="result-card__last-update"]',
+            ),
+            "profile_url": (
+                "a.result-card__title-link",
+                'a[data-qa="result-card__title-link"]',
+            ),
+        },
+        optional_fields={
+            "website": (
+                "a.result-card__website",
+                'a[data-qa="result-card__website"]',
+            ),
+        },
+        next_selectors=(
+            "a.pager__button--next",
+            "li.next a",
+            'a[data-qa="pager__next"]',
+        ),
+        columns=columns,
+        max_pages=50,
+        page_sleep_range=(6.0, 18.0),
+        empty_result_markers=(
+            "No companies found",
+            "We couldn't find any results",
+            "Try adjusting your filters",
+        ),
+    )
+
+
+def pitchbook_people_cfg() -> ListConfig:
+    base = "https://pitchbook.com/"
+
+    def build_url(query: str) -> str:
+        return _pitchbook_search_url("person", query, base)
+
+    columns = [
+        "name",
+        "title",
+        "affiliation",
+        "location",
+        "last_update",
+        "profile_url",
+        "linkedin",
+    ]
+
+    return ListConfig(
+        name="pitchbook_people",
+        base=base,
+        build_search_url=build_url,
+        row_selectors=(
+            "div.search-results__result",
+            "article.result-card",
+            'div[data-qa="search-results__result"]',
+        ),
+        field_selectors={
+            "name": (
+                "a.result-card__title-link",
+                "h3 a",
+                'a[data-qa="result-card__title-link"]',
+            ),
+            "title": (
+                "span.result-card__subtitle",
+                "div.result-card__subtitle",
+                'span[data-qa="result-card__subtitle"]',
+            ),
+            "affiliation": (
+                "span.result-card__affiliation",
+                "div.result-card__affiliation",
+                'span[data-qa="result-card__affiliation"]',
+            ),
+            "location": (
+                "span.result-card__location",
+                "div.result-card__location",
+                'span[data-qa="result-card__location"]',
+            ),
+            "last_update": (
+                "span.result-card__last-update",
+                "time.result-card__last-update",
+                'span[data-qa="result-card__last-update"]',
+            ),
+            "profile_url": (
+                "a.result-card__title-link",
+                'a[data-qa="result-card__title-link"]',
+            ),
+        },
+        optional_fields={
+            "linkedin": (
+                "a.result-card__linkedin",
+                'a[href*="linkedin.com"]',
+                'a[data-qa="result-card__linkedin"]',
+            ),
+        },
+        next_selectors=(
+            "a.pager__button--next",
+            "li.next a",
+            'a[data-qa="pager__next"]',
+        ),
+        columns=columns,
+        max_pages=50,
+        page_sleep_range=(6.0, 18.0),
+        empty_result_markers=(
+            "No people found",
+            "Try adjusting your filters",
+            "We couldn't find any results",
+        ),
+    )
+
+
+def pitchbook_investor_cfg() -> ListConfig:
+    base = "https://pitchbook.com/"
+
+    def build_url(query: str) -> str:
+        return _pitchbook_search_url("investor", query, base)
+
+    columns = [
+        "name",
+        "investor_type",
+        "focus",
+        "location",
+        "last_update",
+        "profile_url",
+        "website",
+    ]
+
+    return ListConfig(
+        name="pitchbook_investors",
+        base=base,
+        build_search_url=build_url,
+        row_selectors=(
+            "div.search-results__result",
+            "article.result-card",
+            'div[data-qa="search-results__result"]',
+        ),
+        field_selectors={
+            "name": (
+                "a.result-card__title-link",
+                "h3 a",
+                'a[data-qa="result-card__title-link"]',
+            ),
+            "investor_type": (
+                "span.result-card__subtitle",
+                "div.result-card__subtitle",
+                'span[data-qa="result-card__subtitle"]',
+            ),
+            "focus": (
+                "span.result-card__focus",
+                "div.result-card__focus",
+                'span[data-qa="result-card__focus"]',
+            ),
+            "location": (
+                "span.result-card__location",
+                "div.result-card__location",
+                'span[data-qa="result-card__location"]',
+            ),
+            "last_update": (
+                "span.result-card__last-update",
+                "time.result-card__last-update",
+                'span[data-qa="result-card__last-update"]',
+            ),
+            "profile_url": (
+                "a.result-card__title-link",
+                'a[data-qa="result-card__title-link"]',
+            ),
+        },
+        optional_fields={
+            "website": (
+                "a.result-card__website",
+                'a[data-qa="result-card__website"]',
+            ),
+        },
+        next_selectors=(
+            "a.pager__button--next",
+            "li.next a",
+            'a[data-qa="pager__next"]',
+        ),
+        columns=columns,
+        max_pages=50,
+        page_sleep_range=(6.0, 18.0),
+        empty_result_markers=(
+            "No investors found",
+            "We couldn't find any results",
+            "Try adjusting your filters",
+        ),
+    )
+
+
+def _default_output_name(entity: str, query: str) -> str:
+    safe_query = re.sub(r"[^A-Za-z0-9._-]+", "_", query.strip()) or "query"
+    return f"pitchbook_{entity}_{safe_query}.csv"
+
+
+def _build_auth_options_from_args(args) -> PitchbookAuthOptions:
+    return PitchbookAuthOptions(
+        email=None,  # mechanized login removed
+        password=None,
+        session_id=args.session_id or os.getenv("ZYTE_SESSION_ID"),
+        user_agent=args.user_agent or os.getenv("PITCHBOOK_USER_AGENT"),
+        login_url=args.login_url or os.getenv("PITCHBOOK_LOGIN_URL"),
+        login_form_selector=None,
+        email_field=None,
+        password_field=None,
+        cookie_header=args.cookie_header or os.getenv("PITCHBOOK_COOKIE"),
+        cookies_file=args.cookies_file or os.getenv("PITCHBOOK_COOKIES_FILE"),
+    )
+
+
+def _render_ui_from_csv(csv_path: str, html_path: Optional[str] = None, title: str = "PitchBook Results") -> str:
+    if not os.path.exists(csv_path):
+        raise FileNotFoundError(csv_path)
+    rows: List[Dict[str, str]] = []
+    with open(csv_path, "r", encoding="utf-8") as fh:
+        reader = csv.DictReader(fh)
+        for r in reader:
+            rows.append({k: (v or "") for k, v in r.items()})
+    columns: List[str] = list(rows[0].keys()) if rows else []
+    data_json = json.dumps({"columns": columns, "rows": rows}, ensure_ascii=False)
+    # prevent closing the script tag if data contains </script>
+    data_json = data_json.replace("</", "<\/")
+    html = f"""
+<!doctype html>
+<html>
+<head>
+  <meta charset=\"utf-8\" />
+  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
+  <title>{title}</title>
+  <style>
+    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 20px; color: #222; }}
+    h1 {{ font-size: 20px; margin: 0 0 12px; }}
+    .controls {{ display: flex; gap: 12px; align-items: center; margin-bottom: 12px; flex-wrap: wrap; }}
+    input[type=text] {{ padding: 8px 10px; border: 1px solid #ccc; border-radius: 6px; min-width: 240px; }}
+    table {{ border-collapse: collapse; width: 100%; }}
+    thead th {{ position: sticky; top: 0; background: #fafafa; border-bottom: 1px solid #ddd; text-align: left; padding: 8px; font-weight: 600; }}
+    tbody td {{ border-top: 1px solid #eee; padding: 8px; vertical-align: top; }}
+    tbody tr:hover {{ background: #fffdf5; }}
+    a {{ color: #0066cc; text-decoration: none; }}
+    a:hover {{ text-decoration: underline; }}
+    .count {{ color: #666; font-size: 12px; }}
+  </style>
+  <script>window.__PB_DATA__ = {data_json};</script>
+</head>
+<body>
+  <h1>{title}</h1>
+  <div class=\"controls\">
+    <input id=\"q\" type=\"text\" placeholder=\"Search...\" />
+    <span class=\"count\" id=\"count\"></span>
+  </div>
+  <div style=\"overflow:auto; max-width:100%;\">
+    <table id=\"tbl\"> <thead id=\"thead\"></thead> <tbody id=\"tbody\"></tbody> </table>
+  </div>
+  <script>
+    const S = window.__PB_DATA__ || {columns:[], rows:[]};
+    const thead = document.getElementById('thead');
+    const tbody = document.getElementById('tbody');
+    const q = document.getElementById('q');
+    const countEl = document.getElementById('count');
+    function escapeHtml(s){return (s+"").replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;');}
+    function renderHead(){
+      const ths = S.columns.map(c=>`<th>${escapeHtml(c)}</th>`).join('');
+      thead.innerHTML = `<tr>${ths}</tr>`;
+    }
+    function isLink(val){return /^https?:\/\//i.test(val||'');}
+    function renderRows(filter){
+      const f = (filter||'').toLowerCase().trim();
+      let rows = S.rows;
+      if(f){ rows = rows.filter(r => S.columns.some(c => (r[c]||'').toLowerCase().includes(f))); }
+      const html = rows.map(r=>{
+        const tds = S.columns.map(c=>{
+          const v = r[c]||'';
+          if(isLink(v)) return `<td><a href="${escapeHtml(v)}" target="_blank" rel="noopener">${escapeHtml(v)}</a></td>`;
+          return `<td>${escapeHtml(v)}</td>`;
+        }).join('');
+        return `<tr>${tds}</tr>`;
+      }).join('');
+      tbody.innerHTML = html || '<tr><td colspan="'+S.columns.length+'" style="color:#999">No rows</td></tr>';
+      countEl.textContent = rows.length + ' rows';
+    }
+    renderHead();
+    renderRows('');
+    q.addEventListener('input', ()=>renderRows(q.value));
+  </script>
+</body>
+</html>
+"""
+    out = html_path or os.path.splitext(csv_path)[0] + ".html"
+    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
+    with open(out, "w", encoding="utf-8") as fh:
+        fh.write(html)
+    return out
+
+
+if __name__ == "__main__":
+    import argparse
+
+    parser = argparse.ArgumentParser(description="PitchBook list exporter with network, direct and offline modes")
+    parser.add_argument(
+        "entity",
+        choices=["companies", "people", "investors"],
+        help="Which PitchBook directory to crawl",
+    )
+    parser.add_argument("query", help="Search query to run on PitchBook or glob for offline HTML when --mode=offline")
+    parser.add_argument("--output", "-o", help="Output CSV path")
+    parser.add_argument("--open-ui", action="store_true", help="Open results in a local HTML UI after completion")
+    parser.add_argument(
+        "--max-pages",
+        type=int,
+        help="Maximum number of result pages to crawl (defaults to the entity configuration)",
+    )
+    parser.add_argument(
+        "--min-delay",
+        type=float,
+        help="Minimum pause in seconds between page requests",
+    )
+    parser.add_argument(
+        "--max-delay",
+        type=float,
+        help="Maximum pause in seconds between page requests",
+    )
+    # Authentication: accept a cookie header or cookie jar (file) instead of mechanized login
+    parser.add_argument("--cookie-header", help="Cookie header string to authenticate to PitchBook")
+    parser.add_argument("--cookies-file", help="Path to file containing a Cookie header or a Netscape cookie jar")
+    parser.add_argument(
+        "--user-agent",
+        help="Override the browser user-agent; defaults to a rotating profile",
+    )
+    parser.add_argument("--ua-file", help="Path to a file with one User-Agent per line to expand the pool")
+    parser.add_argument("--session-id", help="Override session id used for identity selection")
+    parser.add_argument("--login-url", help="Override the login form URL")
+    # Rendering mode and run mode
+    parser.add_argument("--render", choices=["auto", "browser", "http"], default="auto", help="Rendering mode for Zyte: auto (default), browser, or http")
+    parser.add_argument("--mode", choices=["network", "direct", "offline"], default="offline", help="Run mode: offline reads local HTML files; network uses Zyte API; direct uses requests + optional proxy")
+    # Proxy controls for direct mode
+    parser.add_argument("--proxy", help="Proxy URL for direct mode (e.g. http://user:pass@host:port)")
+    parser.add_argument("--proxy-file", help="Path to a file with proxy URLs; one will be chosen at random for the session")
+    parser.add_argument("--profile", help="Persistent profile name to bind UA/session/proxy across runs")
+    parser.add_argument(
+        "--skip-login",
+        action="store_true",
+        help="Skip login even if the selected directory normally requires it",
+    )
+    args = parser.parse_args()
+
+    cfg_factory = {
+        "companies": pitchbook_company_cfg,
+        "people": pitchbook_people_cfg,
+        "investors": pitchbook_investor_cfg,
+    }
+
+    cfg = cfg_factory[args.entity]()
+    if args.skip_login:
+        cfg.requires_login = False
+
+    output_path = args.output or _default_output_name(args.entity, args.query)
+
+    sleep_range: Optional[Tuple[float, float]] = None
+    if args.min_delay is not None or args.max_delay is not None:
+        if args.min_delay is None or args.max_delay is None:
+            raise SystemExit("Both --min-delay and --max-delay must be supplied together.")
+        sleep_range = (args.min_delay, args.max_delay)
+
+    extra_uas = _load_lines(args.ua_file)
+    identity_pool = _build_identity_pool(extra_uas)
+
+    auth_options = _build_auth_options_from_args(args)
+    session_id = auth_options.resolved_session_id()
+    client: Optional[object] = None
+
+    if args.mode == "network":
+        if not ZYTE_API_KEY:
+            raise SystemExit("ZYTE_API_KEY must be set for network mode.")
+        client = ZyteSessionClient(ZYTE_API_KEY, auth_options, render_mode=args.render, identity_pool=identity_pool, session_id=session_id)
+    elif args.mode == "direct":
+        proxy_url = None
+        if args.proxy_file:
+            proxies = _load_lines(args.proxy_file)
+            proxy_url = random.choice(proxies) if proxies else None
+        if not proxy_url:
+            proxy_url = args.proxy
+        proxy_pool = _load_lines(args.proxy_file) if args.proxy_file else ([args.proxy] if args.proxy else None)
+        client = DirectSessionClient(
+            auth_options,
+            identity_pool=identity_pool,
+            proxy_url=proxy_url,
+            session_id=session_id,
+            profile=args.profile,
+            proxy_pool=proxy_pool,
+        )
+
+    scraper = ListScraper(
+        cfg=cfg,
+        out_csv=output_path,
+        max_pages=args.max_pages,
+        page_sleep_range=sleep_range,
+        client=client,
+    )
+
+    if args.mode == "offline":
+        html_files = sorted(glob.glob(args.query))
+        scraper.crawl_offline_files(html_files)
+    else:
+        scraper.crawl(query=args.query)
+    if args.open_ui:
+        html_out = _render_ui_from_csv(output_path, title=f"{cfg.name} – {args.query}")
+        try:
+            webbrowser.open_new_tab(f"file://{os.path.abspath(html_out)}")
+        except Exception:
+            pass
+
