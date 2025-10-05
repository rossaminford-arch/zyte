# pip install requests beautifulsoup4 tenacity

import os
import csv
import time
import random
import re
import uuid
import hashlib
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin, urlencode, urlparse

import requests
from urllib.parse import urlsplit
from urllib import robotparser
from bs4 import BeautifulSoup
from bs4.element import Tag
from tenacity import retry, wait_exponential_jitter, stop_after_attempt


def _strip_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


ZYTE_API_KEY = os.getenv("ZYTE_API_KEY")
if not ZYTE_API_KEY:
    raise RuntimeError("ZYTE_API_KEY env var is not set. In PowerShell: $env:ZYTE_API_KEY='YOUR_KEY'")

ZYTE_ENDPOINT = "https://api.zyte.com/v1/extract"
PITCHBOOK_LOGIN_URL_DEFAULT = "https://pitchbook.com/account/login"


def _origin(url: Optional[str]) -> Optional[str]:
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _registrable_domain(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    parts = host.split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def _sec_fetch_site(target_url: Optional[str], referer: Optional[str]) -> str:
    if not referer:
        return "none"
    target = urlparse(target_url or "")
    ref = urlparse(referer)
    if not target.netloc or not ref.netloc:
        return "none"
    if target.netloc == ref.netloc:
        return "same-origin"
    if _registrable_domain(target.hostname) == _registrable_domain(ref.hostname):
        return "same-site"
    return "cross-site"


def _ensure_tuple(value: Optional[Iterable[str]]) -> Tuple[str, ...]:
    if value is None:
        return tuple()
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return (value,)


@dataclass(frozen=True)
class BrowserIdentity:
    label: str
    user_agent: str
    accept_language: str

    def document_headers(
        self,
        target_url: Optional[str],
        referer: Optional[str] = None,
        navigation: str = "navigate",
        dest: str = "document",
    ) -> Dict[str, str]:
        # Minimize synthetic, high-entropy headers to avoid mismatches
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": self.accept_language,
        }
        if referer:
            headers["Referer"] = referer
        return headers

    def form_headers(self, target_url: Optional[str], referer: Optional[str]) -> Dict[str, str]:
        headers = self.document_headers(target_url, referer)
        origin = _origin(target_url)
        if origin:
            headers["Origin"] = origin
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        return headers


IDENTITY_POOL: Tuple[BrowserIdentity, ...] = (
    BrowserIdentity(
        label="win-chrome-124",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        accept_language="en-US,en;q=0.9",
    ),
    BrowserIdentity(
        label="mac-chrome-123",
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        accept_language="en-US,en;q=0.9",
    ),
    BrowserIdentity(
        label="win-edge-124",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.67",
        accept_language="en-US,en;q=0.9",
    ),
)


def _resolve_identity(session_id: str, override_ua: Optional[str]) -> BrowserIdentity:
    if override_ua:
        return BrowserIdentity(
            label="custom",
            user_agent=override_ua,
            accept_language="en-US,en;q=0.9",
        )
    digest = hashlib.sha256(session_id.encode("utf-8")).digest()
    idx = digest[0] % len(IDENTITY_POOL)
    return IDENTITY_POOL[idx]


class AuthenticationError(RuntimeError):
    pass


class ChallengeError(RuntimeError):
    pass


class ThrottleError(RuntimeError):
    pass


@dataclass
class PageContent:
    url: str
    html: str
    soup: BeautifulSoup
    status: Optional[int] = None


@dataclass
class ListConfig:
    name: str
    base: str
    build_search_url: Callable[[str], str]
    row_selectors: Iterable[str]
    field_selectors: Dict[str, Iterable[str]]
    optional_fields: Dict[str, Iterable[str]] = field(default_factory=dict)
    next_selectors: Iterable[str] = field(default_factory=lambda: ("li.next a",))
    columns: List[str] = field(default_factory=list)
    max_pages: int = 50
    page_sleep_range: Tuple[float, float] = (6.0, 18.0)
    requires_login: bool = True
    empty_result_markers: Tuple[str, ...] = ("No results found", "Try adjusting your filters")

    def __post_init__(self) -> None:
        self.row_selectors = _ensure_tuple(self.row_selectors)
        self.next_selectors = _ensure_tuple(self.next_selectors)
        self.field_selectors = {key: _ensure_tuple(value) for key, value in self.field_selectors.items()}
        self.optional_fields = {key: _ensure_tuple(value) for key, value in self.optional_fields.items()}
        if not self.columns:
            ordered: List[str] = list(self.field_selectors.keys())
            for col in self.optional_fields.keys():
                if col not in ordered:
                    ordered.append(col)
            self.columns = ordered


@dataclass
class PitchbookAuthOptions:
    email: Optional[str] = None
    password: Optional[str] = None
    session_id: Optional[str] = None
    user_agent: Optional[str] = None
    login_url: Optional[str] = None
    login_form_selector: Optional[str] = None
    email_field: Optional[str] = None
    password_field: Optional[str] = None
    cookie_header: Optional[str] = None
    cookies_file: Optional[str] = None

    def __post_init__(self) -> None:
        self.email = _strip_or_none(self.email)
        self.password = _strip_or_none(self.password)
        self.session_id = _strip_or_none(self.session_id)
        self.user_agent = _strip_or_none(self.user_agent)
        self.login_url = _strip_or_none(self.login_url)
        self.login_form_selector = _strip_or_none(self.login_form_selector)
        self.email_field = _strip_or_none(self.email_field)
        self.password_field = _strip_or_none(self.password_field)
        self.cookie_header = _strip_or_none(self.cookie_header)
        self.cookies_file = _strip_or_none(self.cookies_file)

    def resolved_login_url(self) -> str:
        return self.login_url or PITCHBOOK_LOGIN_URL_DEFAULT

    def resolved_session_id(self) -> str:
        return self.session_id or f"pitchbook-{uuid.uuid4().hex}"

    def has_credentials(self) -> bool:
        return bool(self.email and self.password)


class AdaptiveThrottle:
    def __init__(self, base_range: Tuple[float, float]):
        self.base_low, self.base_high = base_range
        self.penalty = random.uniform(0.2, 1.0)

    def propose_delay(self, modifier: float = 0.0) -> float:
        # Heavy-tailed randomization with occasional longer pauses
        base = random.uniform(self.base_low, self.base_high) + modifier + self.penalty
        # Add a small lognormal jitter
        base += random.lognormvariate(0.0, 0.25) - 1.0
        # 5% chance to take a longer break
        if random.random() < 0.05:
            base += random.uniform(20.0, 75.0)
        return max(0.5, base)

    def record_success(self) -> None:
        if self.penalty > 0:
            self.penalty = max(0.0, self.penalty - random.uniform(0.1, 0.4))

    def record_penalty(self, severity: float = 1.5) -> None:
        self.penalty = min(18.0, self.penalty + severity)
class ZyteSessionClient:
    def __init__(self, api_key: str, auth: Optional[PitchbookAuthOptions] = None, render_mode: str = "auto"):
        self.api_key = api_key
        self.auth = auth or PitchbookAuthOptions()
        # Default to ephemeral sessions unless the user explicitly sets one
        self.session_id = self.auth.resolved_session_id()
        self.identity = _resolve_identity(self.session_id, self.auth.user_agent)
        self.login_url = self.auth.resolved_login_url()
        self._authenticated = False
        self._auth_failures = 0
        self._last_url: Optional[str] = None
        self._cookie_header: Optional[str] = self._load_cookie_header()
        self._render_mode: str = render_mode  # auto | browser | http
        self._cache: Dict[str, PageContent] = {}
        self._cache_order: List[str] = []
        self._cache_capacity: int = 32

    @retry(wait=wait_exponential_jitter(initial=1, max=12), stop=stop_after_attempt(5))
    def _request_zyte(self, payload: Dict) -> Dict:
        response = requests.post(
            ZYTE_ENDPOINT,
            auth=(self.api_key, ""),
            json=payload,
            timeout=70,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code == 400:
            try:
                print("Zyte 400:", response.json())
            except Exception:
                print("Zyte 400 raw:", response.text[:500])
        response.raise_for_status()
        return response.json()

    def _extract_status(self, data: Dict) -> Optional[int]:
        for key in ("statusCode", "httpResponseStatusCode", "httpResponseStatus"):
            value = data.get(key)
            if isinstance(value, int):
                return value
            try:
                return int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
        return None

    def _html_from(self, data: Dict) -> str:
        return data.get("browserHtml") or data.get("httpResponseBody") or ""

    def _classify_page(self, soup: BeautifulSoup) -> Optional[str]:
        if soup is None:
            return None
        # Minimal classification; avoid explicit fingerprints
        # Detect authentication prompts or JS verification pages
        text = soup.get_text(" ", strip=True).lower()
        text = text[:8000]
        if any(token in text for token in ("log in", "sign in", "login", "please sign in", "session expired")):
            return "login"
        text = soup.get_text(" ", strip=True).lower()
        text = text[:8000]
        if any(token in text for token in ("verify you are human", "captcha", "security check", "robot check", "please enable javascript")):
            return "challenge"
        if any(token in text for token in ("too many requests", "rate limit", "temporarily blocked", "unusual traffic", "request limit", "throttled", "quota exceeded")):
            return "throttle"
        return None

    def _load_cookie_header(self) -> Optional[str]:
        if self.auth.cookie_header:
            return self.auth.cookie_header
        # Simple Netscape cookie file support: use as-is if provided (user-managed)
        if self.auth.cookies_file and os.path.exists(self.auth.cookies_file):
            try:
                with open(self.auth.cookies_file, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()
                    if content:
                        return content
            except Exception:
                pass
        return None

    def _render_once(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
        request_payload = dict(payload)
        target_url = request_payload.get("url")
        # Lightweight GET cache keyed by URL when no body/method overrides are set
        if (
            not request_payload.get("httpRequestMethod")
            and not request_payload.get("httpRequestBody")
            and isinstance(target_url, str)
            and target_url in self._cache
        ):
            return self._cache[target_url]
        base_headers = self.identity.document_headers(target_url, referer)
        # Attach user-provided cookie header if available
        if self._cookie_header:
            base_headers["Cookie"] = self._cookie_header
        extra_headers = request_payload.get("httpRequestHeaders") or {}
        if extra_headers:
            base_headers.update(extra_headers)
        request_payload["httpRequestHeaders"] = base_headers
        session_spec = request_payload.setdefault("session", {})
        session_spec.setdefault("id", self.session_id)

        data = self._request_zyte(request_payload)
        html = self._html_from(data)
        soup = BeautifulSoup(html, "html.parser") if html else BeautifulSoup("", "html.parser")
        classification = self._classify_page(soup)
        if classification == "login" and not allow_login:
            self._authenticated = False
            raise AuthenticationError("Authentication required. Provide a valid cookie via --cookie-header or --cookies-file, or use --skip-login.")
        if classification == "challenge":
            self._authenticated = False
            raise ChallengeError("Access verification required.")
        if classification == "throttle":
            raise ThrottleError("Service reported temporary rate limits.")
        status_code = self._extract_status(data)
        page = PageContent(url=target_url, html=html, soup=soup, status=status_code)
        # Populate cache for plain GETs
        if (
            not request_payload.get("httpRequestMethod")
            and not request_payload.get("httpRequestBody")
            and isinstance(target_url, str)
        ):
            self._cache[target_url] = page
            self._cache_order.append(target_url)
            if len(self._cache_order) > self._cache_capacity:
                evict = self._cache_order.pop(0)
                self._cache.pop(evict, None)
        return page

    def _render(self, payload: Dict, *, allow_login: bool, referer: Optional[str]) -> PageContent:
        # Auto rendering: try HTTP body first, fall back to browser if needed
        mode = self._render_mode
        if mode == "browser":
            payload = dict(payload)
            payload["browserHtml"] = True
            return self._render_once(payload, allow_login=allow_login, referer=referer)
        if mode == "http":
            payload = dict(payload)
            payload.pop("browserHtml", None)
            return self._render_once(payload, allow_login=allow_login, referer=referer)
        # auto
        first_payload = dict(payload)
        first_payload.pop("browserHtml", None)
        try:
            result = self._render_once(first_payload, allow_login=allow_login, referer=referer)
        except (AuthenticationError, ChallengeError, ThrottleError):
            # Propagate auth/throttle decisions without switching rendering
            raise
        # If body seems empty or lacks any rows/links, retry with browser
        looks_empty = not result.html or len(result.html) < 512 or len(result.soup.get_text(" ", strip=True)) < 80
        if looks_empty:
            second_payload = dict(payload)
            second_payload["browserHtml"] = True
            return self._render_once(second_payload, allow_login=allow_login, referer=referer)
        return result

    def ensure_logged_in(self, require: bool = False) -> None:
        if not require:
            return
        if self._authenticated:
            return
        if not self._cookie_header:
            raise RuntimeError(
                "Authentication is required. Provide a cookie via --cookie-header or --cookies-file, or run with --skip-login."
            )
        # We assume the provided cookie is valid; any failure will be detected on first request
        self._authenticated = True

    # Form-based login removed to avoid mechanized credential submission flows

    def fetch_page(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> PageContent:
        if require_login:
            self.ensure_logged_in(require=True)
        effective_referer = referer or self._last_url
        page = self._render(
            {"url": url},
            allow_login=False,
            referer=effective_referer,
        )
        self._authenticated = True
        self._last_url = url
        return page

    def fetch_html(self, url: str, require_login: bool = False, referer: Optional[str] = None) -> str:
        return self.fetch_page(url, require_login=require_login, referer=referer).html
class ListScraper:
    def __init__(
        self,
        cfg: ListConfig,
        out_csv: str = "results.csv",
        max_pages: Optional[int] = None,
        page_sleep_range: Optional[Tuple[float, float]] = None,
        client: Optional[ZyteSessionClient] = None,
    ):
        self.cfg = cfg
        self.out_csv = out_csv
        self.max_pages = max_pages if max_pages is not None else cfg.max_pages
        if self.max_pages is not None and self.max_pages <= 0:
            raise ValueError("max_pages must be a positive integer")
        sleep_range = tuple(page_sleep_range or cfg.page_sleep_range)
        if len(sleep_range) != 2:
            raise ValueError("page_sleep_range must contain exactly two values")
        low, high = sleep_range
        if low < 0 or high < 0 or low > high:
            raise ValueError("page_sleep_range must be non-negative and increasing")
        self.page_sleep_range = (low, high)
        self.client = client or ZyteSessionClient(ZYTE_API_KEY)
        self.throttle = AdaptiveThrottle(self.page_sleep_range)
        self.max_empty_pages = 1

    def build_search_url(self, query: str) -> str:
        return self.cfg.build_search_url(query)

    def parse_rows(self, soup: BeautifulSoup, page_url: str) -> List[dict]:
        row_groups: List[Tag] = []
        for selector in self.cfg.row_selectors:
            row_groups = list(soup.select(selector))
            if row_groups:
                break
        if not row_groups:
            return []
        rows: List[dict] = []
        for row in row_groups:
            record: Dict[str, str] = {}
            for col, selectors in self.cfg.field_selectors.items():
                record[col] = self._extract_value(row, selectors, page_url)
            for col, selectors in self.cfg.optional_fields.items():
                value = self._extract_value(row, selectors, page_url)
                if value:
                    record[col] = value
            rows.append(record)
        return rows

    def _extract_value(self, row: Tag, selectors: Iterable[str], page_url: str) -> str:
        for sel in selectors:
            if not sel:
                continue
            el = row.select_one(sel)
            if not el:
                continue
            if el.name == "a" and el.get("href"):
                href = el.get("href")
                if href:
                    return urljoin(page_url, href.strip())
            text = el.get("title") or el.get_text(" ", strip=True)
            if text:
                return text
        return ""

    def _looks_like_empty_results(self, soup: BeautifulSoup) -> bool:
        text = soup.get_text(" ", strip=True).lower()
        for marker in self.cfg.empty_result_markers:
            if marker.lower() in text:
                return True
        return False

    def next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
        for selector in self.cfg.next_selectors:
            nxt = soup.select_one(selector)
            if nxt and nxt.get("href"):
                return urljoin(current_url, nxt["href"])
        return None

    def append_csv(self, batch: List[dict]) -> None:
        file_exists = os.path.exists(self.out_csv)
        with open(self.out_csv, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=self.cfg.columns)
            if not file_exists:
                writer.writeheader()
            for record in batch:
                writer.writerow({k: record.get(k, "") for k in self.cfg.columns})

    def _robots_allows(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
            robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
            rp = robotparser.RobotFileParser()
            rp.set_url(robots_url)
            rp.read()
            return rp.can_fetch(self.client.identity.user_agent, url)
        except Exception:
            # If robots cannot be fetched, err on the safe side by allowing
            return True

    def crawl(self, query: str) -> None:
        require_login = getattr(self.cfg, "requires_login", True)
        if require_login:
            self.client.ensure_logged_in(require=True)
        url = self.build_search_url(query)
        if not self._robots_allows(url):
            print(f"[{self.cfg.name}] robots.txt disallows this path for the configured User-Agent; exiting.")
            return
        total = 0
        pages = 0
        referer: Optional[str] = None
        consecutive_empty = 0
        initial_pause = random.uniform(2.0, 7.0)
        print(f"[{self.cfg.name}] Preparing... pausing {initial_pause:.2f}s before first request.")
        time.sleep(initial_pause)
        while url and (self.max_pages is None or pages < self.max_pages):
            page_attempt = 0
            while True:
                page_attempt += 1
                try:
                    page = self.client.fetch_page(url, require_login=require_login, referer=referer)
                    break
                except AuthenticationError as exc:
                    print(f"[{self.cfg.name}] Access requires authentication ({exc}).")
                    return
                except ThrottleError as exc:
                    penalty = 1.5 + page_attempt
                    self.throttle.record_penalty(severity=penalty)
                    wait_for = self.throttle.propose_delay(modifier=penalty)
                    print(f"[{self.cfg.name}] Temporarily unavailable; waiting {wait_for:.2f}s before retry.")
                    time.sleep(wait_for)
                    if page_attempt >= 4:
                        print(f"[{self.cfg.name}] Stopping after repeated temporary unavailability.")
                        return
                    continue
                except ChallengeError as exc:
                    print(f"[{self.cfg.name}] Access verification encountered; stopping.")
                    return
            soup = page.soup
            rows = self.parse_rows(soup, page.url)
            if not rows:
                referer = page.url
                consecutive_empty += 1
                if self._looks_like_empty_results(soup):
                    print(f"[{self.cfg.name}] Page {pages + 1}: no results visible. Stopping.")
                    break
                if consecutive_empty > self.max_empty_pages:
                    print(f"[{self.cfg.name}] Page {pages + 1}: no rows parsed on repeated attempts; stopping.")
                    break
                self.throttle.record_penalty(severity=2.5)
                wait_for = self.throttle.propose_delay(modifier=random.uniform(6.0, 12.0))
                print(f"[{self.cfg.name}] Page {pages + 1}: no rows parsed; waiting {wait_for:.2f}s before refetch.")
                time.sleep(wait_for)
                continue
            consecutive_empty = 0
            self.append_csv(rows)
            total += len(rows)
            pages += 1
            print(f"[{self.cfg.name}] Page {pages}: saved {len(rows)} rows (total={total}) -> {self.out_csv}")
            referer = page.url
            next_url = self.next_page(soup, page.url)
            if not next_url:
                break
            url = next_url
            wait_for = self.throttle.propose_delay()
            self.throttle.record_success()
            print(f"[{self.cfg.name}] Next request in {wait_for:.2f}s")
            time.sleep(wait_for)
        print(f"[{self.cfg.name}] Done. Pages: {pages}, Rows: {total}, File: {self.out_csv}")


def _pitchbook_search_url(entity: str, query: str, base: str) -> str:
    params = {"q": query, "entity": entity}
    return urljoin(base, f"profiles/search/?{urlencode(params)}")
def pitchbook_company_cfg() -> ListConfig:
    base = "https://pitchbook.com/"

    def build_url(query: str) -> str:
        return _pitchbook_search_url("company", query, base)

    columns = [
        "name",
        "headline",
        "location",
        "industries",
        "last_update",
        "profile_url",
        "website",
    ]

    return ListConfig(
        name="pitchbook_companies",
        base=base,
        build_search_url=build_url,
        row_selectors=(
            "div.search-results__result",
            "article.result-card",
            'div[data-qa="search-results__result"]',
        ),
        field_selectors={
            "name": (
                "a.result-card__title-link",
                "h3 a",
                'a[data-qa="result-card__title-link"]',
            ),
            "headline": (
                "div.result-card__description",
                "p.result-card__description",
                'div[data-qa="result-card__description"]',
            ),
            "location": (
                "span.result-card__location",
                "div.result-card__location",
                'span[data-qa="result-card__location"]',
            ),
            "industries": (
                "span.result-card__industries",
                "div.result-card__industries",
                'span[data-qa="result-card__industries"]',
            ),
            "last_update": (
                "span.result-card__last-update",
                "time.result-card__last-update",
                'span[data-qa="result-card__last-update"]',
            ),
            "profile_url": (
                "a.result-card__title-link",
                'a[data-qa="result-card__title-link"]',
            ),
        },
        optional_fields={
            "website": (
                "a.result-card__website",
                'a[data-qa="result-card__website"]',
            ),
        },
        next_selectors=(
            "a.pager__button--next",
            "li.next a",
            'a[data-qa="pager__next"]',
        ),
        columns=columns,
        max_pages=50,
        page_sleep_range=(6.0, 18.0),
        empty_result_markers=(
            "No companies found",
            "We couldn't find any results",
            "Try adjusting your filters",
        ),
    )


def pitchbook_people_cfg() -> ListConfig:
    base = "https://pitchbook.com/"

    def build_url(query: str) -> str:
        return _pitchbook_search_url("person", query, base)

    columns = [
        "name",
        "title",
        "affiliation",
        "location",
        "last_update",
        "profile_url",
        "linkedin",
    ]

    return ListConfig(
        name="pitchbook_people",
        base=base,
        build_search_url=build_url,
        row_selectors=(
            "div.search-results__result",
            "article.result-card",
            'div[data-qa="search-results__result"]',
        ),
        field_selectors={
            "name": (
                "a.result-card__title-link",
                "h3 a",
                'a[data-qa="result-card__title-link"]',
            ),
            "title": (
                "span.result-card__subtitle",
                "div.result-card__subtitle",
                'span[data-qa="result-card__subtitle"]',
            ),
            "affiliation": (
                "span.result-card__affiliation",
                "div.result-card__affiliation",
                'span[data-qa="result-card__affiliation"]',
            ),
            "location": (
                "span.result-card__location",
                "div.result-card__location",
                'span[data-qa="result-card__location"]',
            ),
            "last_update": (
                "span.result-card__last-update",
                "time.result-card__last-update",
                'span[data-qa="result-card__last-update"]',
            ),
            "profile_url": (
                "a.result-card__title-link",
                'a[data-qa="result-card__title-link"]',
            ),
        },
        optional_fields={
            "linkedin": (
                "a.result-card__linkedin",
                'a[href*="linkedin.com"]',
                'a[data-qa="result-card__linkedin"]',
            ),
        },
        next_selectors=(
            "a.pager__button--next",
            "li.next a",
            'a[data-qa="pager__next"]',
        ),
        columns=columns,
        max_pages=50,
        page_sleep_range=(6.0, 18.0),
        empty_result_markers=(
            "No people found",
            "Try adjusting your filters",
            "We couldn't find any results",
        ),
    )


def pitchbook_investor_cfg() -> ListConfig:
    base = "https://pitchbook.com/"

    def build_url(query: str) -> str:
        return _pitchbook_search_url("investor", query, base)

    columns = [
        "name",
        "investor_type",
        "focus",
        "location",
        "last_update",
        "profile_url",
        "website",
    ]

    return ListConfig(
        name="pitchbook_investors",
        base=base,
        build_search_url=build_url,
        row_selectors=(
            "div.search-results__result",
            "article.result-card",
            'div[data-qa="search-results__result"]',
        ),
        field_selectors={
            "name": (
                "a.result-card__title-link",
                "h3 a",
                'a[data-qa="result-card__title-link"]',
            ),
            "investor_type": (
                "span.result-card__subtitle",
                "div.result-card__subtitle",
                'span[data-qa="result-card__subtitle"]',
            ),
            "focus": (
                "span.result-card__focus",
                "div.result-card__focus",
                'span[data-qa="result-card__focus"]',
            ),
            "location": (
                "span.result-card__location",
                "div.result-card__location",
                'span[data-qa="result-card__location"]',
            ),
            "last_update": (
                "span.result-card__last-update",
                "time.result-card__last-update",
                'span[data-qa="result-card__last-update"]',
            ),
            "profile_url": (
                "a.result-card__title-link",
                'a[data-qa="result-card__title-link"]',
            ),
        },
        optional_fields={
            "website": (
                "a.result-card__website",
                'a[data-qa="result-card__website"]',
            ),
        },
        next_selectors=(
            "a.pager__button--next",
            "li.next a",
            'a[data-qa="pager__next"]',
        ),
        columns=columns,
        max_pages=50,
        page_sleep_range=(6.0, 18.0),
        empty_result_markers=(
            "No investors found",
            "We couldn't find any results",
            "Try adjusting your filters",
        ),
    )
def _default_output_name(entity: str, query: str) -> str:
    safe_query = re.sub(r"[^A-Za-z0-9._-]+", "_", query.strip()) or "query"
    return f"pitchbook_{entity}_{safe_query}.csv"


def _build_auth_options_from_args(args) -> PitchbookAuthOptions:
    return PitchbookAuthOptions(
        email=None,  # mechanized login removed
        password=None,
        session_id=os.getenv("ZYTE_SESSION_ID"),
        user_agent=args.user_agent or os.getenv("PITCHBOOK_USER_AGENT"),
        login_url=args.login_url or os.getenv("PITCHBOOK_LOGIN_URL"),
        login_form_selector=None,
        email_field=None,
        password_field=None,
        cookie_header=args.cookie_header or os.getenv("PITCHBOOK_COOKIE"),
        cookies_file=args.cookies_file or os.getenv("PITCHBOOK_COOKIES_FILE"),
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scrape PitchBook search results with Zyte (reduced automation cues)")
    parser.add_argument(
        "entity",
        choices=["companies", "people", "investors"],
        help="Which PitchBook directory to crawl",
    )
    parser.add_argument("query", help="Search query to run on PitchBook")
    parser.add_argument("--output", "-o", help="Output CSV path")
    parser.add_argument(
        "--max-pages",
        type=int,
        help="Maximum number of result pages to crawl (defaults to the entity configuration)",
    )
    parser.add_argument(
        "--min-delay",
        type=float,
        help="Minimum pause in seconds between page requests",
    )
    parser.add_argument(
        "--max-delay",
        type=float,
        help="Maximum pause in seconds between page requests",
    )
    # Authentication: accept a cookie header instead of mechanized login
    parser.add_argument("--cookie-header", help="Cookie header string to authenticate to PitchBook")
    parser.add_argument("--cookies-file", help="Path to file containing a Cookie header")
    parser.add_argument(
        "--user-agent",
        help="Override the browser user-agent; defaults to a rotating profile",
    )
    parser.add_argument("--login-url", help="Override the login form URL")
    # Rendering mode
    parser.add_argument("--render", choices=["auto", "browser", "http"], default="auto", help="Rendering mode: auto (default), browser, or http")
    parser.add_argument(
        "--skip-login",
        action="store_true",
        help="Skip login even if the selected directory normally requires it",
    )
    args = parser.parse_args()

    cfg_factory = {
        "companies": pitchbook_company_cfg,
        "people": pitchbook_people_cfg,
        "investors": pitchbook_investor_cfg,
    }

    cfg = cfg_factory[args.entity]()
    if args.skip_login:
        cfg.requires_login = False

    output_path = args.output or _default_output_name(args.entity, args.query)

    sleep_range: Optional[Tuple[float, float]] = None
    if args.min_delay is not None or args.max_delay is not None:
        if args.min_delay is None or args.max_delay is None:
            raise SystemExit("Both --min-delay and --max-delay must be supplied together.")
        sleep_range = (args.min_delay, args.max_delay)

    auth_options = _build_auth_options_from_args(args)
    client = ZyteSessionClient(ZYTE_API_KEY, auth_options, render_mode=args.render)

    scraper = ListScraper(
        cfg=cfg,
        out_csv=output_path,
        max_pages=args.max_pages,
        page_sleep_range=sleep_range,
        client=client,
    )
    scraper.crawl(query=args.query)

