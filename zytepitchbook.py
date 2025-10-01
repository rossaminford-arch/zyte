
# pip install requests beautifulsoup4 tenacity

import os
import csv
import time
import random
import re
import uuid
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlencode

import requests
from bs4 import BeautifulSoup
from bs4.element import Tag
from tenacity import retry, wait_exponential_jitter, stop_after_attempt


def _strip_or_none(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    value = value.strip()
    return value or None


# ---------- ENV & ENDPOINT ----------
ZYTE_API_KEY = os.getenv("ZYTE_API_KEY")
if not ZYTE_API_KEY:
    raise RuntimeError("ZYTE_API_KEY env var is not set. In PowerShell: $env:ZYTE_API_KEY='YOUR_KEY'")

ZYTE_ENDPOINT = "https://api.zyte.com/v1/extract"
PITCHBOOK_LOGIN_URL_DEFAULT = "https://pitchbook.com/account/login"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
)


# ---------- GENERIC CONFIG ----------
@dataclass
class ListConfig:
    name: str
    base: str
    build_search_url: Callable[[str], str]
    row_selector: str
    field_selectors: Dict[str, str]
    optional_fields: Dict[str, str] = field(default_factory=dict)
    next_selector: str = "li.next a"
    columns: List[str] = field(default_factory=list)
    max_pages: int = 500
    page_sleep_range: Tuple[float, float] = (0.6, 2.0)
    requires_login: bool = True


@dataclass
class PitchbookAuthOptions:
    email: Optional[str] = None
    password: Optional[str] = None
    cookie: Optional[str] = None
    session_id: Optional[str] = None
    user_agent: Optional[str] = None
    login_url: Optional[str] = None
    login_form_selector: Optional[str] = None
    email_field: Optional[str] = None
    password_field: Optional[str] = None

    def __post_init__(self) -> None:
        self.email = _strip_or_none(self.email)
        self.password = _strip_or_none(self.password)
        self.cookie = _strip_or_none(self.cookie)
        self.session_id = _strip_or_none(self.session_id)
        self.user_agent = _strip_or_none(self.user_agent)
        self.login_url = _strip_or_none(self.login_url)
        self.login_form_selector = _strip_or_none(self.login_form_selector)
        self.email_field = _strip_or_none(self.email_field)
        self.password_field = _strip_or_none(self.password_field)

    def resolved_login_url(self) -> str:
        return self.login_url or PITCHBOOK_LOGIN_URL_DEFAULT

    def resolved_user_agent(self) -> str:
        return self.user_agent or DEFAULT_USER_AGENT

    def has_credentials(self) -> bool:
        return bool(self.email and self.password)


class ZyteSessionClient:
    def __init__(self, api_key: str, auth: Optional[PitchbookAuthOptions] = None):
        self.api_key = api_key
        self.auth = auth or PitchbookAuthOptions()
        self.session_id = self.auth.session_id or f"pitchbook-{uuid.uuid4().hex}"
        self.user_agent = self.auth.resolved_user_agent()
        self.cookie = self.auth.cookie
        self.login_url = self.auth.resolved_login_url()
        self._authenticated = bool(self.cookie)
        self._login_attempted = False

    def ensure_logged_in(self, require: bool = False) -> None:
        if self._authenticated:
            return
        if self.cookie:
            self._authenticated = True
            return
        if self._login_attempted:
            if require:
                raise RuntimeError("PitchBook authentication failed in a previous attempt.")
            return
        self._login_attempted = True
        if self.auth.has_credentials():
            self._login_with_form()
            self._authenticated = True
            return
        if require:
            raise RuntimeError(
                "PitchBook authentication required but no credentials or cookie provided. "
                "Set PITCHBOOK_COOKIE or provide --pitchbook-email/--pitchbook-password."
            )

    def _login_with_form(self) -> None:
        if not self.auth.has_credentials():
            raise RuntimeError("PitchBook credentials are required for login.")

        session = requests.Session()
        session.headers.update({"User-Agent": self.user_agent})

        response = session.get(self.login_url, timeout=40)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        form: Optional[Tag] = None
        if self.auth.login_form_selector:
            form = soup.select_one(self.auth.login_form_selector)
        if form is None:
            form = soup.find("form")
        if form is None:
            raise RuntimeError("Could not locate login form on PitchBook login page.")

        action_attr = form.get("action") or response.url
        action_url = urljoin(response.url, action_attr)
        method = (form.get("method") or "post").lower()

        payload: Dict[str, str] = {}
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if not name:
                continue
            value = input_tag.get("value", "")
            payload[name] = value

        email_field = self.auth.email_field or self._guess_input_name(form, ["email", "username", "user"], "email")
        password_field = self.auth.password_field or self._guess_input_name(form, ["password", "pass"], "password")

        if not email_field or not password_field:
            raise RuntimeError("Unable to infer email/password fields on PitchBook login form.")

        payload[email_field] = self.auth.email or ""
        payload[password_field] = self.auth.password or ""

        request_kwargs = {"allow_redirects": True, "timeout": 40, "headers": {"Referer": response.url}}
        if method == "get":
            login_response = session.get(action_url, params=payload, **request_kwargs)
        else:
            login_response = session.post(action_url, data=payload, **request_kwargs)

        if login_response.status_code >= 400:
            raise RuntimeError(
                f"PitchBook login failed (status {login_response.status_code}). "
                "Verify your credentials."
            )

        if not session.cookies:
            raise RuntimeError(
                "PitchBook login did not yield cookies; authentication may have failed or additional steps are required."
            )

        cookie_pairs = []
        for cookie in session.cookies:
            if cookie.value:
                cookie_pairs.append(f"{cookie.name}={cookie.value}")
        if not cookie_pairs:
            raise RuntimeError("PitchBook login returned cookies without usable values.")
        self.cookie = "; ".join(cookie_pairs)
        self._authenticated = True

    def _guess_input_name(self, form: Tag, keywords: List[str], input_type: Optional[str]) -> Optional[str]:
        if input_type:
            input_tag = form.find("input", {"type": input_type})
            if input_tag and input_tag.get("name"):
                return input_tag["name"]
        for keyword in keywords:
            input_tag = form.find("input", {"name": keyword})
            if input_tag:
                return keyword
        for input_tag in form.find_all("input"):
            name = input_tag.get("name")
            if not name:
                continue
            lower_name = name.lower()
            if any(keyword in lower_name for keyword in keywords):
                return name
        return None

    @retry(wait=wait_exponential_jitter(initial=1, max=10), stop=stop_after_attempt(5))
    def _post(self, payload: Dict) -> Dict:
        request_payload = dict(payload)
        session_spec = request_payload.setdefault("session", {})
        session_spec.setdefault("id", self.session_id)

        headers = request_payload.setdefault("httpRequestHeaders", {})
        headers.setdefault("User-Agent", self.user_agent)
        if self.cookie:
            headers["Cookie"] = self.cookie

        response = requests.post(
            ZYTE_ENDPOINT,
            auth=(self.api_key, ""),
            json=request_payload,
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

    def fetch_html(self, url: str, require_login: bool = False) -> str:
        if require_login:
            self.ensure_logged_in(require=True)
        data = self._post({"url": url, "browserHtml": True})
        html = data.get("browserHtml") or data.get("httpResponseBody") or ""
        if not html:
            raise RuntimeError(f"Zyte returned no HTML for {url}")
        return html


# ---------- CORE SCRAPER ----------
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

    def build_search_url(self, query: str) -> str:
        return self.cfg.build_search_url(query)

    def parse_rows(self, soup: BeautifulSoup, page_url: str) -> List[dict]:
        rows = []
        for row in soup.select(self.cfg.row_selector):
            record = {}
            for col, sel in self.cfg.field_selectors.items():
                el = row.select_one(sel)
                if el is None:
                    record[col] = ""
                elif el.name == "a" and el.get("href"):
                    record[col] = urljoin(page_url, el.get("href"))
                else:
                    record[col] = el.get("title") or el.get_text(strip=True)
            for col, sel in self.cfg.optional_fields.items():
                el = row.select_one(sel)
                record[col] = (
                    urljoin(page_url, el.get("href"))
                    if el and el.name == "a" and el.get("href")
                    else (
                        el.get("title")
                        if el and el.get("title")
                        else (el.get_text(strip=True) if el else "")
                    )
                )
            rows.append(record)
        return rows

    def next_page(self, soup: BeautifulSoup, current_url: str) -> Optional[str]:
        nxt = soup.select_one(self.cfg.next_selector)
        return urljoin(current_url, nxt.get("href")) if nxt else None

    def append_csv(self, batch: List[dict]):
        file_exists = os.path.exists(self.out_csv)
        with open(self.out_csv, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=self.cfg.columns)
            if not file_exists:
                w.writeheader()
            for r in batch:
                w.writerow({k: r.get(k, "") for k in self.cfg.columns})

    def crawl(self, query: str):
        require_login = getattr(self.cfg, "requires_login", True)
        if require_login:
            self.client.ensure_logged_in(require=True)
        url = self.build_search_url(query)
        total = 0
        pages = 0
        while url and (self.max_pages is None or pages < self.max_pages):
            if require_login:
                self.client.ensure_logged_in(require=True)
            html = self.client.fetch_html(url)
            soup = BeautifulSoup(html, "html.parser")
            batch = self.parse_rows(soup, url)
            if not batch:
                print(f"[{self.cfg.name}] No rows at {url}; stopping.")
                break
            self.append_csv(batch)
            total += len(batch)
            pages += 1
            print(f"[{self.cfg.name}] Page {pages}: saved {len(batch)} rows (total={total}) -> {self.out_csv}")
            next_url = self.next_page(soup, url)
            if not next_url:
                break
            url = next_url
            time.sleep(random.uniform(*self.page_sleep_range))
        print(f"[{self.cfg.name}] Done. Pages: {pages}, Rows: {total}, File: {self.out_csv}")


# ---------- PITCHBOOK CONFIGS ----------

def _pitchbook_search_url(entity: str, query: str, base: str) -> str:
    params = {"q": query, "entity": entity}
    return urljoin(base, f"profiles/search/?{urlencode(params)}")


def pitchbook_company_cfg() -> ListConfig:
    """Build a configuration for the PitchBook company search results."""

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
        row_selector='div[data-qa="search-results__result"]',
        field_selectors={
            "name": 'a[data-qa="result-card__title-link"]',
            "headline": 'div[data-qa="result-card__description"]',
            "location": 'span[data-qa="result-card__location"]',
            "industries": 'span[data-qa="result-card__industries"]',
            "last_update": 'span[data-qa="result-card__last-update"]',
            "profile_url": 'a[data-qa="result-card__title-link"]',
        },
        optional_fields={
            "website": 'a[data-qa="result-card__website"]',
        },
        columns=columns,
        next_selector='a[data-qa="pager__next"]',
        max_pages=500,
        page_sleep_range=(1.5, 3.5),
    )


def pitchbook_people_cfg() -> ListConfig:
    """Configuration for the PitchBook people directory search results."""

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
        row_selector='div[data-qa="search-results__result"]',
        field_selectors={
            "name": 'a[data-qa="result-card__title-link"]',
            "title": 'span[data-qa="result-card__subtitle"]',
            "affiliation": 'span[data-qa="result-card__affiliation"]',
            "location": 'span[data-qa="result-card__location"]',
            "last_update": 'span[data-qa="result-card__last-update"]',
            "profile_url": 'a[data-qa="result-card__title-link"]',
        },
        optional_fields={
            "linkedin": 'a[data-qa="result-card__linkedin"]',
        },
        columns=columns,
        next_selector='a[data-qa="pager__next"]',
        max_pages=500,
        page_sleep_range=(1.5, 3.5),
    )


def pitchbook_investor_cfg() -> ListConfig:
    """Configuration for the PitchBook investor search results."""

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
        row_selector='div[data-qa="search-results__result"]',
        field_selectors={
            "name": 'a[data-qa="result-card__title-link"]',
            "investor_type": 'span[data-qa="result-card__subtitle"]',
            "focus": 'span[data-qa="result-card__focus"]',
            "location": 'span[data-qa="result-card__location"]',
            "last_update": 'span[data-qa="result-card__last-update"]',
            "profile_url": 'a[data-qa="result-card__title-link"]',
        },
        optional_fields={
            "website": 'a[data-qa="result-card__website"]',
        },
        columns=columns,
        next_selector='a[data-qa="pager__next"]',
        max_pages=500,
        page_sleep_range=(1.5, 3.5),
    )


def _default_output_name(entity: str, query: str) -> str:
    safe_query = re.sub(r"[^A-Za-z0-9._-]+", "_", query.strip()) or "query"
    return f"pitchbook_{entity}_{safe_query}.csv"


def _build_auth_options_from_args(args) -> PitchbookAuthOptions:
    return PitchbookAuthOptions(
        email=args.pitchbook_email or os.getenv("PITCHBOOK_EMAIL"),
        password=args.pitchbook_password or os.getenv("PITCHBOOK_PASSWORD"),
        cookie=args.pitchbook_cookie or os.getenv("PITCHBOOK_COOKIE"),
        session_id=args.zyte_session_id or os.getenv("ZYTE_SESSION_ID"),
        user_agent=args.user_agent or os.getenv("PITCHBOOK_USER_AGENT"),
        login_url=args.login_url or os.getenv("PITCHBOOK_LOGIN_URL"),
        login_form_selector=args.login_form_selector or os.getenv("PITCHBOOK_LOGIN_FORM_SELECTOR"),
        email_field=args.pitchbook_email_field or os.getenv("PITCHBOOK_EMAIL_FIELD"),
        password_field=args.pitchbook_password_field or os.getenv("PITCHBOOK_PASSWORD_FIELD"),
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Scrape PitchBook search results with Zyte")
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
    parser.add_argument("--pitchbook-email", help="PitchBook email/username for login")
    parser.add_argument("--pitchbook-password", help="PitchBook password for login")
    parser.add_argument(
        "--pitchbook-cookie",
        help="Pre-authenticated Cookie header to reuse instead of logging in",
    )
    parser.add_argument(
        "--zyte-session-id",
        help="Sticky Zyte session identifier to persist login across runs",
    )
    parser.add_argument("--user-agent", help="Override the browser user-agent sent to PitchBook")
    parser.add_argument("--login-url", help="Override the login form URL")
    parser.add_argument(
        "--login-form-selector",
        help="CSS selector for the login form if it cannot be auto-detected",
    )
    parser.add_argument(
        "--pitchbook-email-field",
        help="Explicit login form field name for the email/username",
    )
    parser.add_argument(
        "--pitchbook-password-field",
        help="Explicit login form field name for the password",
    )
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
    client = ZyteSessionClient(ZYTE_API_KEY, auth_options)

    scraper = ListScraper(
        cfg=cfg,
        out_csv=output_path,
        max_pages=args.max_pages,
        page_sleep_range=sleep_range,
        client=client,
    )
    scraper.crawl(query=args.query)

