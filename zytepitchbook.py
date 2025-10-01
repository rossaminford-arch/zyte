# pip install requests beautifulsoup4 pandas tenacity python-dateutil

import os, csv, time, random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
from urllib.parse import urljoin, urlencode
import requests
from bs4 import BeautifulSoup
from tenacity import retry, wait_exponential_jitter, stop_after_attempt

# ---------- ENV & ENDPOINT ----------
ZYTE_API_KEY = os.getenv("ZYTE_API_KEY")
if not ZYTE_API_KEY:
    raise RuntimeError("ZYTE_API_KEY env var is not set. In PowerShell: $env:ZYTE_API_KEY='YOUR_KEY'")

ZYTE_ENDPOINT = "https://api.zyte.com/v1/extract"


# ---------- GENERIC CONFIG ----------
@dataclass
class ListConfig:
    name: str
    base: str
    # Build the first URL from a search query
    build_search_url: Callable[[str], str]
    # CSS selectors for parsing a page of rows
    row_selector: str
    field_selectors: Dict[str, str]              # column -> CSS (scoped inside each row)
    optional_fields: Dict[str, str] = field(default_factory=dict)  # optional column -> CSS
    # How to get the next page
    next_selector: str = "li.next a"
    # Columns to write, in order
    columns: List[str] = field(default_factory=list)
    # Safety cap
    max_pages: int = 500
    # polite pause
    page_sleep_range: tuple = (0.6, 2.0)


# ---------- ZYTE FETCH ----------
@retry(wait=wait_exponential_jitter(initial=1, max=10), stop=stop_after_attempt(5))
def fetch_html(url: str) -> str:
    payload = {
        "url": url,
        "browserHtml": True,  # ask Zyte to return the rendered DOM
    }
    r = requests.post(
        ZYTE_ENDPOINT,
        auth=(ZYTE_API_KEY, ""),
        json=payload,
        timeout=70,
        headers={"Content-Type": "application/json"},
    )
    if r.status_code == 400:
        try:
            print("Zyte 400:", r.json())
        except Exception:
            print("Zyte 400 raw:", r.text[:500])
    r.raise_for_status()
    data = r.json()
    html = data.get("browserHtml") or data.get("httpResponseBody") or ""
    if not html:
        raise RuntimeError("Zyte returned no HTML. Check payload/plan.")
    return html


# ---------- CORE SCRAPER ----------
class ListScraper:
    def __init__(self, cfg: ListConfig, out_csv: str = "results.csv"):
        self.cfg = cfg
        self.out_csv = out_csv

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
                    # normalize absolute URLs
                    record[col] = urljoin(page_url, el.get("href"))
                else:
                    record[col] = el.get("title") or el.get_text(strip=True)
            for col, sel in self.cfg.optional_fields.items():
                el = row.select_one(sel)
                record[col] = (urljoin(page_url, el.get("href")) if el and el.name == "a" and el.get("href")
                               else (el.get("title") if el and el.get("title")
                                     else (el.get_text(strip=True) if el else "")))
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
        url = self.build_search_url(query)
        total = 0
        pages = 0
        while url and pages < self.cfg.max_pages:
            html = fetch_html(url)
            soup = BeautifulSoup(html, "html.parser")
            batch = self.parse_rows(soup, url)
            if not batch:
                print(f"[{self.cfg.name}] No rows at {url} — stopping.")
                break
            self.append_csv(batch)
            total += len(batch)
            pages += 1
            print(f"[{self.cfg.name}] Page {pages}: saved {len(batch)} rows (total={total}) → {self.out_csv}")
            url = self.next_page(soup, url)
            time.sleep(random.uniform(*self.cfg.page_sleep_range))
        print(f"[{self.cfg.name}] Done. Pages: {pages}, Rows: {total}, File: {self.out_csv}")


# ---------- EXAMPLE: BooksToScrape ----------
def books_cfg() -> ListConfig:
    base = "https://books.toscrape.com/"

    def build_url(_query: str) -> str:
        # site has no search; start at catalog page 1
        return urljoin(base, "catalogue/page-1.html")

    cols = ["title", "price", "availability", "rating", "product_url", "image_url"]

    return ListConfig(
        name="books",
        base=base,
        build_search_url=build_url,
        row_selector="article.product_pod",
        field_selectors={
            "title": "h3 a",
            "price": "p.price_color",
            "availability": "p.instock.availability",
            "rating": "p.star-rating",      # will give class names; simple display
            "product_url": "h3 a",
            "image_url": "img",
        },
        columns=cols,
        next_selector="li.next a",
        max_pages=500,
        page_sleep_range=(0.6, 1.2),
    )


# ---------- HOW TO ADD OTHER LISTS ----------
# For your company/people/investor lists, make a new config with:
# - row_selector pointing to each card/row
# - field_selectors mapping your CSV columns to CSS inside each row
# - build_search_url that builds the first list page based on the search term
#
# Example skeleton (fill selectors for your target site):
def company_cfg() -> ListConfig:
    base = "https://example.com/"
    def build_url(query: str) -> str:
        return base + "search?" + urlencode({"q": query, "type": "company"})
    cols = ["name", "industry", "location", "profile_url"]
    return ListConfig(
        name="companies",
        base=base,
        build_search_url=build_url,
        row_selector="div.company-card",                     # <-- change
        field_selectors={
            "name": "h3 a",
            "industry": ".meta .industry",
            "location": ".meta .location",
            "profile_url": "h3 a",
        },
        columns=cols,
        next_selector="a.next",                              # <-- change
        max_pages=500,
    )


if __name__ == "__main__":
    # Choose a config and run. For books, query is ignored (site has no search).
    scraper = ListScraper(cfg=books_cfg(), out_csv="books_results.csv")
    scraper.crawl(query="anything")
