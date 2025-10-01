diff --git a/zytepitchbook.py b/zytepitchbook.py
index 55bae6b6e07bb3a5d16a9c857fc28dd5f6334c23..52c697c5650390e008c9f027b24beaa76bb0ca6e 100644
--- a/zytepitchbook.py
+++ b/zytepitchbook.py
@@ -1,192 +1,327 @@
-# pip install requests beautifulsoup4 pandas tenacity python-dateutil
+# pip install requests beautifulsoup4 tenacity python-dateutil
 
-import os, csv, time, random
+import argparse
+import os
+import csv
+import time
+import random
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
-    # Build the first URL from a search query
-    build_search_url: Callable[[str], str]
+    # Build the first URL from a search query (optional when a full URL is supplied)
+    build_search_url: Optional[Callable[[str], str]] = None
     # CSS selectors for parsing a page of rows
-    row_selector: str
-    field_selectors: Dict[str, str]              # column -> CSS (scoped inside each row)
+    row_selector: str = ""
+    field_selectors: Dict[str, str] = field(default_factory=dict)  # column -> CSS (scoped inside each row)
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
+        if not self.cfg.build_search_url:
+            raise ValueError("This configuration does not define a search URL builder. Provide --start-url instead of --query.")
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
 
-    def crawl(self, query: str):
-        url = self.build_search_url(query)
+    def crawl(self, query: Optional[str] = None, start_url: Optional[str] = None):
+        if start_url:
+            url = start_url
+        elif query is not None:
+            url = self.build_search_url(query)
+        else:
+            raise ValueError("Either query or start_url must be provided.")
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
 
 
-# ---------- EXAMPLE: BooksToScrape ----------
-def books_cfg() -> ListConfig:
-    base = "https://books.toscrape.com/"
+def _pitchbook_search_url(base: str, list_path: str, query: str) -> str:
+    params = {"q": query}
+    return urljoin(base, f"search/{list_path}?" + urlencode(params))
 
-    def build_url(_query: str) -> str:
-        # site has no search; start at catalog page 1
-        return urljoin(base, "catalogue/page-1.html")
 
-    cols = ["title", "price", "availability", "rating", "product_url", "image_url"]
+def pitchbook_company_cfg() -> ListConfig:
+    base = "https://pitchbook.com/"
+    cols = [
+        "company_name",
+        "profile_url",
+        "primary_industry",
+        "headquarters",
+        "description",
+        "last_financing",
+        "status",
+        "employees",
+    ]
+    return ListConfig(
+        name="pitchbook_companies",
+        base=base,
+        build_search_url=lambda query: _pitchbook_search_url(base, "companies", query),
+        row_selector="table tbody tr",
+        field_selectors={
+            "company_name": "td:nth-of-type(1) a",
+            "profile_url": "td:nth-of-type(1) a",
+            "primary_industry": "td:nth-of-type(2)",
+            "headquarters": "td:nth-of-type(3)",
+            "description": "td:nth-of-type(4)",
+            "last_financing": "td:nth-of-type(5)",
+            "status": "td:nth-of-type(6)",
+            "employees": "td:nth-of-type(7)",
+        },
+        optional_fields={
+            "last_funding_date": "td:nth-of-type(8)",
+        },
+        columns=cols + ["last_funding_date"],
+        next_selector="[aria-label='Next page'], li.next a",
+        max_pages=500,
+        page_sleep_range=(1.2, 3.0),
+    )
 
+
+def pitchbook_people_cfg() -> ListConfig:
+    base = "https://pitchbook.com/"
+    cols = [
+        "person_name",
+        "profile_url",
+        "title",
+        "primary_organization",
+        "location",
+        "last_activity",
+    ]
     return ListConfig(
-        name="books",
+        name="pitchbook_people",
         base=base,
-        build_search_url=build_url,
-        row_selector="article.product_pod",
+        build_search_url=lambda query: _pitchbook_search_url(base, "people", query),
+        row_selector="table tbody tr",
         field_selectors={
-            "title": "h3 a",
-            "price": "p.price_color",
-            "availability": "p.instock.availability",
-            "rating": "p.star-rating",      # will give class names; simple display
-            "product_url": "h3 a",
-            "image_url": "img",
+            "person_name": "td:nth-of-type(1) a",
+            "profile_url": "td:nth-of-type(1) a",
+            "title": "td:nth-of-type(2)",
+            "primary_organization": "td:nth-of-type(3)",
+            "location": "td:nth-of-type(4)",
+            "last_activity": "td:nth-of-type(5)",
+        },
+        optional_fields={
+            "phone": "td:nth-of-type(6)",
+            "email": "td:nth-of-type(7) a",
         },
-        columns=cols,
-        next_selector="li.next a",
+        columns=cols + ["phone", "email"],
+        next_selector="[aria-label='Next page'], li.next a",
         max_pages=500,
-        page_sleep_range=(0.6, 1.2),
+        page_sleep_range=(1.2, 3.0),
     )
 
 
-# ---------- HOW TO ADD OTHER LISTS ----------
-# For your company/people/investor lists, make a new config with:
-# - row_selector pointing to each card/row
-# - field_selectors mapping your CSV columns to CSS inside each row
-# - build_search_url that builds the first list page based on the search term
-#
-# Example skeleton (fill selectors for your target site):
-def company_cfg() -> ListConfig:
-    base = "https://example.com/"
-    def build_url(query: str) -> str:
-        return base + "search?" + urlencode({"q": query, "type": "company"})
-    cols = ["name", "industry", "location", "profile_url"]
+def pitchbook_investor_cfg() -> ListConfig:
+    base = "https://pitchbook.com/"
+    cols = [
+        "investor_name",
+        "profile_url",
+        "investor_type",
+        "location",
+        "description",
+        "investment_count",
+        "exit_count",
+    ]
     return ListConfig(
-        name="companies",
+        name="pitchbook_investors",
         base=base,
-        build_search_url=build_url,
-        row_selector="div.company-card",                     # <-- change
+        build_search_url=lambda query: _pitchbook_search_url(base, "investors", query),
+        row_selector="table tbody tr",
         field_selectors={
-            "name": "h3 a",
-            "industry": ".meta .industry",
-            "location": ".meta .location",
-            "profile_url": "h3 a",
+            "investor_name": "td:nth-of-type(1) a",
+            "profile_url": "td:nth-of-type(1) a",
+            "investor_type": "td:nth-of-type(2)",
+            "location": "td:nth-of-type(3)",
+            "description": "td:nth-of-type(4)",
+            "investment_count": "td:nth-of-type(5)",
+            "exit_count": "td:nth-of-type(6)",
         },
-        columns=cols,
-        next_selector="a.next",                              # <-- change
+        optional_fields={
+            "assets_under_management": "td:nth-of-type(7)",
+        },
+        columns=cols + ["assets_under_management"],
+        next_selector="[aria-label='Next page'], li.next a",
         max_pages=500,
+        page_sleep_range=(1.2, 3.0),
     )
 
 
+def available_configs() -> Dict[str, Callable[[], ListConfig]]:
+    return {
+        "companies": pitchbook_company_cfg,
+        "people": pitchbook_people_cfg,
+        "investors": pitchbook_investor_cfg,
+    }
+
+
+def parse_args() -> argparse.Namespace:
+    parser = argparse.ArgumentParser(
+        description=(
+            "Scrape PitchBook search results for companies, people, or investors "
+            "using Zyte's smart proxy browser."
+        )
+    )
+    parser.add_argument(
+        "list_type",
+        choices=sorted(available_configs().keys()),
+        help="PitchBook list to scrape (companies, people, investors)",
+    )
+    parser.add_argument(
+        "--query",
+        help=(
+            "Search keyword to use when building the first page URL. "
+            "Skip this if you already have a PitchBook search results URL."
+        ),
+    )
+    parser.add_argument(
+        "--start-url",
+        help=(
+            "Full PitchBook results URL to start crawling from (paste the URL after running a search). "
+            "Overrides --query."
+        ),
+    )
+    parser.add_argument(
+        "--out",
+        default="pitchbook_results.csv",
+        help="CSV file to write results into (default: pitchbook_results.csv)",
+    )
+    parser.add_argument(
+        "--max-pages",
+        type=int,
+        help="Stop after visiting this many pages (default is config specific)",
+    )
+    parser.add_argument(
+        "--sleep-range",
+        nargs=2,
+        type=float,
+        metavar=("MIN", "MAX"),
+        help="Override the per-page sleep range in seconds (e.g. --sleep-range 1.5 4.0)",
+    )
+    return parser.parse_args()
+
+
+def main():
+    args = parse_args()
+    cfg_factory = available_configs()[args.list_type]
+    cfg = cfg_factory()
+    if args.max_pages is not None:
+        cfg.max_pages = args.max_pages
+    if args.sleep_range is not None:
+        lo, hi = args.sleep_range
+        if lo <= 0 or hi <= 0 or hi < lo:
+            raise ValueError("Sleep range values must be positive and MAX >= MIN")
+        cfg.page_sleep_range = (lo, hi)
+
+    scraper = ListScraper(cfg=cfg, out_csv=args.out)
+
+    if not args.start_url and not args.query:
+        raise SystemExit("Provide either --start-url or --query so we know where to start.")
+
+    scraper.crawl(query=args.query, start_url=args.start_url)
+
+
 if __name__ == "__main__":
-    # Choose a config and run. For books, query is ignored (site has no search).
-    scraper = ListScraper(cfg=books_cfg(), out_csv="books_results.csv")
-    scraper.crawl(query="anything")
+    main()
