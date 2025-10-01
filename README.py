
-# zyte

+# PitchBook list scraper via Zyte
+

+This project turns Zyte's smart browser into a high-volume scraper for PitchBook search
+results. After you run a search inside PitchBook (companies, people, or investors), paste
+the resulting URL into the tool to export every page of the table into a CSV file.
+

+## Prerequisites
+

+* Python 3.9+

+*
A [Zyte API key](https://docs.zyte.com/zyte-api/get-started.html) with browser access.
+* `pip install requests beautifulsoup4 tenacity python-dateutil`
+

+Set the API key in your shell before running the scraper:
+

+```bash
+export ZYTE_API_KEY="your-key-here"
+```

+
+## Usage
+

+```
+python zytepitchbook.py LIST_TYPE [--start-url URL | --query QUERY]
+```

+
+* `LIST_TYPE` – one of `companies`, `people`, or `investors`.
+* `--start-url` – the full PitchBook results URL (recommended: copy/paste from the address
+  bar after searching).
+  
+* `--query` – if you prefer to let the script build the first page URL. PitchBook changes
   
+  its patterns frequently, so this is best-effort and `--start-url` is safer.
+  
+* `--out` – path to the CSV file (default: `pitchbook_results.csv`).
   
+* `--max-pages` – stop after this many result pages.
   
+* `--sleep-range MIN MAX` – override the per-page random delay to modulate crawl speed.

+
+Example (start from an existing search URL):

+
+```bash
+python zytepitchbook.py companies --start-url "https://pitchbook.com/search/companies?q=climate" --out climate.csv
+```
+
+The scraper will iterate through the "next" pagination button (ARIA label or classic link),

+append rows to the CSV, and sleep a random amount between page requests to reduce the risk of

+detection.

+
+## Output columns

+
+### Companies

+* `company_name`
+* `profile_url`
+* `primary_industry`
+* `headquarters`
+* `description`
+* `last_financing`
+* `status`
+* `employees`
+* `last_funding_date` *(optional, present when visible)*

+
+### People

+* `person_name`
+* `profile_url`
+* `title`
+* `primary_organization`
+* `location`
+* `last_activity`
+* `phone` *(optional)*
+* `email` *(optional)*
+
+### Investors
+* `investor_name`
+* `profile_url`
+* `investor_type`
+* `location`
+* `description`
+* `investment_count`
+* `exit_count`
+* `assets_under_management` *(optional)*
+
+Customize selectors by editing `pitchbook_*_cfg()` inside `zytepitchbook.py` if PitchBook
+adjusts its DOM.
