import os
import re
import json
import time
import logging
from typing import List, Dict, Tuple, Optional
from urllib.parse import urljoin, urlparse
from io import StringIO
from datetime import datetime, timedelta, timezone
import hashlib
import certifi
from pymongo import MongoClient

import requests
from bs4 import BeautifulSoup
import pandas as pd
# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is required")
MONGO_CLIENT = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME") or "saham_db"
MONGO_DB = MONGO_CLIENT[MONGO_DB_NAME]
MONGO_PRICES = MONGO_DB["prices"]
LOGIN_POST = "https://mtp.signalsaham.com/index.php"
FUNDAMENTAL_URL = "https://mtp.signalsaham.com/fundamental.php"

LOGIN_URL = "https://mtp.signalsaham.com/"
HOME_URL = "https://mtp.signalsaham.com/home.php"


class SignalSahamScraper:
    def __init__(self, use_selenium: bool = False, headless: bool = True):
        self.session = requests.Session()
        self.base_url = "https://mtp.signalsaham.com/"
        self.login_url = LOGIN_URL
        self.home_url = HOME_URL
        self.timeout = 60
        self.max_retries = 5
        self.use_selenium = use_selenium
        self.headless = headless
        self.driver = None
        self.cred_email = None
        self.cred_password = None
        self.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
            "Referer": self.login_url,
            "Connection": "keep-alive",
        }
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

    def _get(self, url: str) -> requests.Response:
        return self.session.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=True)

    def _post(self, url: str, data: Dict[str, str]) -> requests.Response:
        h = dict(self.headers)
        h["Origin"] = self.base_url.rstrip("/")
        h["Content-Type"] = "application/x-www-form-urlencoded"
        return self.session.post(url, headers=h, data=data, timeout=self.timeout, allow_redirects=True)

    def login_fixed(self, username: str, password: str) -> bool:
        payload = {"username": username, "password": password}
        delay = 1
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._post(LOGIN_POST, payload)
                home = self._get(self.home_url)
                body = home.text.lower()
                if ("logout" in body or "keluar" in body or "dashboard" in body) and home.status_code == 200:
                    print("✔ Login success")
                    return True
                logging.warning("Login fixed attempt %d failed; status=%s", attempt, resp.status_code)
            except Exception as e:
                logging.warning("Login fixed error attempt %d: %s", attempt, str(e))
            time.sleep(delay)
            delay = min(delay * 2, 16)
        print("❌ Login failed")
        return False

    def fetch_fundamental(self) -> Optional[str]:
        r = self._get(FUNDAMENTAL_URL)
        return r.text if r.status_code == 200 else None

    def submit_fundamental_form(self) -> Optional[str]:
        data = {
            "minValue": "0",
            "minDeviden": "0",
            "maxPbv": "-",
            "maxPer": "-",
            "minNet": "0",
            "cari": "Ubah Settingan",
        }
        h = dict(self.headers)
        h["Origin"] = "https://mtp.signalsaham.com"
        h["Referer"] = FUNDAMENTAL_URL
        h["Content-Type"] = "application/x-www-form-urlencoded"
        r = self.session.post(FUNDAMENTAL_URL, headers=h, data=data, timeout=self.timeout, allow_redirects=True)
        if r.status_code == 200:
            print("✔ Form submitted")
            return r.text
        return None

    def parse_fundamental_table(self, html: str) -> pd.DataFrame:
        soup = BeautifulSoup(html, "html.parser")
        table = soup.find("table", id="fundamentalTable")
        if not table:
            table = None
        for t in soup.find_all("table"):
            cls = " ".join((t.get("class") or [])).lower()
            idv = (t.get("id") or "").lower()
            if "datatable" in cls or "datatables" in cls or "datatable" in idv or "data" in idv:
                table = t
                break
        if table is None:
            tables = soup.find_all("table")
            table = tables[0] if tables else None
        if table is None:
            return pd.DataFrame()
        headers = []
        thead = table.find("thead")
        if thead:
            ths = thead.find_all(["th", "td"])
            headers = [th.get_text(strip=True) for th in ths]
        headers = list(headers)
        headers.extend(["stock_name", "stock_code"])
        tbody = table.find("tbody") or table
        rows = []
        for tr in tbody.find_all("tr"):
            cells = tr.find_all(["td", "th"])
            row = [c.get_text(strip=True) for c in cells]
            stock_name = ""
            stock_code = ""
            a = tr.find("a", href=True)
            if a and "stock_price.php" in a.get("href"):
                stock_name = a.get_text(strip=True)
                href = a.get("href")
                m = re.search(r"[?&]s=([^&#]+)", href)
                if m:
                    stock_code = m.group(1)
            row.extend([stock_name, stock_code])
            if row:
                rows.append(row)
        if not headers and rows:
            headers = [f"col_{i}" for i in range(len(rows[0]))]
        try:
            df = pd.DataFrame(rows, columns=headers if headers and len(headers) == len(rows[0]) else None)
        except Exception:
            df = pd.DataFrame(rows)
        return df

    def detect_login_requirements(self) -> Tuple[str, Dict[str, str], Dict[str, str]]:
        r = self._get(self.login_url)
        soup = BeautifulSoup(r.text, "html.parser")
        form = soup.find("form")
        if not form:
            raise RuntimeError("Login form not found")
        action = form.get("action") or self.login_url
        action_url = urljoin(self.login_url, action)
        inputs = {}
        tokens = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            value = inp.get("value") or ""
            inputs[name] = value
            t = (inp.get("type") or "").lower()
            if t == "hidden" or "csrf" in name.lower() or "token" in name.lower():
                tokens[name] = value
        logging.info("Detected form action: %s", action_url)
        logging.info("Detected input fields: %s", ", ".join(inputs.keys()))
        logging.info("Detected hidden tokens: %s", ", ".join(tokens.keys()) or "none")
        return action_url, inputs, tokens

    def _guess_field(self, inputs: Dict[str, str], keywords: List[str]) -> Optional[str]:
        for k in inputs.keys():
            kl = k.lower()
            for kw in keywords:
                if kw in kl:
                    return k
        return None

    def _has_captcha(self, html: str) -> bool:
        s = html.lower()
        if "captcha" in s or "g-recaptcha" in s or "recaptcha" in s:
            return True
        return False

    def _is_logged_in(self, response: requests.Response) -> bool:
        if response.url.startswith(self.home_url):
            return True
        h = response.text
        if "Logout" in h or "Keluar" in h or "Dashboard" in h or "home.php" in h:
            return True
        return False

    def login(self, email: str, password: str) -> bool:
        if self.use_selenium:
            return self._login_selenium(email, password)
        delay = 1
        for attempt in range(1, self.max_retries + 1):
            try:
                action_url, inputs, tokens = self.detect_login_requirements()
                email_field = self._guess_field(inputs, ["email", "user", "username"])
                password_field = self._guess_field(inputs, ["pass", "password"])
                payload = dict(tokens)
                if email_field:
                    payload[email_field] = email
                else:
                    payload["email"] = email
                if password_field:
                    payload[password_field] = password
                else:
                    payload["password"] = password
                for k, v in inputs.items():
                    if k not in payload:
                        payload[k] = v
                logging.info("Submitting login attempt %d", attempt)
                resp = self._post(action_url, payload)
                if self._has_captcha(resp.text):
                    logging.warning("Captcha detected; consider enabling Selenium mode")
                if self._is_logged_in(resp):
                    logging.info("Login successful")
                    return True
                logging.warning("Login failed; status=%s url=%s", resp.status_code, resp.url)
            except Exception as e:
                logging.warning("Login error: %s", str(e))
            time.sleep(delay)
            delay = min(delay * 2, 16)
        return False

    def _login_selenium(self, email: str, password: str) -> bool:
        try:
            from selenium import webdriver
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.chrome.options import Options
        except Exception:
            logging.error("Selenium not available")
            return False
        opts = Options()
        if self.headless:
            opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        try:
            driver.get(self.login_url)
            wait = WebDriverWait(driver, 20)
            email_field = None
            password_field = None
            try:
                email_field = wait.until(EC.presence_of_element_located((By.NAME, "username")))
            except Exception:
                try:
                    email_field = wait.until(EC.presence_of_element_located((By.NAME, "email")))
                except Exception:
                    pass
            try:
                password_field = wait.until(EC.presence_of_element_located((By.NAME, "password")))
            except Exception:
                pass
            if not email_field:
                try:
                    email_field = driver.find_element(By.XPATH, "//input[contains(@type,'text') or contains(@type,'email')]")
                except Exception:
                    pass
            if not password_field:
                try:
                    password_field = driver.find_element(By.XPATH, "//input[contains(@type,'password')]")
                except Exception:
                    pass
            if not email_field or not password_field:
                logging.error("Login fields not found")
                driver.quit()
                return False
            email_field.clear()
            email_field.send_keys(email)
            password_field.clear()
            password_field.send_keys(password)
            try:
                btn = driver.find_element(By.XPATH, "//button|//input[@type='submit']")
                btn.click()
            except Exception:
                logging.error("Login submit button not found")
                driver.quit()
                return False
            wait.until(lambda d: d.current_url.startswith(self.home_url) or "home.php" in d.page_source)
            cookies = driver.get_cookies()
            for c in cookies:
                self.session.cookies.set(c.get("name"), c.get("value"), domain=c.get("domain"), path=c.get("path"))
            logging.info("Login successful via Selenium")
            driver.quit()
            return True
        except Exception as e:
            logging.error("Selenium login error: %s", str(e))
            try:
                driver.quit()
            except Exception:
                pass
            return False

    def fetch_fundamental_selenium(self) -> Optional[str]:
        if not self.use_selenium:
            return None
        try:
            from selenium import webdriver
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.common.by import By
            from selenium.webdriver.chrome.options import Options
        except Exception:
            return None
        opts = Options()
        if self.headless:
            opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        try:
            driver.get(self.base_url)
            for c in self.session.cookies:
                try:
                    driver.add_cookie({
                        "name": c.name,
                        "value": c.value,
                        "path": c.path,
                        "domain": c.domain or "mtp.signalsaham.com",
                    })
                except Exception:
                    pass
            driver.get(FUNDAMENTAL_URL)
            wait = WebDriverWait(driver, 15)
            try:
                wait.until(EC.presence_of_element_located((By.ID, "fundamentalTable")))
            except Exception:
                try:
                    wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".dataTables_wrapper")))
                except Exception:
                    pass
            import time as _t
            _t.sleep(2)
            return driver.page_source
        except Exception:
            return None
        finally:
            try:
                driver.quit()
            except Exception:
                pass

    def fetch_stock_price_selenium(self, symbol: str) -> Optional[str]:
        if not self.use_selenium:
            return None
        try:
            from selenium import webdriver
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
            from selenium.webdriver.common.by import By
            from selenium.webdriver.chrome.options import Options
        except Exception:
            return None
        opts = Options()
        if self.headless:
            opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=opts)
        try:
            driver.get(self.base_url)
            target = f"https://mtp.signalsaham.com/stock_price.php?s={symbol}"
            try:
                driver.get(target)
            except Exception:
                pass
            current = driver.current_url
            if "index.php" in current or "login" in current.lower():
                try:
                    wait = WebDriverWait(driver, 20)
                    u = wait.until(EC.presence_of_element_located((By.NAME, "username")))
                except Exception:
                    try:
                        u = driver.find_element(By.NAME, "email")
                    except Exception:
                        u = None
                try:
                    p = driver.find_element(By.NAME, "password")
                except Exception:
                    p = None
                if u and p and getattr(self, "cred_email", None) and getattr(self, "cred_password", None):
                    u.clear(); u.send_keys(self.cred_email)
                    p.clear(); p.send_keys(self.cred_password)
                    try:
                        btn = driver.find_element(By.XPATH, "//button|//input[@type='submit']")
                        btn.click()
                    except Exception:
                        pass
                    WebDriverWait(driver, 20).until(lambda d: "home.php" in d.current_url or "home.php" in d.page_source)
                    driver.get(target)
            wait = WebDriverWait(driver, 20)
            try:
                wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, "table tbody tr")) > 0 or len(d.find_elements(By.XPATH, "//table//tr")) > 10)
            except Exception:
                pass
            import time as _t
            _t.sleep(2)
            return driver.page_source
        except Exception:
            return None
        finally:
            try:
                driver.quit()
            except Exception:
                pass
    def discover_data_endpoints(self, html: str) -> List[str]:
        urls = []
        for m in re.findall(r"https?://[^\'\"\s)]+", html):
            ml = m.lower()
            if any(x in ml for x in ["api", "ajax", "data", "json"]) and urlparse(m).netloc in urlparse(self.base_url).netloc:
                urls.append(m)
        for m in re.findall(r"['\"](\/[^'\"]+|[A-Za-z0-9_\/.\-]+\.php[^'\"]*)['\"]", html):
            ml = m.lower()
            if any(x in ml for x in ["api", "ajax", "data", "json", ".php"]):
                urls.append(urljoin(self.base_url, m))
        return list(dict.fromkeys(urls))

    def fetch_page_tables(self, url: str) -> List[Tuple[str, str, pd.DataFrame]]:
        r = self._get(url)
        soup = BeautifulSoup(r.text, "html.parser")
        out = []
        idx = 0
        for t in soup.find_all("table"):
            try:
                df = self._table_to_dataframe(t)
                if df is not None and not df.empty:
                    out.append((url, t.get("id") or f"table_{idx}", df))
                idx += 1
            except Exception:
                pass
        return out

    def find_pagination_links(self, html: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a"):
            txt = (a.get_text() or "").strip().lower()
            if re.search(r"(next|berikutnya|>>|>)", txt):
                href = a.get("href")
                if href:
                    links.append(urljoin(self.base_url, href))
        return list(dict.fromkeys(links))

    def _table_to_dataframe(self, table_tag) -> Optional[pd.DataFrame]:
        headers = []
        thead = table_tag.find("thead")
        if thead:
            ths = thead.find_all(["th", "td"])
            headers = [th.get_text(strip=True) for th in ths]
        tbody = table_tag.find("tbody") or table_tag
        rows = []
        for tr in tbody.find_all("tr"):
            cells = tr.find_all(["td", "th"])
            row = [c.get_text(strip=True) for c in cells]
            if row:
                rows.append(row)
        if not headers and rows:
            headers = [f"col_{i}" for i in range(len(rows[0]))]
        if rows:
            try:
                df = pd.DataFrame(rows, columns=headers if len(headers) == len(rows[0]) else None)
            except Exception:
                df = pd.DataFrame(rows)
            return df
        return None

    def fetch_data(self) -> List[Tuple[str, str, pd.DataFrame]]:
        queue = [self.home_url]
        seen = set()
        all_tables = []
        depth = {self.home_url: 0}
        while queue:
            u = queue.pop(0)
            if u in seen:
                continue
            seen.add(u)
            try:
                r = self._get(u)
            except Exception as e:
                logging.warning("Fetch error: %s", str(e))
                continue
            tables = self.fetch_page_tables(u)
            all_tables.extend(tables)
            logging.info("Page %s: tables=%d", u, len(tables))
            for nxt in self.find_pagination_links(r.text):
                if nxt not in seen:
                    queue.append(nxt)
                    depth[nxt] = depth.get(u, 0) + 1
            for nxt in self.discover_internal_links(r.text):
                if nxt not in seen and depth.get(u, 0) < 2:
                    queue.append(nxt)
                    depth[nxt] = depth.get(u, 0) + 1
            eps = self.discover_data_endpoints(r.text)
            logging.info("Page %s: endpoints=%d", u, len(eps))
            for ep in eps:
                try:
                    j = self._fetch_json(ep, referer=u)
                    if j is not None:
                        rows = None
                        if isinstance(j, dict):
                            for k in ["data", "rows", "result"]:
                                if k in j and isinstance(j[k], list):
                                    rows = j[k]
                                    break
                        elif isinstance(j, list):
                            rows = j
                        if rows:
                            df = pd.DataFrame(rows)
                            all_tables.append((ep, "api", df))
                except Exception:
                    pass
        return all_tables

    def discover_internal_links(self, html: str) -> List[str]:
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for a in soup.find_all("a"):
            href = a.get("href")
            if not href:
                continue
            if any(x in href.lower() for x in ["logout", "keluar", "index.php", "login"]):
                continue
            full = urljoin(self.base_url, href)
            if urlparse(full).netloc == urlparse(self.base_url).netloc:
                links.append(full)
        return list(dict.fromkeys(links))

    def _fetch_json(self, url: str, referer: Optional[str] = None) -> Optional[object]:
        try:
            h = dict(self.headers)
            if referer:
                h["Referer"] = referer
            r = self.session.get(url, headers=h, timeout=self.timeout)
            ct = r.headers.get("Content-Type", "")
            t = r.text.strip()
            if "application/json" in ct or t.startswith("{") or t.startswith("["):
                return r.json()
            r2 = self.session.post(url, headers=h, data={}, timeout=self.timeout)
            ct2 = r2.headers.get("Content-Type", "")
            t2 = r2.text.strip()
            if "application/json" in ct2 or t2.startswith("{") or t2.startswith("["):
                return r2.json()
        except Exception:
            return None
        return None

    def parse_data(self, items: List[Tuple[str, str, pd.DataFrame]]) -> pd.DataFrame:
        dfs = []
        for (src, tid, df) in items:
            df = df.copy()
            df["source_url"] = src
            df["table_id"] = tid
            dfs.append(df)
        if not dfs:
            return pd.DataFrame()
        return pd.concat(dfs, ignore_index=True, sort=False)

    def save_to_file(self, df: pd.DataFrame, json_path: str = "data.json", csv_path: str = "data.csv") -> None:
        if df.empty:
            logging.warning("No data to save")
            return
        df.to_csv(csv_path, index=False, encoding="utf-8")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json.loads(df.to_json(orient="records")), f, ensure_ascii=False, indent=2)
        logging.info("Saved CSV to %s", csv_path)
        logging.info("Saved JSON to %s", json_path)

    def _fingerprint_path(self, symbol: str) -> str:
        outdir = os.path.join("data", "stock_price", symbol)
        os.makedirs(outdir, exist_ok=True)
        return os.path.join(outdir, ".fingerprint")

    def _compute_fingerprint(self, df: pd.DataFrame) -> str:
        try:
            cols = [c for c in ["Date", "Open", "High", "Low", "Close", "Volume", "Value", "symbol"] if c in df.columns]
            use = df[cols].copy() if cols else df.copy()
        except Exception:
            use = df.copy()
        try:
            if "Date" in use.columns:
                use["Date_parsed"] = pd.to_datetime(use["Date"], errors="coerce")
                use = use.sort_values(by=["Date_parsed", "Date"], ascending=[False, False])
                use = use.drop(columns=["Date_parsed"])
        except Exception:
            pass
        try:
            limited = use.head(200)
        except Exception:
            limited = use
        try:
            payload = json.dumps(json.loads(limited.to_json(orient="records")), ensure_ascii=False, separators=(",", ":"))
        except Exception:
            payload = str(limited.values.tolist())
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _load_fingerprint(self, symbol: str) -> Optional[str]:
        p = self._fingerprint_path(symbol)
        try:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    t = f.read().strip()
                    return t or None
        except Exception:
            return None
        return None

    def _save_fingerprint(self, symbol: str, fp: str) -> None:
        p = self._fingerprint_path(symbol)
        try:
            with open(p, "w", encoding="utf-8") as f:
                f.write(fp)
        except Exception:
            pass

    def start_driver(self):
        if not self.use_selenium:
            return None
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
        except Exception:
            return None
        opts = Options()
        if self.headless:
            opts.add_argument("--headless")
        opts.add_argument("--no-sandbox")
        opts.add_argument("--disable-gpu")
        opts.add_argument("--disable-dev-shm-usage")
        self.driver = webdriver.Chrome(options=opts)
        try:
            self.driver.get(self.base_url)
            for c in self.session.cookies:
                try:
                    self.driver.add_cookie({
                        "name": c.name,
                        "value": c.value,
                        "path": c.path,
                        "domain": c.domain or "mtp.signalsaham.com",
                    })
                except Exception:
                    pass
        except Exception:
            pass
        return self.driver

    def close_driver(self):
        try:
            if self.driver:
                self.driver.quit()
        except Exception:
            pass
        self.driver = None

    def restart_driver_and_login(self) -> bool:
        try:
            self.close_driver()
        except Exception:
            pass
        drv = self.start_driver()
        if not drv:
            return False
        try:
            self.driver.get(self.home_url)
        except Exception:
            pass
        return self.login_with_driver()

    def login_with_driver(self) -> bool:
        if not self.driver:
            return False
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
        except Exception:
            return False
        self.driver.get(self.login_url)
        wait = WebDriverWait(self.driver, 20)
        try:
            if self.driver.current_url.startswith(self.home_url) or "home.php" in self.driver.page_source or "Logout" in self.driver.page_source:
                return True
        except Exception:
            pass
        u = None
        p = None
        try:
            u = wait.until(EC.presence_of_element_located((By.NAME, "username")))
        except Exception:
            try:
                u = self.driver.find_element(By.NAME, "email")
            except Exception:
                u = None
        try:
            p = self.driver.find_element(By.NAME, "password")
        except Exception:
            p = None
        if not u or not p:
            return False
        u.clear(); u.send_keys(self.cred_email or "")
        p.clear(); p.send_keys(self.cred_password or "")
        try:
            btn = self.driver.find_element(By.XPATH, "//button|//input[@type='submit']")
            btn.click()
        except Exception:
            return False
        try:
            wait.until(lambda d: d.current_url.startswith(self.home_url) or "home.php" in d.page_source)
            return True
        except Exception:
            return False

    def scrape_symbol_with_driver(self, symbol: str, refresh_retry: bool = False) -> Optional[pd.DataFrame]:
        if not self.driver:
            return None
        try:
            from selenium.webdriver.common.by import By
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC
        except Exception:
            return None
        url = f"https://mtp.signalsaham.com/stock_price.php?s={symbol}"
        self.driver.get(url)
        try:
            cur = self.driver.current_url
            if "index.php" in cur or "login" in cur.lower():
                wait = WebDriverWait(self.driver, 20)
                u = None
                try:
                    u = wait.until(EC.presence_of_element_located((By.NAME, "username")))
                except Exception:
                    try:
                        u = self.driver.find_element(By.NAME, "email")
                    except Exception:
                        u = None
                try:
                    p = self.driver.find_element(By.NAME, "password")
                except Exception:
                    p = None
                if u and p and self.cred_email and self.cred_password:
                    u.clear(); u.send_keys(self.cred_email)
                    p.clear(); p.send_keys(self.cred_password)
                    try:
                        btn = self.driver.find_element(By.XPATH, "//button|//input[@type='submit']")
                        btn.click()
                    except Exception:
                        pass
                    WebDriverWait(self.driver, 20).until(lambda d: "home.php" in d.current_url or "home.php" in d.page_source)
                    self.driver.get(url)
        except Exception:
            pass
        wait = WebDriverWait(self.driver, 25)
        ok = False
        try:
            ok = wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, "table tbody tr")) > 0 or len(d.find_elements(By.XPATH, "//table//tr")) > 10)
        except Exception:
            ok = False
        if not ok and refresh_retry:
            try:
                self.driver.refresh()
                ok = wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, "table tbody tr")) > 0 or len(d.find_elements(By.XPATH, "//table//tr")) > 10)
            except Exception:
                ok = False
        html = self.driver.page_source
        dfs = []
        try:
            for df in pd.read_html(StringIO(html)):
                dfs.append(df)
        except Exception:
            pass
        if not dfs:
            soup = BeautifulSoup(html, "html.parser")
            for t in soup.find_all("table"):
                df = self._table_to_dataframe(t)
                if df is not None and not df.empty:
                    dfs.append(df)
        key_cols = ["Date", "Open", "High", "Low", "Close", "Volume", "Value"]
        chosen = None
        for df in dfs:
            cols = [str(c) for c in list(df.columns)]
            if all(any(k.lower() in str(c).lower() for c in cols) for k in key_cols):
                chosen = df
                break
        if chosen is None and dfs:
            chosen = max(dfs, key=lambda x: len(x))
        if chosen is None:
            return pd.DataFrame()
        chosen["symbol"] = symbol
        return chosen

    def scrape_symbol_via_requests(self, symbol: str) -> pd.DataFrame:
        url = f"https://mtp.signalsaham.com/stock_price.php?s={symbol}"
        try:
            r = self._get(url)
        except Exception:
            return pd.DataFrame()
        html = r.text
        dfs = []
        try:
            for df in pd.read_html(StringIO(html)):
                dfs.append(df)
        except Exception:
            pass
        if not dfs:
            soup = BeautifulSoup(html, "html.parser")
            for t in soup.find_all("table"):
                df = self._table_to_dataframe(t)
                if df is not None and not df.empty:
                    dfs.append(df)
        if not dfs:
            endpoints = self.discover_data_endpoints(html)
            for u in endpoints:
                obj = self._fetch_json(u, referer=url)
                if obj is None:
                    continue
                try:
                    if isinstance(obj, list):
                        dfj = pd.DataFrame(obj)
                    elif isinstance(obj, dict):
                        if isinstance(obj.get("data"), list):
                            dfj = pd.DataFrame(obj.get("data"))
                        elif isinstance(obj.get("rows"), list):
                            dfj = pd.DataFrame(obj.get("rows"))
                        else:
                            dfj = pd.DataFrame([obj])
                    else:
                        dfj = pd.DataFrame()
                except Exception:
                    dfj = pd.DataFrame()
                if dfj is not None and not dfj.empty:
                    dfs.append(dfj)
        key_cols = ["Date", "Open", "High", "Low", "Close", "Volume", "Value"]
        chosen = None
        for df in dfs:
            cols = [str(c) for c in list(df.columns)]
            if all(any(k.lower() in str(c).lower() for c in cols) for k in key_cols):
                chosen = df
                break
        if chosen is None and dfs:
            chosen = max(dfs, key=lambda x: len(x))
        if chosen is None:
            return pd.DataFrame()
        chosen["symbol"] = symbol
        return chosen

    def _write_symbol_data(self, symbol: str, df: pd.DataFrame, update_mode: str = "snapshot") -> None:
        if df is None or (hasattr(df, "empty") and df.empty):
            print(f"❌ {symbol} tidak ada data")
            return
        final_df = df.copy()
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            records = json.loads(final_df.to_json(orient="records"))
        except Exception:
            records = []
        date_col = None
        try:
            for c in list(final_df.columns):
                s = str(c).lower().strip()
                if ("date" in s) or ("tanggal" in s) or ("tgl" in s):
                    date_col = c
                    break
            if date_col is None:
                for c in list(final_df.columns):
                    try:
                        ser = pd.to_datetime(final_df[c], errors="coerce", dayfirst=True)
                        if int(ser.notna().sum()) > 0:
                            date_col = c
                            break
                    except Exception:
                        pass
        except Exception:
            date_col = None
        inserted = 0
        for rec in records:
            try:
                d = rec.get("Date") or rec.get("Tanggal") or rec.get("tgl") or rec.get("col_1") or (rec.get(date_col) if date_col else "")
                if not d:
                    continue
                rec["symbol"] = symbol
                rec["scraped_at_utc"] = now_utc
                MONGO_PRICES.update_one({"symbol": symbol, "Date": d}, {"$set": rec}, upsert=True)
                inserted += 1
            except Exception as e:
                print(f"❌ {symbol} upsert error: {e}")
                continue
        print(f"✔ {symbol} → upserted={inserted}")

    def scrape_symbols_from_file(self, file_path: str, limit: Optional[int] = None, skip_existing: bool = False, rate_limit_ms: int = 0, refresh_retry: bool = False, update_mode: str = "snapshot") -> Tuple[int, int]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = [ln.strip() for ln in f.readlines() if ln.strip()]
        except Exception:
            return 0, 0
        print(f"Loaded lines: {len(lines)}")
        symbols = []
        for ln in lines:
            m = re.search(r"[?&]s=([A-Za-z0-9]+)", ln)
            if m:
                symbols.append(m.group(1).upper())
        symbols = list(dict.fromkeys(symbols))
        if skip_existing:
            filtered = []
            for s in symbols:
                outdir = os.path.join("data", "stock_price", s)
                j = os.path.join(outdir, f"{s}.json")
                if os.path.exists(j):
                    continue
                filtered.append(s)
            symbols = filtered
        if limit is not None:
            try:
                limit = int(limit)
            except Exception:
                limit = None
            if limit is not None and limit > 0:
                symbols = symbols[:limit]
        print(f"Parsed symbols: {len(symbols)}")
        os.makedirs("data/stock_price", exist_ok=True)
        use_driver = True
        drv = self.start_driver()
        if not drv:
            use_driver = False
        else:
            try:
                self.driver.get(self.home_url)
                logged = False
                try:
                    if self.driver.current_url.startswith(self.home_url) or "home.php" in self.driver.page_source or "Logout" in self.driver.page_source:
                        logged = True
                except Exception:
                    logged = False
                if not logged:
                    if not self.login_with_driver():
                        self.close_driver()
                        use_driver = False
            except Exception:
                use_driver = False
        done = 0
        total = len(symbols)
        for s in symbols:
            try:
                if use_driver and self.driver:
                    df = self.scrape_symbol_with_driver(s, refresh_retry=refresh_retry)
                    if df is None or (hasattr(df, "empty") and df.empty):
                        df = self.scrape_symbol_via_requests(s)
                else:
                    df = self.scrape_symbol_via_requests(s)
                if df is None:
                    df = pd.DataFrame()
                self._write_symbol_data(s, df, update_mode=update_mode)
                done += 1
                print(f"✔ {s} → rows={len(df)}")
                if rate_limit_ms and rate_limit_ms > 0:
                    try:
                        time.sleep(rate_limit_ms / 1000.0)
                    except Exception:
                        pass
            except Exception as e:
                msg = str(e).lower()
                if use_driver and ("invalid session id" in msg or "no such window" in msg or "disconnected" in msg):
                    ok = self.restart_driver_and_login()
                    if ok:
                        try:
                            df = self.scrape_symbol_with_driver(s, refresh_retry=refresh_retry)
                            if df is None or (hasattr(df, "empty") and df.empty):
                                df = self.scrape_symbol_via_requests(s)
                            if df is None:
                                df = pd.DataFrame()
                            self._write_symbol_data(s, df, update_mode=update_mode)
                            done += 1
                            print(f"✔ {s} (retry) → rows={len(df)}")
                            if rate_limit_ms and rate_limit_ms > 0:
                                try:
                                    time.sleep(rate_limit_ms / 1000.0)
                                except Exception:
                                    pass
                            continue
                        except Exception as e2:
                            print(f"❌ {s} gagal setelah retry: {e2}")
                            continue
                print(f"❌ {s} gagal: {e}")
                continue
        self.close_driver()
        # index file output disabled for MongoDB storage
        return done, total

    # aggregate_all disabled for MongoDB storage


def run_scrape_job() -> Dict[str, int]:
    username = os.environ.get("SIGNALSAHAM_EMAIL") or ""
    password = os.environ.get("SIGNALSAHAM_PASSWORD") or ""
    symbol = os.environ.get("SIGNALSAHAM_SYMBOL") or ""
    links_file = os.environ.get("LINKS_FILE") or ""
    links_limit = os.environ.get("LINKS_LIMIT") or ""
    skip_existing_env = os.environ.get("SKIP_EXISTING") or "true"
    rate_limit_ms_env = os.environ.get("RATE_LIMIT_MS") or "800"
    refresh_retry_env = os.environ.get("REFRESH_RETRY") or "true"
    update_mode = (os.environ.get("UPDATE_MODE") or "append").strip().lower()
    headless_env = os.environ.get("HEADLESS_MODE") or "true"
    headless_flag = str(headless_env).strip().lower() in ("1", "true", "yes", "y")
    if not username or not password:
        raise RuntimeError("Provide SIGNALSAHAM_EMAIL and SIGNALSAHAM_PASSWORD environment variables")
    scraper = SignalSahamScraper(use_selenium=True, headless=headless_flag)
    scraper.cred_email = username
    scraper.cred_password = password
    if not scraper.login(username, password):
        if not scraper.login_fixed(username, password):
            return {"done": 0, "total": 0}
    try:
        MONGO_CLIENT.admin.command("ping")
        print("✔ Mongo connected")
    except Exception as e:
        print(f"❌ Mongo connect failed: {e}")
        return {"done": 0, "total": 0}
    if not links_file:
        candidates = [os.path.join("backend", "link-name-stock.txt"), "link-name-stock.txt"]
        for cand in candidates:
            try:
                if os.path.exists(cand):
                    links_file = cand
                    break
            except Exception:
                pass
    if links_file:
        try:
            rate_ms = int(rate_limit_ms_env)
        except Exception:
            rate_ms = 800
        skip_existing = str(skip_existing_env).strip().lower() in ("1", "true", "yes", "y")
        refresh_retry = str(refresh_retry_env).strip().lower() in ("1", "true", "yes", "y")
        print(f"Links file: {links_file}")
        done, total = scraper.scrape_symbols_from_file(links_file, limit=(int(links_limit) if links_limit else None), skip_existing=skip_existing, rate_limit_ms=rate_ms, refresh_retry=refresh_retry, update_mode=update_mode)
        return {"done": done, "total": total}
    if symbol:
        html = scraper.fetch_stock_price_selenium(symbol)
        if not html:
            return {"done": 0, "total": 1}
        dfs = []
        try:
            for df in pd.read_html(StringIO(html)):
                dfs.append(df)
        except Exception:
            pass
        if not dfs:
            soup = BeautifulSoup(html, "html.parser")
            for t in soup.find_all("table"):
                df = scraper._table_to_dataframe(t)
                if df is not None and not df.empty:
                    dfs.append(df)
        key_cols = ["Date", "Open", "High", "Low", "Close", "Volume", "Value"]
        chosen = None
        for df in dfs:
            cols = [str(c) for c in list(df.columns)]
            if all(any(k.lower() in str(c).lower() for c in cols) for k in key_cols):
                chosen = df
                break
        if chosen is None and dfs:
            chosen = max(dfs, key=lambda x: len(x))
        out = chosen if chosen is not None else pd.DataFrame()
        out["symbol"] = symbol
        try:
            records = json.loads(out.to_json(orient="records"))
        except Exception:
            records = []
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        up = 0
        for rec in records:
            d = rec.get("Date") or rec.get("col_1") or ""
            if not d:
                continue
            rec["symbol"] = symbol
            rec["scraped_at_utc"] = now_utc
            try:
                MONGO_PRICES.update_one({"symbol": symbol, "Date": d}, {"$set": rec}, upsert=True)
                up += 1
            except Exception:
                pass
        return {"done": up, "total": 1}
    return {"done": 0, "total": 0}


if __name__ == "__main__":
    run_scrape_job()