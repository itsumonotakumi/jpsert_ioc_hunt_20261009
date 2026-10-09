#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jpcert_ioc_hunt.py
  Webアクセスログから、JPCERT/CC 注意喚起（ケースA/B/C）の痕跡を洗い出す調査スクリプト。
  Python 3.8+ / 標準ライブラリのみ / 読み取り専用（ログは一切変更しない）。

使い方:
  python3 jpcert_ioc_hunt.py /var/log/nginx/                      # ディレクトリごと（.gz/.bz2/.xz 可）
  python3 jpcert_ioc_hunt.py access.log* --since 2026-07-25       # 期間を絞る（JST）
  python3 jpcert_ioc_hunt.py logs/ --allow-ip 203.0.113.10 --allow-ip 100.64.0.0/10
  zcat access.log.gz | python3 jpcert_ioc_hunt.py -

対応ログ形式:
  - Apache / nginx の combined（先頭に vhost が付く形式も可）
  - JSON Lines（nginx の JSON ログ / Caddy / Traefik）
  - それ以外の行は「IoC の IP・固有UA が含まれるか」だけを生テキストで照合

検出内容:
  IoC   注意喚起記載の送信元IP（行内のどこにあっても照合。XFF欄も拾う）/ User-Agent
  A     設定・バックアップ・認証情報ファイルの探索と取得成功、既知脆弱性の探索、大量404
  B     NoSQLi 演算子、スクリプト系UAからのAPI書き込み成功、401/403 と 2xx の混在（応答差分の確認）
  C     Metabase: POST /api/session/reset_password(400) → GET /api/user/current(200) の連続

出力:
  標準出力にサマリー、<PREFIX>_findings.csv（検出行）、<PREFIX>_ip_summary.csv（IP別集計）
  終了コード: 2 = HIGH あり / 1 = MEDIUM あり / 0 = それ以外

限界（重要）:
  - アクセスログには POST ボディが残らない。ケースBの権限変更・アカウント作成・ボディ内 NoSQLi は
    ここでは「兆候」までしか分からない。アプリ側の監査ログ・DB（ユーザー一覧/権限/作成日時）を別途確認すること。
  - curl / python-requests などの汎用UAは正規利用でも普通に出るため、UA一致だけでは検出扱いにしない。
  - CDN / LB 配下で実IPがログ先頭に出ていない場合、IP別の集計（A-SCAN 等）は当てにならない。IoC IP 照合は有効。
  - Strapi など `filters[x][$ne]` を正規に使うAPIでは B-NOSQLI が誤検知になる。
  - C-MB-SEQUENCE は「同一IP」での連続だけを見る。攻撃者が途中でIPを変えた場合は拾えないため、
    C-MB-RESET（reset_password への POST が 400）が1件でも出たら、その前後の時刻を手で確認すること。
"""
import argparse
import bz2
import csv
import glob
import gzip
import ipaddress
import json
import lzma
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote

JST = timezone(timedelta(hours=9))

# =============================================================================
# IoC（注意喚起の記載どおり。追加は --ioc-file でも可）
# =============================================================================
IOC_IPS = {
    # ケースB: API経由の不正操作（9月ごろ悪用）
    "3.112.252.14": "B",
    "54.95.112.6": "B",
    "69.10.51.162": "B",
    "172.86.91.7": "B",
    "210.149.87.120": "B",
    # ケースC: Metabase CVE-2026-72898（8月上旬〜9月上旬に悪用）
    "213.163.202.171": "C",
    "221.216.140.49": "C",
    "221.216.140.129": "C",
}

# 悪用が確認された時期に前後の余裕を足した判定窓。窓の外の一致は MEDIUM に落とす
# （注意喚起に「調査時点では正規利用されている可能性」とあるため）。
IOC_WINDOWS = {
    "B": (datetime(2026, 8, 15, tzinfo=JST), datetime(2026, 10, 15, tzinfo=JST)),
    "C": (datetime(2026, 7, 25, tzinfo=JST), datetime(2026, 9, 25, tzinfo=JST)),
}

# 固有性が高いUA（部分一致）: 一致したら HIGH
IOC_UA_STRONG = {"metabase-ghsa": "C"}
# 完全一致で MEDIUM: 正規の Chrome は "Chrome/126.0.0.0" 形式なので、この短縮形は不自然
IOC_UA_EXACT = {
    "mozilla/5.0 (macintosh; intel mac os x 10_15_7) applewebkit/537.36 "
    "(khtml, like gecko) chrome/126.0 safari/537.36": "B",
}
# 汎用UA（完全一致）: 単独では検出扱いにしない。APIパスと重なったときだけ LOW
IOC_UA_WEAK = {
    "curl/7.88.1": "B",
    "python-requests/2.34.2": "B",
    "python-requests/2.33.1": "C",
}

# =============================================================================
# 検出パターン
# =============================================================================
# ケースA: 設定ファイル・バックアップ・認証情報（デコード済み・小文字化したパスに適用）
SENSITIVE_RE = re.compile(r"""
    (?:^|/)\.env(?:[._-][\w.-]*)?$
  | (?:^|/)\.git/(?:config|head|index|packed-refs|logs/|objects/|refs/)
  | (?:^|/)\.svn/(?:entries|wc\.db)
  | (?:^|/)\.hg/
  | (?:^|/)\.aws/(?:credentials|config)
  | (?:^|/)\.ssh/
  | (?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$
  | (?:^|/)\.ht(?:passwd|access)(?:[._~-]\w*)?$
  | (?:^|/)\.(?:npmrc|pypirc|netrc|pgpass|my\.cnf|bash_history|ds_store|dockerenv|user\.ini)$
  | (?:^|/)\.docker/config\.json$
  | (?:^|/)(?:\.vscode/sftp|sftp-config|\.ftpconfig)(?:\.json)?$
  | (?:^|/)wp-config(?!\.php$|-sample\.php$)[\w.~-]*$
  | (?:^|/)(?:secrets?|credentials?|service[-_]?account[\w-]*)\.(?:json|ya?ml|txt|ini|env|xml)$
  | (?:^|/)(?:database|parameters|application(?:-\w+)?)\.(?:ya?ml|properties)$
  | (?:^|/)(?:appsettings(?:\.\w+)?|local\.settings)\.json$
  | (?:^|/)(?:config|configuration|settings|db|database)\.(?:php|inc|py|js|json|ya?ml|ini)[._~-](?:bak|old|orig|save|swp|backup|txt|\d+)$
  | (?:^|/)(?:docker-compose|compose)(?:\.[\w-]+)?\.ya?ml$
  | (?:^|/)(?:web\.config|php\.ini)$
  | (?:^|/)(?:phpinfo|info|pinfo|php_info)\.php$
  | (?:^|/)(?:storage/logs/laravel\.log|wp-content/debug\.log|debug\.log|error_log)$
  | (?:^|/)actuator/(?:env|heapdump|configprops|mappings|logfile)
  | (?:^|/)(?:server-status|server-info)$
  | (?:^|/)(?:_profiler|telescope/requests|debug/default/view)
  | \.(?:sql|sqlite3?|mdb|dump|bak|backup|old|orig|save|swp|swo)(?:\.(?:gz|zip|bz2|xz|7z))?$
  | (?:^|/)(?:backups?|bak|www|wwwroot|site|html|public_html|htdocs|web|db|database|dump|data|old|archive|src|source|release)
        [\w.-]*\.(?:zip|tar|tar\.gz|tgz|7z|rar|gz)$
""", re.X)

# ケースA: 既知脆弱性の探索でよく見る痕跡（デコード済み・小文字化したURI全体に適用）
VULN_RE = re.compile(r"""
    \.\./ | \.\.\\ | /etc/passwd | /proc/self/environ | \$\{jndi:
  | phpunit/.*eval-stdin\.php
  | /_ignition/execute-solution
  | /cgi-bin/.*(?:\.\.|/bin/sh|/bin/bash)
  | /vendor/[\w./-]+\.php
  | /solr/admin | /manager/html | /jmx-console | /invoker/
  | /remote/(?:fgt_lang|logincheck) | /dana-na/ | /global-protect/ | /\+cscoe\+/
  | /owa/auth/ | /ecp/ | /boaform/ | /hnap1 | /geoserver/
  | /wp-content/plugins/[\w-]+/(?:.*upload.*\.php|.*shell.*\.php)
  | (?:^|/)(?:shell|cmd|c99|r57|wso|alfa|mini|up|upload)\.php$
""", re.X)

# ケースB: NoSQLインジェクション演算子（クエリ文字列に適用）
NOSQL_RE = re.compile(
    r"\[\$(?:ne|gt|gte|lt|lte|in|nin|regex|exists|where)\]"
    r"|[\"']\$(?:ne|gt|gte|lt|lte|in|nin|regex|exists|where)[\"']\s*:"
    r"|\$where\b"
)

# ケースB: APIパスの既定判定（--api-regex で差し替え可）
DEFAULT_API_REGEX = r"(?:^|/)(?:api|apis|graphql|rest|internal|wp-json|v[0-9]+)(?:/|$)"
# 権限・アカウント系の操作を示すパス断片
PRIV_RE = re.compile(
    r"admin|role|permission|privilege|users?(?:/|$)|accounts?|members?|auth|token|"
    r"api[-_]?keys?|register|signup|sign-up|invite|grant"
)
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# 人手・スクリプトによる直接操作で使われやすいUA（正規モバイルアプリの okhttp / CFNetwork 等は含めない）
SCRIPT_UA_RE = re.compile(
    r"^(?:curl|wget|python-requests|python-urllib|python-httpx|python/|aiohttp|httpx|go-http-client|"
    r"libwww-perl|httpie|postmanruntime|insomnia|node-fetch|undici|node$|scrapy|sqlmap|nuclei|zgrab|"
    r"nikto|ffuf|gobuster|dirsearch|feroxbuster|wpscan|masscan|nmap|fasthttp|ruby|java/)"
)

SEV = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_NAME = {v: k for k, v in SEV.items()}

RULES = {
    "IOC-IP": ("B/C", "注意喚起に記載の不審な送信元IPからのアクセス"),
    "IOC-UA-STRONG": ("C", "Metabase攻撃ツール固有のUser-Agent（Metabase-GHSA-*）"),
    "IOC-UA": ("B", "注意喚起記載のUAと完全一致（正規Chromeは 126.0.0.0 形式のため不自然）"),
    "IOC-UA-API": ("B/C", "注意喚起記載の汎用UA（curl / python-requests）でAPIパスへアクセス"),
    "RAW-IOC": ("-", "解析できない行に IoC（IP / 固有UA）が含まれる"),
    "A-SENSITIVE-OK": ("A", "設定・バックアップ・認証情報ファイルの取得に成功した可能性（2xx）"),
    "A-SENSITIVE-PROBE": ("A", "設定・バックアップファイルの探索（取得は失敗）"),
    "A-VULN-2XX": ("A", "既知脆弱性の探索リクエストに 2xx を返している"),
    "A-VULN-PROBE": ("A", "既知脆弱性の探索（失敗）"),
    "A-SCAN": ("A", "同一IPからの大量404（スキャン挙動）"),
    "B-NOSQLI": ("B", "NoSQLインジェクション演算子を含むリクエスト"),
    "B-NOSQLI-BLIND": ("B", "同一IPから NoSQLi 演算子付きリクエストが多数（ブラインド探索の疑い）"),
    "B-SCRIPT-WRITE": ("B", "スクリプト系UAからAPIへの書き込み系リクエストが成功"),
    "B-AUTH-PROBE": ("B", "APIで 401/403 を多数出しつつ 2xx も得ているIP（認証応答の差分確認の疑い）"),
    "C-MB-RESET": ("C", "Metabase /api/session/reset_password への POST"),
    "C-MB-SEQUENCE": ("C", "reset_password(400) → /api/user/current(200) の連続（侵害の可能性が高いパターン）"),
}

NEXT_ACTIONS = {
    "IOC-IP": "該当IPの全リクエストを時系列で確認し、2xx を返した操作の影響（データ変更・取得）を特定する",
    "IOC-UA-STRONG": "Metabase のバージョンと /api/session/reset_password の公開状況を確認する",
    "A-SENSITIVE-OK": "応答サイズと実ファイルの有無を確認。実在したなら中の認証情報・APIキーをすべてローテーションする",
    "B-NOSQLI-BLIND": "対象エンドポイントの入力検証を確認し、アカウント情報の漏えい前提でパスワード・トークンを失効させる",
    "C-MB-SEQUENCE": "Metabase のセッション・APIキー・管理者アカウントを確認し、接続先DBの認証情報を変更する",
}

# =============================================================================
# ログ解析
# =============================================================================
LINE_RE = re.compile(
    r'^(?:(?P<vhost>\S+) )?(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_TZ_CACHE = {}


def parse_clf_time(s):
    """'09/Oct/2026:09:22:01 +0900' → datetime（tz付き）"""
    try:
        off = s[21:26]
        tz = _TZ_CACHE.get(off)
        if tz is None:
            sign = -1 if off[0] == "-" else 1
            tz = timezone(sign * timedelta(hours=int(off[1:3]), minutes=int(off[3:5])))
            _TZ_CACHE[off] = tz
        return datetime(int(s[7:11]), MONTHS[s[3:6]], int(s[0:2]),
                        int(s[12:14]), int(s[15:17]), int(s[18:20]), tzinfo=tz)
    except (ValueError, KeyError, IndexError):
        return None


def parse_any_time(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        try:
            return datetime.fromtimestamp(v / 1000 if v > 1e12 else v, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    s = str(v).strip()
    t = parse_clf_time(s)
    if t:
        return t
    s = s.replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # ナノ秒 → マイクロ秒
    try:
        t = datetime.fromisoformat(s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=JST)  # tzなしは JST とみなす


class Rec:
    __slots__ = ("ip", "t", "method", "uri", "status", "size", "ua", "src")

    def __init__(self, ip, t, method, uri, status, size, ua, src=""):
        self.ip, self.t, self.method, self.uri = ip, t, method, uri
        self.status, self.size, self.ua, self.src = status, size, ua, src


def _first(o, keys):
    for k in keys:
        v = o.get(k)
        if v not in (None, ""):
            return v
    return None


def parse_json_line(line):
    try:
        o = json.loads(line)
    except ValueError:
        return None
    if not isinstance(o, dict):
        return None
    req = o.get("request")
    if isinstance(req, dict):  # Caddy
        ip = req.get("client_ip") or req.get("remote_ip") or req.get("remote_addr")
        method, uri = req.get("method"), req.get("uri")
        ua = (req.get("headers") or {}).get("User-Agent")
        if isinstance(ua, list):
            ua = ua[0] if ua else ""
    else:
        ip = _first(o, ("remote_addr", "client_ip", "clientip", "remote_ip", "ClientHost", "client", "ip"))
        method = _first(o, ("request_method", "method", "RequestMethod", "verb"))
        uri = _first(o, ("request_uri", "uri", "RequestPath", "path", "url"))
        ua = _first(o, ("http_user_agent", "user_agent", "request_User-Agent", "agent", "useragent"))
        if isinstance(req, str) and (not method or uri is None):
            p = req.split(" ")
            if len(p) >= 2:
                method, uri = method or p[0], uri if uri is not None else p[1]
    if not ip or uri is None:
        return None
    try:
        status = int(_first(o, ("status", "DownstreamStatus", "status_code", "response_status")) or 0)
    except (TypeError, ValueError):
        status = 0
    try:
        size = int(_first(o, ("body_bytes_sent", "bytes_sent", "size", "DownstreamContentSize", "bytes")) or -1)
    except (TypeError, ValueError):
        size = -1
    t = parse_any_time(_first(o, ("ts", "time_iso8601", "time_local", "@timestamp", "timestamp", "time", "StartUTC")))
    return Rec(str(ip).split(":")[0] if str(ip).count(":") == 1 else str(ip),
               t, str(method or "-").upper(), str(uri), status, size, str(ua or ""))


def parse_line(line):
    if line.startswith("{"):
        return parse_json_line(line)
    m = LINE_RE.match(line)
    if not m:
        return None
    req = m.group("req")
    p = req.split(" ")
    method, uri = (p[0].upper(), p[1]) if len(p) >= 2 else ("-", req)
    size = m.group("size")
    return Rec(m.group("ip"), parse_clf_time(m.group("time")), method, uri,
               int(m.group("status")), int(size) if size.isdigit() else -1, m.group("ua") or "")


def decode(s):
    d = unquote(s, errors="replace")
    if "%" in d:  # 二重エンコード対策
        d = unquote(d, errors="replace")
    return d.lower()


def open_any(path):
    if path == "-":
        return sys.stdin
    low = path.lower()
    if low.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    if low.endswith(".bz2"):
        return bz2.open(path, "rt", encoding="utf-8", errors="replace")
    if low.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def expand_paths(paths):
    out = []
    for p in paths:
        if p == "-":
            out.append(p)
        elif os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                out.extend(os.path.join(root, f) for f in sorted(files))
        elif os.path.isfile(p):
            out.append(p)
        else:
            hits = sorted(glob.glob(p))
            if not hits:
                print(f"[警告] 見つかりません: {p}", file=sys.stderr)
            out.extend(h for h in hits if os.path.isfile(h))
    return out


# =============================================================================
# 集計
# =============================================================================
class IPStat:
    __slots__ = ("total", "first", "last", "n404", "paths404", "api_deny", "api_ok",
                 "api_script", "nosqli", "rules", "maxsev", "ua", "weak_ua")

    def __init__(self):
        self.total = self.n404 = self.api_deny = self.api_ok = 0
        self.api_script = self.nosqli = self.weak_ua = 0
        self.first = self.last = self.paths404 = self.rules = None
        self.maxsev = -1
        self.ua = ""


def csv_safe(v):
    """ログ由来の文字列を表計算ソフトで開いても数式として実行されないようにする"""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") and len(s) > 1 else s


def fmt_time(t):
    return t.astimezone(JST).strftime("%Y-%m-%d %H:%M:%S") if t else ""


class Report:
    COLS = ["severity", "case", "rule", "time_jst", "ip", "method", "uri", "status", "size",
            "user_agent", "note", "source"]

    def __init__(self, csv_path, include_info):
        self.include_info = include_info
        self.count = Counter()            # (sev, rule) → 件数
        self.samples = defaultdict(list)  # rule → 例
        self.fh = self.w = None
        if csv_path:
            self.fh = open(csv_path, "w", newline="", encoding="utf-8-sig")
            self.w = csv.writer(self.fh)
            self.w.writerow(self.COLS)

    def add(self, sev, rule, rec, ipstats, note=""):
        self.count[(sev, rule)] += 1
        st = ipstats.get(rec.ip) if rec.ip else None
        if st is not None and sev != "INFO":
            if st.rules is None:
                st.rules = Counter()
            st.rules[rule] += 1
            st.maxsev = max(st.maxsev, SEV[sev])
        if sev == "INFO" and not self.include_info:
            return
        if len(self.samples[(sev, rule)]) < 10:
            self.samples[(sev, rule)].append((rec, note))
        if self.w:
            self.w.writerow([sev, RULES[rule][0], rule, fmt_time(rec.t), csv_safe(rec.ip), csv_safe(rec.method),
                             csv_safe(rec.uri[:2000]), rec.status or "", rec.size if rec.size >= 0 else "",
                             csv_safe(rec.ua[:500]), csv_safe(note), csv_safe(rec.src)])

    def close(self):
        if self.fh:
            self.fh.close()


def ioc_ip_severity(case, t):
    lo, hi = IOC_WINDOWS[case]
    if t is None or lo <= t <= hi:
        return "HIGH", ""
    return "MEDIUM", "悪用確認時期の外（IP再利用・正規利用の可能性あり）"


def main():
    ap = argparse.ArgumentParser(
        description="アクセスログから JPCERT/CC 注意喚起（ケースA/B/C）の痕跡を探す",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("paths", nargs="+", help="ログファイル / ディレクトリ / glob / '-'（標準入力）")
    ap.add_argument("--since", help="この日以降だけ見る（YYYY-MM-DD, JST）")
    ap.add_argument("--until", help="この日まで見る（YYYY-MM-DD, JST・当日を含む）")
    ap.add_argument("--out", default="ioc_hunt", help="出力CSVの接頭辞（既定: ioc_hunt）")
    ap.add_argument("--no-csv", action="store_true", help="CSVを出力しない")
    ap.add_argument("--allow-ip", action="append", default=[], metavar="IP|CIDR",
                    help="除外する自組織のIP（監視・自前バッチ等）。複数指定可")
    ap.add_argument("--ioc-file", help="追加のIoC IPを1行1件で書いたファイル（'[.]' 表記可, '#' はコメント）")
    ap.add_argument("--api-regex", default=DEFAULT_API_REGEX, help="APIパスとみなす正規表現")
    ap.add_argument("--scan-404", type=int, default=30, help="A-SCAN: 404 の件数しきい値（既定30）")
    ap.add_argument("--auth-deny", type=int, default=10, help="B-AUTH-PROBE: 401/403 の件数しきい値（既定10）")
    ap.add_argument("--nosqli-burst", type=int, default=10, help="B-NOSQLI-BLIND: 件数しきい値（既定10）")
    ap.add_argument("--mb-window", type=int, default=30, help="C-MB-SEQUENCE: 連続とみなす分数（既定30）")
    ap.add_argument("--top", type=int, default=10, help="サマリーに出すIPの数")
    ap.add_argument("--include-info", action="store_true", help="汎用UA一致だけの行もCSVに出す")
    args = ap.parse_args()

    ioc_ips = dict(IOC_IPS)
    if args.ioc_file:
        with open(args.ioc_file, encoding="utf-8") as f:
            for ln in f:
                ln = ln.split("#")[0].strip().replace("[.]", ".").lstrip("- ")
                if ln:
                    ioc_ips.setdefault(ln, "B")
    ioc_ip_re = re.compile(r"(?<![0-9.])(?:" + "|".join(re.escape(i) for i in ioc_ips) + r")(?![0-9])")
    api_re = re.compile(args.api_regex)
    allow_nets = [ipaddress.ip_network(a, strict=False) for a in args.allow_ip]
    allow_cache = {}

    def allowed(ip):
        r = allow_cache.get(ip)
        if r is None:
            try:
                a = ipaddress.ip_address(ip)
                r = any(a in n for n in allow_nets)
            except ValueError:
                r = False
            allow_cache[ip] = r
        return r

    since = datetime.strptime(args.since, "%Y-%m-%d").replace(tzinfo=JST) if args.since else None
    until = (datetime.strptime(args.until, "%Y-%m-%d").replace(tzinfo=JST) + timedelta(days=1)) if args.until else None

    files = expand_paths(args.paths)
    if not files:
        print("対象ファイルがありません", file=sys.stderr)
        return 3

    rep = Report(None if args.no_csv else f"{args.out}_findings.csv", args.include_info)
    ipstats = {}
    ioc_detail = {}                       # IoC IP → {count, first, last, status, paths}
    mb_reset = []                         # (t, ip, rec)  POST reset_password 400
    mb_current = defaultdict(list)        # ip → [t]      GET /api/user/current 200
    n_lines = n_parsed = n_unparsed = n_skipped_time = n_allowed = 0
    t_min = t_max = None

    for path in files:
        try:
            fh = open_any(path)
        except OSError as e:
            print(f"[警告] 開けません: {path}: {e}", file=sys.stderr)
            continue
        try:
            for lineno, line in enumerate(fh, 1):
                n_lines += 1
                line = line.rstrip("\r\n")
                if not line:
                    continue
                src = f"{path}:{lineno}"
                rec = parse_line(line)
                ioc_m = ioc_ip_re.search(line)

                if rec is None:  # 形式不明の行は IoC だけ生照合
                    n_unparsed += 1
                    low = line.lower()
                    strong = next((k for k in IOC_UA_STRONG if k in low), None)
                    if ioc_m or strong:
                        raw = Rec(ioc_m.group(0) if ioc_m else "", None, "-", line[:500], 0, -1, "", src)
                        rep.add("HIGH", "RAW-IOC", raw, ipstats,
                                "IoC IP 一致" if ioc_m else "固有UA一致")
                    continue

                n_parsed += 1
                rec.src = src
                t = rec.t
                if t is not None:
                    if (since and t < since) or (until and t >= until):
                        n_skipped_time += 1
                        continue
                    if t_min is None or t < t_min:
                        t_min = t
                    if t_max is None or t > t_max:
                        t_max = t
                if allow_nets and allowed(rec.ip):
                    n_allowed += 1
                    continue

                st = ipstats.get(rec.ip)
                if st is None:
                    st = ipstats[rec.ip] = IPStat()
                st.total += 1
                if t is not None:
                    if st.first is None or t < st.first:
                        st.first = t
                    if st.last is None or t > st.last:
                        st.last = t
                if not st.ua:
                    st.ua = rec.ua[:200]

                path_raw, _, query_raw = rec.uri.partition("?")
                dpath = decode(path_raw)
                dquery = decode(query_raw) if query_raw else ""
                ua_l = rec.ua.strip().lower()
                status, method = rec.status, rec.method
                ok2xx = 200 <= status < 300
                is_api = bool(api_re.search(dpath))
                is_script = ua_l in ("", "-") or bool(SCRIPT_UA_RE.match(ua_l))
                weak_ua = ua_l in IOC_UA_WEAK

                # ---- IoC: IP ------------------------------------------------
                if ioc_m:
                    hit_ip = ioc_m.group(0)
                    sev, note = ioc_ip_severity(ioc_ips[hit_ip], t)
                    if hit_ip != rec.ip:
                        note = (note + " / " if note else "") + f"クライアントIP欄以外で一致（XFF等）: {hit_ip}"
                    rep.add(sev, "IOC-IP", rec, ipstats, f"ケース{ioc_ips[hit_ip]} {note}".rstrip())
                    d = ioc_detail.setdefault(hit_ip, {"count": 0, "first": t, "last": t,
                                                       "status": Counter(), "paths": Counter()})
                    d["count"] += 1
                    d["status"][status] += 1
                    d["paths"][f"{method} {path_raw[:80]}"] += 1
                    if t is not None:
                        d["first"] = t if d["first"] is None or t < d["first"] else d["first"]
                        d["last"] = t if d["last"] is None or t > d["last"] else d["last"]

                # ---- IoC: User-Agent ---------------------------------------
                if any(k in ua_l for k in IOC_UA_STRONG):
                    rep.add("HIGH", "IOC-UA-STRONG", rec, ipstats)
                elif ua_l in IOC_UA_EXACT:
                    rep.add("MEDIUM", "IOC-UA", rec, ipstats)
                elif weak_ua:
                    st.weak_ua += 1
                    rep.add("LOW" if is_api else "INFO", "IOC-UA-API", rec, ipstats)

                # ---- ケースA ------------------------------------------------
                if SENSITIVE_RE.search(dpath):
                    if ok2xx and rec.size != 0 and method != "HEAD":
                        rep.add("HIGH", "A-SENSITIVE-OK", rec, ipstats,
                                "応答サイズと実ファイルの有無を確認（全URLに200を返す構成なら誤検知）")
                    else:
                        rep.add("LOW", "A-SENSITIVE-PROBE", rec, ipstats)
                elif VULN_RE.search(dpath + ("?" + dquery if dquery else "")):
                    rep.add("MEDIUM" if ok2xx else "LOW", "A-VULN-2XX" if ok2xx else "A-VULN-PROBE", rec, ipstats)
                if status == 404:
                    st.n404 += 1
                    if st.paths404 is None:
                        st.paths404 = set()
                    if len(st.paths404) < 200:
                        st.paths404.add(dpath)

                # ---- ケースB ------------------------------------------------
                if dquery and NOSQL_RE.search(dquery):
                    st.nosqli += 1
                    rep.add("MEDIUM", "B-NOSQLI", rec, ipstats)
                if is_api:
                    if status in (401, 403):
                        st.api_deny += 1
                    elif ok2xx:
                        st.api_ok += 1
                    if is_script or weak_ua or ua_l in IOC_UA_EXACT:
                        st.api_script += 1
                    if is_script and method in WRITE_METHODS and 200 <= status < 400:
                        priv = PRIV_RE.search(dpath)
                        rep.add("MEDIUM" if priv else "LOW", "B-SCRIPT-WRITE", rec, ipstats,
                                "権限・アカウント系パス" if priv else "")

                # ---- ケースC ------------------------------------------------
                p = dpath.rstrip("/")
                if p.endswith("/api/session/reset_password") and method == "POST":
                    rep.add("MEDIUM" if status == 400 else "LOW", "C-MB-RESET", rec, ipstats,
                            "400応答（攻撃時に観測されるステータス）" if status == 400 else "")
                    if status == 400 and t is not None:
                        mb_reset.append((t, rec.ip, rec))
                elif p.endswith("/api/user/current") and method == "GET" and status == 200 and t is not None:
                    if len(mb_current[rec.ip]) < 20000:
                        mb_current[rec.ip].append(t)
        except (OSError, EOFError, lzma.LZMAError) as e:
            print(f"[警告] 読み込み中断: {path}: {e}", file=sys.stderr)
        finally:
            if fh is not sys.stdin:
                fh.close()

    # ---- IP単位・時系列の判定 ---------------------------------------------
    def agg(sev, rule, ip, st, note):
        rep.add(sev, rule, Rec(ip, st.first, "-", "(集計)", 0, -1, st.ua, f"{fmt_time(st.first)}〜{fmt_time(st.last)}"),
                ipstats, note)

    for ip, st in list(ipstats.items()):
        if st.n404 >= args.scan_404 and st.paths404 and len(st.paths404) >= min(20, args.scan_404):
            agg("LOW", "A-SCAN", ip, st, f"404={st.n404}件 / 異なるパス{len(st.paths404)}{'+' if len(st.paths404) >= 200 else ''}種")
        if st.nosqli >= args.nosqli_burst:
            agg("HIGH", "B-NOSQLI-BLIND", ip, st, f"NoSQLi演算子付き {st.nosqli}件")
        if st.api_deny >= args.auth_deny and st.api_ok >= 1:
            agg("MEDIUM" if st.api_script else "LOW", "B-AUTH-PROBE", ip, st,
                f"API 401/403={st.api_deny}件, 2xx={st.api_ok}件, スクリプト系/IoC UA={st.api_script}件")

    win = timedelta(minutes=args.mb_window)
    seen_seq = set()
    for t, ip, rec in sorted(mb_reset, key=lambda x: x[0]):
        if ip in seen_seq:
            continue
        nxt = [c for c in mb_current.get(ip, ()) if t <= c <= t + win]
        if nxt:
            seen_seq.add(ip)
            rep.add("HIGH", "C-MB-SEQUENCE", rec, ipstats,
                    f"{fmt_time(min(nxt))} に GET /api/user/current が 200（{args.mb_window}分以内）")
    rep.close()

    # ---- IP別サマリーCSV ---------------------------------------------------
    flagged = sorted(((ip, st) for ip, st in ipstats.items() if st.maxsev >= SEV["LOW"]),
                     key=lambda x: (-x[1].maxsev, -sum(x[1].rules.values())))
    if not args.no_csv:
        with open(f"{args.out}_ip_summary.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["ip", "max_severity", "ioc_ip_case", "requests", "findings", "rules", "n_404",
                        "api_401_403", "api_2xx", "weak_ioc_ua_requests", "first_seen_jst", "last_seen_jst",
                        "sample_user_agent"])
            for ip, st in flagged:
                w.writerow([ip, SEV_NAME[st.maxsev], ioc_ips.get(ip, ""), st.total, sum(st.rules.values()),
                            " ".join(f"{k}={v}" for k, v in st.rules.most_common()), st.n404, st.api_deny,
                            st.api_ok, st.weak_ua, fmt_time(st.first), fmt_time(st.last), csv_safe(st.ua)])

    # ---- 画面サマリー ------------------------------------------------------
    by_sev = Counter()
    for (sev, _rule), n in rep.count.items():
        by_sev[sev] += n
    line = "=" * 78
    print(line)
    print(" JPCERT/CC 注意喚起 IoC ハント結果")
    print(line)
    print(f" 対象ファイル : {len(files)} 件")
    print(f" 行数         : {n_lines:,}（解析 {n_parsed:,} / 形式不明 {n_unparsed:,} / 期間外 {n_skipped_time:,} / 除外IP {n_allowed:,}）")
    print(f" ログの期間   : {fmt_time(t_min) or '不明'} 〜 {fmt_time(t_max) or '不明'}（JST）")
    print(f" 送信元IP数   : {len(ipstats):,}")
    print(f" 検出         : HIGH {by_sev['HIGH']:,} / MEDIUM {by_sev['MEDIUM']:,} / LOW {by_sev['LOW']:,}"
          f"（汎用UA一致のみ {by_sev['INFO']:,} 件は検出扱いにしていない）")
    if n_parsed == 0:
        print(" [注意] 1行も解析できていません。ログ形式を確認してください。")
    if t_min and t_min > IOC_WINDOWS["C"][0] and not since:
        print(f" [注意] ログが {fmt_time(t_min)} 以降しかありません。7月下旬〜の悪用期間をカバーしていない可能性があります。")

    def show(rec, note):
        uri = rec.uri if len(rec.uri) <= 110 else rec.uri[:107] + "..."
        ua = rec.ua if len(rec.ua) <= 60 else rec.ua[:57] + "..."
        head = f"{fmt_time(rec.t) or '-':19}  {rec.ip:15}"
        if rec.method == "-" and rec.uri == "(集計)":
            print(f"     {head}  {note}")
        elif rec.method == "-" and not rec.status:  # 形式不明の行は生テキストのまま出す
            print(f"     {rec.ip or '-':15}  {uri}")
            print(f"       ↳ {note}  [{rec.src}]")
        else:
            print(f"     {head}  {rec.method} {uri}  → {rec.status or '-'} ({rec.size if rec.size >= 0 else '-'}B)  UA={ua!r}")
            if note:
                print(f"       ↳ {note}")

    for sev, n_samples in (("HIGH", 10), ("MEDIUM", 5), ("LOW", 2)):
        rules = sorted(((r, n) for (s, r), n in rep.count.items() if s == sev), key=lambda x: -x[1])
        if not rules:
            continue
        print()
        print(f"--- {sev} " + "-" * (73 - len(sev)))
        for rule, n in rules:
            print(f" [{rule}] {n:,}件  ケース{RULES[rule][0]}: {RULES[rule][1]}")
            for rec, note in rep.samples[(sev, rule)][:n_samples]:
                show(rec, note)
            if n > n_samples:
                print(f"     … 残り {n - n_samples:,} 件はCSV参照")
            if sev == "HIGH" and rule in NEXT_ACTIONS:
                print(f"     ▶ 次の一手: {NEXT_ACTIONS[rule]}")

    if ioc_detail:
        print()
        print("--- IoC IP 別の内訳 " + "-" * 58)
        for ip, d in sorted(ioc_detail.items(), key=lambda x: -x[1]["count"]):
            sts = " ".join(f"{k}:{v}" for k, v in sorted(d["status"].items()))
            print(f" {ip}（ケース{ioc_ips[ip]}） {d['count']:,}件  {fmt_time(d['first'])} 〜 {fmt_time(d['last'])}  status[{sts}]")
            for pth, c in d["paths"].most_common(5):
                print(f"     {c:>5}  {pth}")

    if flagged:
        print()
        print(f"--- 要確認IP 上位{args.top} " + "-" * 56)
        for ip, st in flagged[:args.top]:
            rules = " ".join(f"{k}={v}" for k, v in st.rules.most_common(4))
            print(f" {SEV_NAME[st.maxsev]:6} {ip:15} req={st.total:<6} 404={st.n404:<5} {rules}")

    print()
    if not by_sev["HIGH"] and not by_sev["MEDIUM"]:
        print(" 結論: このログの範囲では HIGH / MEDIUM の痕跡なし。")
    elif by_sev["HIGH"]:
        print(" 結論: HIGH あり。上記の該当行を時系列で確認し、成功した操作の影響範囲を特定してください。")
    else:
        print(" 結論: HIGH なし・MEDIUM あり。誤検知の可能性を含むため、該当行の内容を確認してください。")
    if not args.no_csv:
        print(f" 出力: {args.out}_findings.csv / {args.out}_ip_summary.csv")
    print(" 補足: POSTボディはアクセスログに残りません。ケースBはアプリ側の監査ログ・DBも併せて確認を。")
    return 2 if by_sev["HIGH"] else 1 if by_sev["MEDIUM"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
