# jpcert_ioc_hunt

Metabase の SQL インジェクションの脆弱性(CVE-2026-72898)に関する JPCERT/CC の注意喚起 [JPCERT-AT-2026-0023](https://www.jpcert.or.jp/at/2026/at260023.html) をもとにした、Web アクセスログの調査スクリプトです。IoC の照合と、ケース A/B/C の攻撃パターン検出を行います。

- Python 3.8 以降、標準ライブラリのみ
- ログは読むだけで、書き換えません
- 自作のサンプルログでは、仕込んだ攻撃をすべて検出し、紛らわしい正常アクセスの誤検知はゼロでした(実ログでは未検証)

## 使い方

```bash
# ディレクトリごと(.gz / .bz2 / .xz もそのまま読める)
python3 jpcert_ioc_hunt.py /var/log/nginx/

# 悪用期間に絞り、自前の監視やバッチのIPを除外
python3 jpcert_ioc_hunt.py logs/ --since 2026-07-25 --allow-ip 203.0.113.10
```

### 対応するログ形式

- Apache / nginx の combined(先頭に vhost が付く形式も可)
- JSON Lines(nginx JSON / Caddy / Traefik)
- それ以外の行(FW ログなど)は、IoC の IP と固有 UA だけ照合します

### 出力
<img width="1332" height="929" alt="2026-10-09_09h42_12" src="https://github.com/user-attachments/assets/5239c964-c86e-4404-8d97-9ff63c3e33f8" />

- 画面にサマリーを表示
- `ioc_hunt_findings.csv`: 検出した行
- `ioc_hunt_ip_summary.csv`: IP 別の集計

### 終了コード

| コード | 意味 |
|---|---|
| 2 | HIGH の検出あり |
| 1 | MEDIUM の検出あり |
| 0 | それ以外 |

cron や CI に組み込めます。

### 主なオプション

| オプション | 内容 |
|---|---|
| `--since` / `--until` | 対象期間(YYYY-MM-DD, JST。`--until` は当日を含む) |
| `--allow-ip IP\|CIDR` | 除外する IP(複数指定可) |
| `--ioc-file` | 追加の IoC IP を 1 行 1 件で書いたファイル(`[.]` 表記可、`#` はコメント) |
| `--out` | 出力 CSV の接頭辞(既定: `ioc_hunt`) |
| `--no-csv` | CSV を出力しない |
| `--api-regex` | API パスとみなす正規表現 |
| `--scan-404` | A-SCAN の 404 件数しきい値(既定 30) |
| `--auth-deny` | B-AUTH-PROBE の 401/403 件数しきい値(既定 10) |
| `--nosqli-burst` | B-NOSQLI-BLIND の件数しきい値(既定 10) |
| `--mb-window` | C-MB-SEQUENCE で連続とみなす分数(既定 30) |
| `--top` | サマリーに出す IP の数(既定 10) |
| `--include-info` | 汎用 UA 一致だけの行も CSV に出す |

全オプションは `python3 jpcert_ioc_hunt.py --help` で確認できます。

速度の目安は、100 万行(222MB)で約 34 秒です。

## 検出内容

| ケース | 見ているもの | 重大度 |
|---|---|---|
| IoC | 注意喚起記載の送信元 IP 8 件(XFF 欄など行内のどこでも照合) | HIGH(悪用時期の外は MEDIUM) |
| IoC | `Metabase-GHSA-*` の UA | HIGH |
| IoC | `Chrome/126.0` 短縮形の UA(完全一致) | MEDIUM |
| A | `.env`・`.git/config`・バックアップ・SQL ダンプ等の取得成功(2xx) | HIGH |
| A | 同ファイルの探索失敗、既知脆弱性の探索、大量 404 | LOW(探索に 2xx を返していれば MEDIUM) |
| B | NoSQLi 演算子(`[$ne]`、`[$regex]` 等)付きリクエスト | MEDIUM(同一 IP で 10 件以上は HIGH) |
| B | スクリプト系 UA からの API 書き込み成功 | LOW(権限・アカウント系パスは MEDIUM) |
| B | 同一 IP が API で 401/403 を多数出しつつ 2xx も得ている | LOW〜MEDIUM |
| C | `POST /api/session/reset_password` が 400 → 同一 IP の `GET /api/user/current` が 200 | HIGH |

ケース C の連続パターンは、注意喚起に書かれている侵害判定の条件をそのまま実装したものです。

## 限界

- **POST ボディは見えません**: ケース B の権限変更・不正アカウント作成・ボディ内の NoSQLi は兆候までしか分かりません。アプリ側の監査ログと DB(ユーザー一覧・権限・作成日時)の確認が別途必要です。
- **汎用 UA は検出扱いにしていません**: `curl/7.88.1` や `python-requests` は正規利用でも普通に出るため、API パスと重なったときだけ LOW にしています。
- **CDN / LB 配下**: 実 IP がログ先頭に出ない構成では、IP 別の集計と、同一 IP を条件にしたケース C の連続判定が当てになりません。IoC IP の照合は有効です。
- **ケース C で IP を変えられた場合**: 連続判定では拾えません。`C-MB-RESET`(400 応答)が 1 件でも出たら前後の時刻を手で確認してください。
- **ログの保存期間**: 悪用は 7 月下旬〜9 月なので、ログがそこまで遡れない場合は「痕跡なし」でも安全とは言えません。該当時はスクリプトが注意を表示します。
- **しきい値は仮置き**: 大量 404 は 30 件、401/403 は 10 件、NoSQLi は 10 件、ケース C の連続は 30 分以内としています。いずれもオプションで変更できます。

## 参考

- [Metabase の SQL インジェクションの脆弱性(CVE-2026-72898)に関する注意喚起](https://www.jpcert.or.jp/at/2026/at260023.html)
