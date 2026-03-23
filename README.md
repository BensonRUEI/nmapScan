# nmapScan

偵測網段內存活主機，並依掃描模式產生開放埠報表或技術檢測報告。

---

## 需求

### 系統環境

| 項目 | 說明 |
|------|------|
| Python | 3.9 以上 |
| [nmap](https://nmap.org/download.html) | 需安裝並加入系統 PATH |
| xsltproc | 選用，用於產生 HTML 報告（Linux 內建；Windows 可透過 [libxslt](https://xmlsoft.org/downloads.html) 安裝） |

### Python 套件

```sh
pip install pandas openpyxl
```

> 程式啟動時會自動檢查套件與 nmap 是否已安裝，缺少時會顯示安裝指令並終止。

### 執行權限

選單選項 1 與 2 均包含 TCP SYN 掃描（`-sS`）或 UDP 掃描（`-sU`），需要管理員權限：

- **Windows**：以「系統管理員身分執行」開啟 PowerShell 後再執行
- **Linux / macOS**：使用 `sudo python ScanPC.py`

---

## 設定掃描目標

編輯 `scanlist.txt`，每行填入一個網段（CIDR）或單一 IP，`#` 開頭為註解行：

```
# 辦公室網段
192.168.0.0/24
192.168.1.0/24
# 單一主機
10.0.0.1
```

---

## 執行

```sh
sudo python ScanPC.py
```

### 選用參數

| 參數 | 說明 | 預設值 |
|------|------|--------|
| `--scanlist` | 網段清單檔案路徑 | `scanlist.txt` |
| `--xsl` | HTML 轉換用 XSL 路徑 | `nmap-bootstrap.xsl` |

```sh
python ScanPC.py --scanlist my_networks.txt --xsl nmap-bootstrap.xsl
```

---

## 執行流程

```
啟動
 └─ 檢查套件與 nmap
 └─ 讀取 scanlist.txt
 └─ 第一階段：Ping 掃描（無需高權限）
     └─ 產生各網段 HTML 報告（需 xsltproc）
     └─ 輸出 livePC.txt（存活主機清單）
 └─ 選擇掃描模式
 └─ 檢查管理員 / root 權限
     ├─ 模式 1：TCP SYN Port 掃描 → scan_results.xlsx
     └─ 模式 2：技術檢測三階段掃描 → 各主機 .txt 報告
```

---

## 掃描模式

### 模式 1 — 主機開放 Port 掃描

對所有存活主機執行 TCP SYN 掃描，彙整開放埠後輸出 Excel 報表。

```
nmap -n -P0 -sS -T4 <ip>
```

### 模式 2 — 技術檢測網路搜尋調查階段掃描

對每台存活主機依序執行三種掃描：

| 掃描類型 | 指令 | 輸出檔案 |
|----------|------|----------|
| Port Scan | `nmap -A <ip>` | `<ip>_portscan.txt` |
| TCP SYN Scan | `nmap -sS <ip>` | `<ip>_tcpsynscan.txt` |
| UDP Scan | `nmap -sU <ip>` | `<ip>_udpscan.txt` |

---

## 輸出目錄結構

執行後在當前目錄產生 `scan_results_YYYYMMDD_HHMMSS/`：

```
scan_results_20260323_231200/
 ├─ livePC.txt                    # 存活主機 IP 清單
 ├─ <network>.html                # Ping 掃描 HTML 報告（需 xsltproc）
 │
 │  ── 模式 1 ──
 ├─ scan_results.xlsx             # 開放埠彙整報表
 │
 │  ── 模式 2 ──
 ├─ <ip>_portscan.txt
 ├─ <ip>_tcpsynscan.txt
 └─ <ip>_udpscan.txt
```

> 中間產生的 XML 暫存檔在解析完成後會自動刪除。

---

## License

MIT

