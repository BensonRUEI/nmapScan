import argparse
import ctypes
import importlib
import ipaddress
import logging
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
logger = logging.getLogger(__name__)

# 必要的 Python 套件：(import 名稱, pip 安裝名稱)
_REQUIRED_PACKAGES = [
    ('pandas',   'pandas'),
    ('openpyxl', 'openpyxl'),
]

# 必要的外部工具
_REQUIRED_BINARIES = ['nmap']


def check_dependencies() -> None:
    """檢查必要的 Python 套件與外部工具，若缺少則提示安裝方式並中止程式。"""
    missing_pkgs = []
    for import_name, pip_name in _REQUIRED_PACKAGES:
        if importlib.util.find_spec(import_name) is None:
            missing_pkgs.append(pip_name)

    if missing_pkgs:
        logger.error("缺少以下 Python 套件：%s", ', '.join(missing_pkgs))
        logger.error("請執行以下指令安裝後重新啟動程式：")
        logger.error("  pip install %s", ' '.join(missing_pkgs))
        sys.exit(1)

    missing_bins = [b for b in _REQUIRED_BINARIES if shutil.which(b) is None]
    if missing_bins:
        logger.error("找不到以下工具，請安裝並確認已加入 PATH：%s", ', '.join(missing_bins))
        sys.exit(1)

    logger.info("套件與工具檢查通過")


def is_privileged() -> bool:
    """檢查目前是否以系統管理員（Windows）或 root（Unix）身分執行。"""
    if sys.platform == 'win32':
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def check_privileges() -> None:
    """確認具備高權限，否則顯示提示並結束程式。"""
    if not is_privileged():
        if sys.platform == 'win32':
            logger.error("此掃描模式需要系統管理員權限。")
            logger.error("請在開始功能表搜尋 PowerShell，按右鍵選擇『以系統管理員身分執行』後重試。")
        else:
            logger.error("此掃描模式需要 root 權限，請使用 sudo python ScanPC.py 重試。")
        sys.exit(1)


def validate_network(network: str) -> bool:
    """驗證字串是否為合法的 IP 位址或 CIDR 網段。"""
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_address(network)
        return True
    except ValueError:
        return False


def load_networks(scanlist_path: Path) -> list:
    """從檔案讀取並驗證網段清單，忽略空行與 # 開頭的註解行。"""
    networks = []
    with open(scanlist_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            entry = line.strip()
            if not entry or entry.startswith('#'):
                continue
            if validate_network(entry):
                networks.append(entry)
            else:
                logger.warning("第 %d 行：無效的網段 '%s'，已略過", line_num, entry)
    return networks


def run_ping_scan(network: str, output_dir: Path, xsl_file: Path) -> list:
    """對單一網段執行 nmap ping 掃描，回傳存活主機 IP 清單。"""
    safe_name = network.replace('/', '_')
    xml_file = output_dir / f"{safe_name}.xml"
    html_file = output_dir / f"{safe_name}.html"

    logger.info("Ping 掃描網段：%s", network)
    result = subprocess.run(
        ['nmap', '-n', '-sn', '-v', '-oX', str(xml_file), network],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error("nmap ping 掃描失敗 (%s)：%s", network, result.stderr.strip())
        return []

    if xsl_file.exists():
        xsl_result = subprocess.run(
            ['xsltproc', '-o', str(html_file), str(xsl_file), str(xml_file)],
            capture_output=True, text=True,
        )
        if xsl_result.returncode != 0:
            logger.warning("xsltproc 轉換失敗 (%s)：%s", network, xsl_result.stderr.strip())
    else:
        logger.warning("找不到 XSL 檔案 '%s'，略過 HTML 轉換", xsl_file)

    live_hosts = parse_live_hosts(xml_file)
    xml_file.unlink(missing_ok=True)
    return live_hosts


def parse_live_hosts(xml_file: Path) -> list:
    """解析 nmap XML，回傳狀態為 up 且非廣播位址的 IP 清單。"""
    live_hosts = []
    try:
        root = ET.parse(xml_file).getroot()
        for host in root.findall('host'):
            status = host.find('status')
            if status is None or status.get('state') != 'up':
                continue
            address = host.find('address')
            if address is None:
                continue
            ip = address.get('addr', '')
            last_octet = ip.split('.')[-1]
            if last_octet not in ('0', '255'):
                live_hosts.append(ip)
    except ET.ParseError as exc:
        logger.error("無法解析 XML 檔案 '%s'：%s", xml_file, exc)
    return live_hosts


def run_port_scan(ip: str, output_dir: Path) -> dict:
    """對單一主機執行 nmap TCP SYN 掃描，回傳結果字典（無開放埠則回傳 None）。"""
    xml_file = output_dir / f"{ip}.xml"
    logger.info("Port 掃描：%s", ip)
    result = subprocess.run(
        ['nmap', '-n', '-P0', '-sS', '-T4', '-oX', str(xml_file), ip],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.error("nmap port 掃描失敗 (%s)：%s", ip, result.stderr.strip())
        return None

    open_ports = parse_open_ports(xml_file)
    xml_file.unlink(missing_ok=True)
    if open_ports:
        return {
            '主機IP': ip,
            'PORT總數': len(open_ports),
            'PORT列表': ', '.join(open_ports),
        }
    return None


def parse_open_ports(xml_file: Path) -> list:
    """解析 nmap XML，回傳所有開放埠號的字串清單。"""
    open_ports = []
    try:
        root = ET.parse(xml_file).getroot()
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                open_ports.append(port.get('portid'))
    except ET.ParseError as exc:
        logger.error("無法解析 XML 檔案 '%s'：%s", xml_file, exc)
    return open_ports


def save_live_hosts(live_hosts: list, output_dir: Path) -> Path:
    """將存活主機 IP 清單寫入 livePC.txt。"""
    livepc_file = output_dir / 'livePC.txt'
    with open(livepc_file, 'w') as f:
        f.write('\n'.join(live_hosts))
        if live_hosts:
            f.write('\n')
    logger.info("已將 %d 台存活主機寫入 %s", len(live_hosts), livepc_file)
    return livepc_file


def save_excel(scan_results: list, output_dir: Path) -> Path:
    """將掃描結果寫入 Excel 檔案。"""
    import pandas as pd  # 確保已通過 check_dependencies 才 import
    excel_file = output_dir / 'scan_results.xlsx'
    pd.DataFrame(scan_results).to_excel(excel_file, index=False)
    logger.info("掃描結果已儲存：%s", excel_file)
    return excel_file


def prompt_scan_mode() -> int:
    """提示使用者選擇掃描模式，回傳 1 或 2。"""
    print("\n請選擇掃描模式：")
    print("  1 - 主機開放 Port 掃描（TCP SYN 掃描）")
    print("  2 - 技術檢測網路搜尋調查階段掃描（Port Scan / TCP SYN Scan / UDP Scan）")
    while True:
        choice = input("請輸入選項 [1/2]：").strip()
        if choice in ('1', '2'):
            return int(choice)
        print("無效輸入，請輸入 1 或 2。")


def run_tech_detection_scan(ip: str, output_dir: Path) -> None:
    """對單一主機執行技術檢測三階段掃描（Port Scan / TCP SYN Scan / UDP Scan）。"""
    scans = [
        ('Port Scan',    ['nmap', '-A',  ip, '-oN', str(output_dir / f"{ip}_portscan.txt")]),
        ('TCP SYN Scan', ['nmap', '-sS', ip, '-oN', str(output_dir / f"{ip}_tcpsynscan.txt")]),
        ('UDP Scan',     ['nmap', '-sU', ip, '-oN', str(output_dir / f"{ip}_udpscan.txt")]),
    ]
    for scan_name, cmd in scans:
        logger.info("%s：%s", scan_name, ip)
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("%s 失敗 (%s)：%s", scan_name, ip, result.stderr.strip())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Nmap 網路掃描工具')
    parser.add_argument(
        '--scanlist', default='scanlist.txt',
        help='網段清單檔案路徑（預設：scanlist.txt）',
    )
    parser.add_argument(
        '--xsl', default='nmap-bootstrap.xsl',
        help='HTML 轉換用 XSL 檔案路徑（預設：nmap-bootstrap.xsl）',
    )
    return parser.parse_args()


def main() -> None:
    check_dependencies()
    args = parse_args()
    scanlist_path = Path(args.scanlist)
    xsl_file = Path(args.xsl)

    if not scanlist_path.exists():
        logger.error("找不到網段清單檔案：%s", scanlist_path)
        sys.exit(1)

    networks = load_networks(scanlist_path)
    if not networks:
        logger.error("網段清單中沒有有效的網段，請確認 %s 的內容", scanlist_path)
        sys.exit(1)

    output_dir = Path(f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
    output_dir.mkdir(exist_ok=True)
    logger.info("輸出目錄：%s", output_dir)

    # 第一階段：Ping 掃描，找出存活主機
    all_live_hosts = []
    for network in networks:
        live_hosts = run_ping_scan(network, output_dir, xsl_file)
        all_live_hosts.extend(live_hosts)

    logger.info("網段掃描完成，共發現 %d 台存活主機", len(all_live_hosts))
    save_live_hosts(all_live_hosts, output_dir)

    if not all_live_hosts:
        logger.info("未發現任何存活主機，結束")
        return

    mode = prompt_scan_mode()
    check_privileges()

    if mode == 1:
        # 選項 1：主機開放 Port 掃描（TCP SYN 掃描）
        scan_results = []
        for ip in all_live_hosts:
            result = run_port_scan(ip, output_dir)
            if result:
                scan_results.append(result)

        if scan_results:
            save_excel(scan_results, output_dir)
        else:
            logger.info("所有存活主機均無開放埠")

    else:
        # 選項 2：技術檢測網路搜尋調查階段掃描
        for ip in all_live_hosts:
            run_tech_detection_scan(ip, output_dir)
        logger.info("技術檢測掃描完成，結果已儲存至 %s", output_dir)


if __name__ == '__main__':
    main()
