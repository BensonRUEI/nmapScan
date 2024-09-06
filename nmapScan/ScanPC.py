import os
import xml.etree.ElementTree as ET
import pandas as pd

# 讀取 scanlist.txt 檔案
with open('scanlist.txt', 'r') as file:
    networks = file.readlines()

# 清理換行符號
networks = [network.strip() for network in networks]

# 執行 nmap 掃描並生成 XML 和 HTML 檔案
for network in networks:
    output_file = f"{network.replace('/', '_')}.xml" 
    output_file_html = f"{network.replace('/', '_')}.html"
    
    # 執行 nmap 並產生 XML 檔案
    command = f"nmap -sn -v -oX {output_file} {network}"
    os.system(command)
    # print(f"Executing: {command}")
    
    # 使用 xsltproc 轉換 XML 為 HTML
    command = f"xsltproc -o {output_file_html} nmap-bootstrap.xsl {output_file}"
    os.system(command)
    # print(f"Executing: {command}")
    
    # 解析 XML 並將 state="up" 的主機 IP 位址寫入 livePC.txt
    tree = ET.parse(output_file)
    root = tree.getroot()
    
    # 清空 livePC.txt 檔案
    if network == networks[0]:
        with open('livePC.txt', 'w') as file:
            file.write('')

    # 搜尋所有 state="up" 的主機，並略過 .0 和 .255 的 IP
    with open('livePC.txt', 'a') as file:
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                address = host.find('address')
                if address is not None:
                    ip = address.get('addr')
                    # 略過最後一位為 0 或 255 的 IP
                    last_octet = ip.split('.')[-1]
                    if last_octet != '0' and last_octet != '255':
                        file.write(f"{ip}\n")

print("所有網段掃描完成，並將 state='up' 的主機 IP 位址寫入 livePC.txt")

# 從 livePC.txt 讀取所有 IP 位址
with open('livePC.txt', 'r') as file:
    live_hosts = file.readlines()

# 清理換行符號
live_hosts = [host.strip() for host in live_hosts]

# 儲存掃描結果的資料結構
scan_results = []

# 執行 Nmap 掃描並解析結果
for ip in live_hosts:
    output_file = f"{ip}.xml"
    
    # 執行 Nmap 進行端口掃描
    command = f"nmap -T4 -vvv -oX {output_file} {ip}"
    os.system(command)
    print(f"Executing: {command}")
    
    # 解析 Nmap 生成的 XML 檔案
    tree = ET.parse(output_file)
    root = tree.getroot()
    
    open_ports = []
    
    # 找到所有開放的端口
    for port in root.findall(".//port"):
        state = port.find('state').get('state')
        if state == 'open':
            port_id = port.get('portid')
            open_ports.append(port_id)
    
    # 如果有開放的端口，將結果加入資料結構
    if open_ports:
        scan_results.append({
            '主機IP': ip,
            'PORT總數': len(open_ports),
            'PORT列表': ', '.join(open_ports)
        })

# 使用 pandas 將資料寫入 Excel
df = pd.DataFrame(scan_results)
excel_file = 'scan_results.xlsx'
df.to_excel(excel_file, index=False)

print(f"掃描完成，結果已儲存為 {excel_file}")
