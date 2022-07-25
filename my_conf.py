## тут название нужного устройства (можно узнать через скрипт get_dev.py)
#dev_name =   "Realtek RTL8723DE 802.11b/g/n PCIe Adapter"
## тут ip шлюза (роутер)
#gateway_ip = "192.168.0.1"
## тут нужно указать сканируемую сеть
#network =    "192.168.0.0/24"
## тут ip устройства у которого будем красть пакеты
#sniff_ip =   "192.168.0.102"
#filter =     f"icmp and (ip src {sniff_ip} or ip dst {sniff_ip})"
#dev_name =   "Realtek RTL8723DE 802.11b/g/n PCIe Adapter"

#dev_name =   "Realtek RTL8723DE 802.11b/g/n PCIe Adapter"
dev_name =   "Intel(R) Ethernet Connection (2) I219-V"
gateway_ip = "192.168.0.1"
network =    "192.168.0.0/24"
database =   "traffic.db"
filter =     "udp or tcp"

#dev_name =   "Realtek PCIe GbE Family Controller"
#gateway_ip = "10.13.10.1"
#network =    "10.13.10.0/24"
#filter =     "ip and ip src 192.168.0.102"

network_scan_interval = 2
arp_poison_interval = 1

report_name = "report.xlsx"

