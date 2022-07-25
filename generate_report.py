import datetime as dt
import json
import mitm_sniff
import xlsxwriter as xlsx
import my_conf

def get_dates(db):
	return db.cursor().execute("""
	select distinct date(when_sent)
	from packet
	""")

def get_packet_stats(db, date):
	return db.cursor().execute("""
	select
		from_device,
		date(when_sent) as date_sent,
		strftime("%H", when_sent) as hour_sent,
		count(*) as packet_count
	from packet
	where date_sent == ?
	group by from_device, hour_sent
	order by hour_sent, from_device, packet_count
	""", (date, ))

if __name__ == "__main__":
	db = mitm_sniff.db_open()
	wb = xlsx.Workbook(my_conf.report_name)
	for date, in get_dates(db):
		devices = {}
		for device, date, hour, count in get_packet_stats(db, date):
			if device not in devices:
				devices[device] = {}
				for i in range(0, 24):
					devices[device][f"{i:02}"] = 0
			devices[device][hour] = count
		ws = wb.add_worksheet(date)
		for i in range(0, 24):
			ws.write(1 + i, 0, f"{i:02} - {i+1:02}")
		device_index = 1
		for device in devices:
			ws.write(0, device_index, device)
			packets = list(devices[device].values())
			ws.write_column(1, device_index, packets)
			device_index += 1
		ws.set_column(1, device_index + 1, 16)

	wb.close()

