import certstream
import json
import logging
import requests
import schedule
import ppdeep
import sqlite3
import time
import threading
from urllib3.exceptions import InsecureRequestWarning


triggers = ["PUT", "KEYWORDS", "HERE"]
allowlist = ["KEYWORDS", "TO", "NOT", "TRIGGER", "ON"]
okta = ["$COMPANY","okta"]
zendesk = ["$COMPANY","zendesk"]
#This is a test list to confirm any changes work, change the below if statement as well so this works
keywords = ["google"]


#time to elapse to ignore new domains is 7 days
time_window = 604800
#time for database to hold domains before purge - 30 days
max_age = 2592000

#requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def initialize_db():
	conn = sqlite3.connect('seen_domains_ssdeep_fixed.db')
	cursor = conn.cursor()
	cursor.execute('''
	CREATE TABLE IF NOT EXISTS domains (
		domain TEXT PRIMARY KEY,
		last_shown_time REAL,
		ssdeep_hash TEXT,
		initial_finding_time REAL,
		hourly_ssdeep_hashes TEXT,
		last_hash_check_time REAL
	)
	''')
	return conn, cursor

def trim_database():
	conn, cursor = initialize_db()
	cutoff = time.time() - max_age
	cursor.execute('DELETE FROM domains WHERE last_shown_time < ?', (cutoff,))
	conn.commit()
	conn.close()

def compute_ssdeep_hash(url):
	try:
		requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
		response = requests.get(url, timeout=6, verify=False)
		content = response.text

		return ppdeep.hash(content)
	except Exception as e:
		logging.error(f"Couldnt hash for {url} for some reason: {e}")
		return None

def check_website_changes():
	conn, cursor = initialize_db()
	current_time = time.time()
	cursor.execute('SELECT domain, ssdeep_hash, initial_finding_time, hourly_ssdeep_hashes, last_hash_check_time FROM domains')
	results = cursor.fetchall()
	for domain, old_hash, initial_finding_time, hourly_ssdeep_hashes, last_hash_check_time in results:
		if (current_time - initial_finding_time) <= time_window:
			new_hash = compute_ssdeep_hash(f"https://{domain}")
			hourly_hashes = json.loads(hourly_ssdeep_hashes) if hourly_ssdeep_hashes else []
			if old_hash and new_hash:
				comparison_score = ppdeep.compare(old_hash, new_hash)
				print (f"Old Hash Check{new_hash}")
				if comparison_score >= 30:
					print(f"ssdeep hash changed for domain: {domain} and has a score of {comparison_score} ")
				
				# Update the ssdeep_hash in the domains table
				cursor.execute('''
				UPDATE domains SET ssdeep_hash = ?, last_hash_check_time = ? WHERE domain = ?
				''', (new_hash, current_time, domain))
				conn.commit()

				hourly_hashes = json.loads(hourly_ssdeep_hashes) if hourly_ssdeep_hashes else []
			if new_hash not in hourly_hashes:
				hourly_hashes.append(new_hash)
			hourly_ssdeep_hashes = json.dumps(hourly_hashes)
			cursor.execute('''
				UPDATE domains SET hourly_ssdeep_hashes = ?, last_hash_check_time = ? WHERE domain = ?
				''', (hourly_ssdeep_hashes, current_time, domain))
	conn.commit()
	conn.close()

def print_callback(message, context):
	logging.debug("Message -> {}".format(message))
	# Extract the certificate data from the message
	if message['message_type'] == "certificate_update":
		conn, cursor = initialize_db()
		leaf_cert = message['data']['leaf_cert']
		all_domains = leaf_cert['all_domains']
		current_time = time.time()
	
	
	for domain in all_domains:
		if domain.startswith('*.'):
			domain = domain[2:]

    	#if any(keyword in domain for keyword in keywords):
        if (all(okta in domain for okta in okta) or any(triggers in domain for triggers in triggers) or all(zendesk in domain for zendesk in zendesk)) and not any(allowlist in domain for allowlist in allowlist):
			# Check if the domain has been seen recently
			cursor.execute('SELECT last_shown_time, initial_finding_time, hourly_ssdeep_hashes FROM domains WHERE domain=?', (domain,))
			result = cursor.fetchone()
			
			if not result or (current_time - last_shown_time) >= time_window:
				# Compute the ssdeep hash of the website content
				ssdeep_hash = compute_ssdeep_hash(f"https://{domain}")

				if not result:
					last_shown_time = initial_finding_time = current_time

				else:
					last_shown_time = current_time
					initial_finding_time = result[1]
				
				hourly_hashes = json.loads(result[2]) if result and result[2] else []

				hourly_hashes.append(ssdeep_hash)
				hourly_ssdeep_hashes = json.dumps(hourly_hashes)

				#if new_hash not in hourly_hashes:
				#	hourly_hashes.append(new_hash)
				
				
				
				print(f"Certificate update for domain: {domain}, ssdeep hash: {ssdeep_hash}")
				
				# Update the database with the domain, current timestamp, and ssdeep hash
				cursor.execute('''
				INSERT OR REPLACE INTO domains (domain, last_shown_time, ssdeep_hash, initial_finding_time, hourly_ssdeep_hashes, last_hash_check_time)
				VALUES (?, ?, ?, ?, ?, ?)
				''', (domain, last_shown_time, ssdeep_hash, initial_finding_time, hourly_ssdeep_hashes, current_time))
				conn.commit()
	conn.close()
	trim_database()
schedule.every(30).seconds.do(check_website_changes)

def run_scheduler():
	while True:
		schedule.run_pending()
		time.sleep(1)
scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()



logging.basicConfig(filename = 'certstream.log', format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
#Set logging level to Critical so we dont get annoying reconect messages
#logging.getLogger("certstream").setLevel(logging.INFO)

certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
