import certstream
import json
import logging
import requests
import schedule
import sqlite3
import time
import threading
from urllib3.exceptions import InsecureRequestWarning
import tlsh
import dnstwist
import os
import sys

triggers = ["PUT", "KEYWORDS", "HERE"]
allowlist = ["KEYWORDS", "TO", "NOT", "TRIGGER", "ON"]
okta = ["$COMPANY","okta"]
zendesk = ["$COMPANY","zendesk"]
#This is a test list to confirm any changes work, change the below if statement as well so this works
keywords = ["google"]
dnstwist_domain = '$YOURDOMAIN'
lookalike_domains = []
#time to elapse to ignore new domains is 7 days
time_window = 604800
#time for database to hold domains before purge - 30 days
max_age = 2592000

#I do not want the list of domains printed
class Suppress_domain_list:
	def __enter__(self):
		self.original_stdout = sys.stdout
		sys.stdout = open(os.devnull, 'w')


	def __exit__(self,exc_type,exc_val,exc_tb):
		sys.stdout.close()
		sys.stdout = self.original_stdout

with Suppress_domain_list():
	domain_variants = dnstwist.run(domain=dnstwist_domain, registered=False, format='list', dictionary='phishWords.dict')
	pass   

for domain in domain_variants:
    if domain['domain'].startswith('xn--'):
        continue
    lookalike_domains.append(domain['domain'])

#time to elapse to ignore new domains is 7 days
time_window = 604800
#time for database to hold domains before purge - 30 days
max_age = 2592000


#make a database for storing everything
def initialize_db():
	conn = sqlite3.connect('seen_domains_tlsh.db', timeout=30)
	cursor = conn.cursor()
	cursor.execute('''
	CREATE TABLE IF NOT EXISTS domains (
		domain TEXT PRIMARY KEY,
		last_shown_time REAL,
		tlsh_hash TEXT,
		initial_finding_time REAL,
		hourly_tlsh_hashes TEXT,
		last_hash_check_time REAL
	)
	''')
	return conn, cursor

#trim the database of 30 day old domains
def trim_database():
	conn, cursor = initialize_db()
	cutoff = time.time() - max_age
	cursor.execute('DELETE FROM domains WHERE initial_finding_time < ?', (cutoff,))
	conn.commit()
	conn.close()

#does what is says
def compute_tlsh_hash(url):
	try:
		#We turned off ssl verification to catch self signed sites and I didnt like the errors
		requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
		response = requests.get(url, timeout=6, verify=False)
		content = response.content

		return tlsh.hash(content)
	except Exception as e:
		logging.error(f"Couldnt hash for {url} for some reason: {e}")
		return None

#does what is says checks for website changes
def check_website_changes():
	conn, cursor = initialize_db()
	current_time = time.time()
	cursor.execute('SELECT domain, tlsh_hash, initial_finding_time, hourly_tlsh_hashes, last_hash_check_time FROM domains')
	results = cursor.fetchall() #fetching all the data
	for domain, old_hash, initial_finding_time, hourly_tlsh_hashes, last_hash_check_time in results:
		if (current_time - initial_finding_time) <= time_window:
			new_hash = compute_tlsh_hash(f"https://{domain}")
			hourly_hashes = json.loads(hourly_tlsh_hashes) if hourly_tlsh_hashes else []
			if old_hash and new_hash:
				comparison_score = tlsh.diff(old_hash, new_hash)
				if comparison_score < 100:
					print(f"tlsh hash changed for domain: {domain} and has a score of {comparison_score} ")
				
				# Update the tlsh_hash in the domains table
				cursor.execute('''
				UPDATE domains SET tlsh_hash = ?, last_hash_check_time = ? WHERE domain = ?
				''', (new_hash, current_time, domain))
				conn.commit()

				hourly_hashes = json.loads(hourly_tlsh_hashes) if hourly_tlsh_hashes else []
			if new_hash not in hourly_hashes:
				hourly_hashes.append(new_hash)
			hourly_tlsh_hashes = json.dumps(hourly_hashes)
			cursor.execute('''
				UPDATE domains SET hourly_tlsh_hashes = ?, last_hash_check_time = ? WHERE domain = ?
				''', (hourly_tlsh_hashes, current_time, domain))
	conn.commit()
	conn.close()

#delaying the hashing because if the site has just been registered it probably doesnt even have data, so we give it a bit to get a parked page or something
def delayed_hashing(domain, last_shown_time, initial_finding_time):
	time.sleep(240) # 4 minutes to see if a page lands on it
	tlsh_hash = compute_tlsh_hash(f"https://{domain}")

	print(f"Certificate update for domain: {domain}, tlsh hash: {tlsh_hash}")

	conn,cursor = initialize_db()
	cursor.execute('''
	INSERT OR REPLACE INTO domains (domain, last_shown_time, tlsh_hash, initial_finding_time)
	VALUES (?, ?, ?, ?)
	''', (domain, last_shown_time, tlsh_hash, initial_finding_time))
	conn.commit()
	conn.close()

#where we get the certstream and only cert updates
def print_callback(message, context):
	logging.debug("Message -> {}".format(message))
	# Extract the certificate data from the message
	if message['message_type'] == "certificate_update":
		conn, cursor = initialize_db()
		leaf_cert = message['data']['leaf_cert']
		all_domains = leaf_cert['all_domains']
		current_time = time.time()
	
	
	for domain in all_domains:
		domain = domain.lstrip('*.')

			#if any(keyword in domain for keyword in keywords):
		if (all(okta in domain for okta in okta) or any(triggers in domain for triggers in triggers) or all(zendesk in domain for zendesk in zendesk) or any(lookalike_domains in domain for lookalike_domains in lookalike_domains)) and not any(allowlist in domain for allowlist in allowlist):
			# Check if the domain has been seen recently
			current_time = time.time()
			conn, cursor = initialize_db()
			cursor.execute('SELECT last_shown_time, initial_finding_time FROM domains WHERE domain=?', (domain,))
			result = cursor.fetchone()
			conn.close()
			
			if not result or (current_time - result[0]) >= time_window:
				last_shown_time = initial_finding_time = current_time if not result else result[0]
				threading.Thread(target=delayed_hashing, args=(domain, last_shown_time, initial_finding_time)).start()

	trim_database()
schedule.every(30).minutes.do(check_website_changes)

#how we schedule a hash recheck
def run_scheduler():
	while True:
		schedule.run_pending()
		time.sleep(1)
scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()


#This will get certstream and other errors, like database access, requests errors, etc.
logging.basicConfig(filename = 'certstream.log', format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)


certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')