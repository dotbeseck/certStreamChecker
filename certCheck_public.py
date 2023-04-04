import certstream
import json
import logging
import requests
import schedule
import ppdeep
import sqlite3
import time
import threading


triggers = ["PUT", "KEYWORDS", "HERE"]
allowlist = ["KEYWORDS", "TO", "NOT", "TRIGGER", "ON"]
okta = ["$COMPANY","okta"]
#This is a test list to confirm any changes work, change the below if statement as well so this works
#keywords = ["google"]

conn = sqlite3.connect('seen_domains_ssdeep_fixed.db')
cursor = conn.cursor()
#time to elapse to ignore new domains is 7 days
time_window = 604800
#time for database to hold domains before purge - 30 days
max_age = 2592000

cursor.execute('''
CREATE TABLE IF NOT EXISTS domains (
    domain TEXT PRIMARY KEY,
    last_shown_time REAL,
    ssdeep_hash TEXT,
    hourly_ssdeep_hashes TEXT
)
''')

def trim_database():
	cutoff = time.time() - max_age

	cursor.execute('DELETE FROM domains WHERE last_shown_time < ?', (cutoff,))
	conn.commit()

def compute_ssdeep_hash(url):
	try:
		response = requests.get(url, timeout=6)
		content = response.text

		return ppdeep.hash(content)
	except Exception as e:
		logging.error(f"Couldnt hash for {url} for some reason: {e}")
		return None

def check_website_changes():
    current_time = time.time()
    cursor.execute('SELECT domain, ssdeep_hash, hourly_ssdeep_hashes FROM domains')
    results = cursor.fetchall()
    for domain, old_hash, last_shown_time, hourly_ssdeep_hashes in results:
        if (current_time - last_shown_time) <= time_window:
            new_hash = compute_ssdeep_hash(f"https://{domain}")
            score = ppdeep.compare(old_hash, new_hash)
            if score >= 30:
                print(f"ssdeep hash changed for domain: {domain} and has a score of {score} ")
                
                # Update the ssdeep_hash in the domains table
                cursor.execute('''
                UPDATE domains SET ssdeep_hash = ? WHERE domain = ?
                ''', (new_hash, domain))
                conn.commit()

                hourly_hashes = json.loads(hourly_ssdeep_hashes) if hourly_ssdeep_hashes else []
                hourly_hashes.append(new_hash)
                hourly_ssdeep_hashes = json.dumps(hourly_hashes)
                cursor.execute('''
                    UPDATE domains SET hourly_ssdeep_hashes = ? WHERE domain = ?
                    ''', (hourly_ssdeep_hashes, domain))
                conn.commit()

def print_callback(message, context):
    #logging.debug("Message -> {}".format(message))
    if message['message_type'] == "certificate_update":
        leaf_cert = message['data']['leaf_cert']
        all_domains = leaf_cert['all_domains']
        current_time = time.time()
    
    
    for domain in all_domains:
    	#if any(keyword in domain for keyword in keywords):
        if (all(okta in domain for okta in okta) or any(triggers in domain for triggers in triggers)) and not any(allowlist in domain for allowlist in allowlist):
            # Check if the domain has been seen recently
            cursor.execute('SELECT last_shown_time, hourly_ssdeep_hashes FROM domains WHERE domain=?', (domain,))
            result = cursor.fetchone()
            last_shown_time = result[0] if result else 0
            hourly_ssdeep_hashes = result[1] if result else None
            
            if not result or (current_time - last_shown_time) >= time_window:
                # Compute the ssdeep hash of the website content
                ssdeep_hash = compute_ssdeep_hash(f"https://{domain}")
                
                hourly_hashes = json.loads(hourly_ssdeep_hashes) if hourly_ssdeep_hashes else []
                
                # Append the new hash to the list
                hourly_hashes.append(ssdeep_hash)
                
                hourly_ssdeep_hashes = json.dumps(hourly_hashes)
                
                print(f"Certificate update for domain: {domain}, ssdeep hash: {ssdeep_hash}")
                
                # Update the database with the domain, current timestamp, and ssdeep hash
                cursor.execute('''
                INSERT OR REPLACE INTO domains (domain, last_shown_time, ssdeep_hash, hourly_ssdeep_hashes)
                VALUES (?, ?, ?, ?)
                ''', (domain, current_time, ssdeep_hash, hourly_ssdeep_hashes))
                conn.commit()

schedule.every().hour.do(check_website_changes)

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(1)
        scheduler_thread = threading.Thread(target=run_scheduler)
        scheduler_thread.start()

trim_database()

#Set logging level to Critical so we dont get annoying reconect messages
logging.getLogger("certstream").setLevel(logging.CRITICAL)


certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')

conn.close()
