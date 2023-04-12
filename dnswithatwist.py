import certstream
import json
import logging
import requests
import schedule
import ppdeep
import psycopg2
import time
from urllib3.exceptions import InsecureRequestWarning
import os
import sys
import dnstwist
import tlsh
import re
import nltk
from nltk.corpus import words
import concurrent.futures
import threading
import random
import queue

nltk.download("words")

english_words = set(words.words())


YOURECOMPANYHEREwords = ["COMPANY", "KEYWORDS", "HERE"]
allowlists = ["DOMAINS","TO","IGNORE"
]
specific_lists = [
	["COMPANY", "okta"],
	["COMPANY", "zendesk"],
]
# This is a test list to confirm any changes work, change the below if statement as well so this works
keywords = ["google"]


lookalike_domains = []


# I do not want the list of domains printed
class Suppress_domain_list:
	def __enter__(self):
		self.original_stdout = sys.stdout
		sys.stdout = open(os.devnull, "w")

	def __exit__(self, exc_type, exc_val, exc_tb):
		sys.stdout.close()
		sys.stdout = self.original_stdout


with Suppress_domain_list():
	domain_variants = dnstwist.run(
		domain="YOURECOMPANYHERE.com",
		registered=False,
		format="list",
		fuzzers="addition,bitsquatting,dictionary,homoglyph,insertion,repetition,transposition",
		dictionary="phishWords.dict",
	)
	pass


for domain in domain_variants:
	if domain["domain"].startswith("xn--"):
		continue
	domain, _ = domain["domain"].split(".", 1)
	if domain.startswith("ch") and domain not in english_words:
		lookalike_domains.append(domain)
# regexMe = '|'.join(re.escape(domain) for domain in lookalike_domains)
special_pattern_lookalike_domains = r"\b(?:{})\b".format(
	"|".join(re.escape(lookalike_domain) for lookalike_domain in lookalike_domains)
)
print(special_pattern_lookalike_domains)
# time to elapse to ignore new domains is 7 days
time_window = 604800
# time for database to hold domains before purge - 30 days
max_age = 2592000


# psql stuff
db_name = "certstream"
db_user = "catcherinthedns"
# Nothing in this needs a pass anyway
db_password = os.environ['DB_PASSWORD']
db_host = "127.0.0.1"
db_port = "5432"


def contains_all_keywords(domain, specific_lists):
	if not isinstance(specific_lists, list) or not all(
		isinstance(kw, str) for kw in specific_lists
	):
		return False
	for specific_list in specific_lists:
		pattern = r"\b" + re.escape(specific_list) + r"\b"
		if not re.search(pattern, domain):
			return False
	return True


def contains_any_keywords(domain, YOURECOMPANYHEREwords):
	if not isinstance(YOURECOMPANYHEREwords, list) or not all(
		isinstance(kw, str) for kw in YOURECOMPANYHEREwords
	):
		return False
	for YOURECOMPANYHEREword in YOURECOMPANYHEREwords:
		pattern = r"\b" + re.escape(YOURECOMPANYHEREwords) + r"\b"
		if re.search(pattern, domain):
			return True
	return False


def pgsql_connection():
	try:
		conn = psycopg2.connect(
			dbname=db_name,
			user=db_user,
			password=db_password,
			host=db_host,
			port=db_port,
		)
		return conn
	except psycopg2.Error as e:
		print(f"Couldnt Connect to DB: {e}")
		return None


def trim_database():

	# Establish a connection to the PostgreSQL database using the pgsql_connection function
	conn = pgsql_connection()

	if conn:
		cursor = conn.cursor()
		cutoff = time.time() - max_age
		# Replace the '?' placeholder with '%s'
		cursor.execute("DELETE FROM domains WHERE initial_finding_time < %s", (cutoff,))
		conn.commit()

		# Close the connection to the database
		cursor.close()
		conn.close()
	else:
		print("Could not establish a connection to the PostgreSQL database.")


def is_valid_hash(tlsh_hash):
	if len(tlsh_hash) != 72:
		return False
	if re.match('T[0-9a-fA-F]*$',tlsh_hash):
		return True 
	return False


# does what is says
def compute_tlsh_hash(url):
	try:
		# We turned off ssl verification to catch self signed sites and I didnt like the errors
		requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
		response = requests.get(url, timeout=6, verify=False)
		content = response.content

		return tlsh.hash(content)
	except Exception as e:
		logging.error(f"Couldnt hash for {url} for some reason: {e}")
		return None


write_queue = queue.Queue()


def writer_thread():
	# Define the PostgreSQL connection parameters

	while True:
		query, params = write_queue.get()

		# Establish a connection to the PostgreSQL database using the pgsql_connection function
		conn = pgsql_connection()

		if conn:
			cursor = conn.cursor()
			cursor.execute(query, params)
			conn.commit()

			# Close the connection to the database
			cursor.close()
			conn.close()

		write_queue.task_done()


threading.Thread(target=writer_thread, daemon=True).start()


# does what is says checks for website changes
def check_website_changes():

	# Establish a connection to the PostgreSQL database using the pgsql_connection function
	conn = pgsql_connection()

	if conn:
		cursor = conn.cursor()
		current_time = time.time()
		cursor.execute(
			"SELECT domain, tlsh_hash, initial_finding_time, hourly_tlsh_hashes, last_hash_check_time FROM domains"
		)
		results = cursor.fetchall()  # Fetching all the data

		for (
			domain,
			old_hash,
			initial_finding_time,
			hourly_tlsh_hashes,
			last_hash_check_time,
		) in results:
			if (current_time - initial_finding_time) <= time_window:
				new_hash = compute_tlsh_hash(f"https://{domain}")
				hourly_hashes = (
					json.loads(hourly_tlsh_hashes) if hourly_tlsh_hashes else []
				)
				if old_hash and new_hash:
					if is_valid_hash(old_hash) and is_valid_hash(new_hash):
						comparison_score = tlsh.diff(old_hash, new_hash)
						if comparison_score > 60:
							print(
								f"tlsh hash changed for domain: {domain} and has a score of {comparison_score} "
							)
					else:
						print("Invalid Hashes")
				write_query = """
				UPDATE domains SET tlsh_hash = %s, last_hash_check_time = %s WHERE domain = %s
				"""
				write_params = (new_hash, current_time, domain)
				write_queue.put((write_query, write_params))

				hourly_hashes = (
					json.loads(hourly_tlsh_hashes) if hourly_tlsh_hashes else []
				)
				if new_hash not in hourly_hashes:
					hourly_hashes.append(new_hash)
				hourly_tlsh_hashes = json.dumps(hourly_hashes)
				write_query = """
				UPDATE domains SET hourly_tlsh_hashes = %s, last_hash_check_time = %s WHERE domain = %s
				"""
				write_params = (hourly_tlsh_hashes, current_time, domain)
				write_queue.put((write_query, write_params))

		# Close the connection to the database
		cursor.close()
		conn.close()
	else:
		print("Could not establish a connection to the PostgreSQL database.")


# delaying the hashing because if the site has just been registered it probably doesnt even have data, so we give it a bit to get a parked page or something
def delayed_hashing(domain, last_shown_time, initial_finding_time):
	time.sleep(240)  # 4 minutes to see if a page lands on it
	tlsh_hash = compute_tlsh_hash(f"https://{domain}")

	print(f"Certificate update for domain: {domain}, tlsh hash: {tlsh_hash}")


	# Establish a connection to the PostgreSQL database using the pgsql_connection function
	conn = pgsql_connection()

	if conn:
		cursor = conn.cursor()
		cursor.execute(
			"""
			INSERT INTO domains (domain, last_shown_time, tlsh_hash, initial_finding_time)
			VALUES (%s, %s, %s, %s)
			ON CONFLICT (domain) DO UPDATE SET
				last_shown_time = EXCLUDED.last_shown_time,
				tlsh_hash = EXCLUDED.tlsh_hash,
				initial_finding_time = EXCLUDED.initial_finding_time
			""",
			(domain, last_shown_time, tlsh_hash, initial_finding_time),
		)
		conn.commit()

		# Close the connection to the database
		cursor.close()
		conn.close()


# where we get the certstream and only cert updates
def print_callback(message, context):
    if message["message_type"] == "certificate_update":
        
        # Establish a connection to the PostgreSQL database using the connect_to_postgresql function
        conn = pgsql_connection()
        if conn:
            cursor = conn.cursor()
            leaf_cert = message["data"]["leaf_cert"]
            all_domains = leaf_cert["all_domains"]
            current_time = time.time()
            conn.commit()

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                for domain in all_domains:
                    domain = domain.lstrip("*.")
                    
                    # Code logic to check domain against keywords, allowlists, etc.
                    if (contains_all_keywords(domain, specific_lists) or
                        contains_any_keywords(YOURECOMPANYHEREwords, domain) or
                        re.search(special_pattern_lookalike_domains, domain)) and \
                        not any(allowlist in domain for allowlist in allowlists):
                    #if any(keyword in domain for keyword in keywords):   
                        cursor.execute(
                            "SELECT last_shown_time, initial_finding_time FROM domains WHERE domain=%s",
                            (domain,)
                        )
                        result = cursor.fetchone()

                        if not result or (current_time - result[0]) >= time_window:
                            last_shown_time = initial_finding_time = (
                                current_time if not result else result[0]
                            )
                            # Submit the delayed_hashing function to the executor
                            executor.submit(
                                delayed_hashing, domain, last_shown_time, initial_finding_time
                            )
                    
            # Close the cursor and connection
            cursor.close()
            conn.close()


schedule.every(90).minutes.do(check_website_changes)
# 		trim_database()
# schedule.every(30).seconds.do(check_website_changes)


# how we schedule a hash recheck
def run_scheduler():
	while True:
		schedule.run_pending()
		time.sleep(1)


scheduler_thread = threading.Thread(target=run_scheduler)
scheduler_thread.start()


# This will get certstream and other errors, like database access, requests errors, etc.
# logging.basicConfig(filename = 'certstream_addDNSTWIST.log', format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
logging.basicConfig(
	filename="certStream.log",
	format="[%(levelname)s:%(name)s] %(asctime)s - %(message)s",
	level=logging.INFO,
)
certstream.listen_for_events(print_callback, url="wss://certstream.calidog.io/")
