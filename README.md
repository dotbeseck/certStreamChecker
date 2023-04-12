# certStreamChecker
Just a Python script that watches certStream for keywords, and ssdeep or tlsh hashes the sites to compare later. Will add more as I build upon it


Have added in a dnstwist generator for typosquatted lists. Youll need your own dictionary if you want more than standard dnstwist. You also need to add your own keywords or company domain to the script for it to work Looking for `YOURCOMPANYHERE` in the script, then follow the below

To use this you need to have postgreSQL installed and a Database created:

Go to your new database: psql $YOURDATABASE

Use this to create the needed Table: CREATE TABLE domains ( domain VARCHAR(255) PRIMARY KEY, last_shown_time DOUBLE PRECISION, tlsh_hash VARCHAR(255), initial_finding_time DOUBLE PRECISION, hourly_tlsh_hashes TEXT, last_hash_check_time DOUBLE PRECISION );

Use this to create the role (user): CREATE ROLE catcherinthedns;

Use this to set a password: ALTER ROLE catcherInTheDNS WITH PASSWORD 'PASSWORD';

Use this to set the permissions: GRANT SELECT, INSERT, UPDATE, DELETE, LOGIN ON TABLE domains TO catcherinthedns;

Set password as environment variable: echo 'export DB_PASSWORD=$SOMEPASSWORD' >> ~/.zshrc and source ~/.zshrc

Setup a virtualenv: virtualenv dnswithatwist

Activate: source dnswithatwist/bin/activate

Install required packages: python -m pip install -r requirements.txt

Run the script: python -m dnswithatwist
