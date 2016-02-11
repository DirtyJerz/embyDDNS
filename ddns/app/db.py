#!/usr/bin/python
import os, sys, sqlite3, base64, OpenSSL, logging
from datetime import datetime

logger = logging.getLogger(__name__)

ACCOUNT_KEY_SIZE = 2048

#get a keypair for the user
#openssl genrsa 4096 > account.key
def generateKeypair():
	key = OpenSSL.crypto.PKey()
	key.generate_key(OpenSSL.crypto.TYPE_RSA, ACCOUNT_KEY_SIZE)
	pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
	return base64.b64encode(pem)

#store keypair for the user
def storeKeypair(hostname, acct_privkey, csr_privkey):
	conn=sqlite3.connect('app/embyDDNS.db')
	c=conn.cursor()
	c.execute("INSERT INTO users (hostname, acct_privkey, csr_privkey, last_update) VALUES ('{0}', '{1}', '{2}', '{3}');".format(hostname, acct_privkey, csr_privkey, datetime.now()))
	conn.commit()
	conn.close()
	logger.debug('stored new keypair for subdomain {}'.format(hostname))

#update records in the DB
def updateHost(hostname, field, value):
	conn=sqlite3.connect('app/embyDDNS.db')
	c=conn.cursor()
	c.execute("UPDATE users SET {0} = '{1}', last_update = '{2}' WHERE hostname = '{3}';".format(field, value, datetime.now(), hostname))
	conn.commit()
	conn.close()

#recall keypair for user
def recallHost(hostname):
	conn=sqlite3.connect('app/embyDDNS.db')
	conn.row_factory = sqlite3.Row
	c=conn.cursor()
	c.execute("SELECT * FROM users WHERE hostname = '{0}'".format(hostname))
	row=c.fetchone()
	conn.commit()
	conn.close()
	if row is None:
		return None
	return row