#!/usr/bin/python
from flask import Flask
import os, sqlite3, subprocess


myapp = Flask(__name__)
domain = 'ddns.oakington.info'
myapp.config['PROPOGATE_EXCEPTIONS'] = True

#check to see if we have a database yet
if not os.path.isfile('app/embyDDNS.db'):	
	conn=sqlite3.connect('app/embyDDNS.db')
	c=conn.cursor()
	c.execute('''CREATE TABLE users (hostname text, acct_privkey text, \
			csr_privkey text, reg_json text, authz_json text, certificate text, certificate_chain text, last_update text)''')
	conn.commit()
	conn.close()

##KEY GENERATION
# openssl genrsa -out keys/private.pem 2048
# openssl rsa -in keys/private.pem -out keys/private_key.pem -outform PEM
# openssl rsa -in keys/private_key.pem -RSAPublicKey_out -out keys/public_key.pem
if not os.path.exists('app/keys'):
	os.makedirs('app/keys')
if not os.path.isfile('app/keys/private.pem'):
	print subprocess.call(['openssl','genrsa', '-out', 'app/keys/private.pem', '2048'])
if not os.path.isfile('app/keys/private_key.pem'):
	print subprocess.call(['openssl','rsa', '-in', 'app/keys/private.pem', '-out', 'app/keys/private_key.pem', '-outform', 'PEM'])
if not os.path.isfile('app/keys/public_key.pem'):
	print subprocess.call(['openssl','rsa', '-in', 'app/keys/private_key.pem', '-RSAPublicKey_out', '-out', 'app/keys/public_key.pem'])

from api import embyapi
myapp.register_blueprint(embyapi)

if __name__ == "__main__":
    myapp.run(host='0.0.0.0', port=5000)
