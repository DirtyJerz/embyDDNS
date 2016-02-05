#!/usr/bin/python
import os, sys, sqlite3, base64, json, copy, subprocess, binascii, sys
import OpenSSL, acme.client, acme.messages
from datetime import datetime
from datetime import timedelta
from urllib2 import urlopen
#from acme import jose, client, messages, challenges
from acme import jose
from app import domain

#CA = "https://acme-staging.api.letsencrypt.org/directory"
#CA = "https://acme-v01.api.letsencrypt.org/directory"
CA = "http://127.0.0.1:4000/directory"
TERMS = "http://127.0.0.1:4001/terms/v1"
#TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

DOMAIN='.' + domain

ACCOUNT_KEY_SIZE = 2048

#LE based b64 encoding
def _b64(b):
	return base64.urlsafe_b64encode(b).decode('utf8').replace("=", "")	

#get a keypair for the user
#openssl genrsa 4096 > account.key
def _generateKeypair():
	key = OpenSSL.crypto.PKey()
	key.generate_key(OpenSSL.crypto.TYPE_RSA, ACCOUNT_KEY_SIZE)
	pem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
	print pem
	return base64.b64encode(pem)

#store keypair for the user
def _storeKeypair(hostname, acct_privkey, csr_privkey):
	conn=sqlite3.connect('app/embyDDNS.db')
	c=conn.cursor()
	c.execute("INSERT INTO users (hostname, acct_privkey, csr_privkey, last_update) VALUES ('{0}', '{1}', '{2}', '{3}');".format(hostname, acct_privkey, csr_privkey, datetime.now()))
	conn.commit()
	conn.close()

#update records in the DB
def _updateHost(hostname, field, value):
	conn=sqlite3.connect('app/embyDDNS.db')
	c=conn.cursor()
	c.execute("UPDATE users SET {0} = '{1}', last_update = '{2}' WHERE hostname = '{3}';".format(field, value, datetime.now(), hostname))
	conn.commit()
	conn.close()

#recall keypair for user
def _recallHost(hostname):
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

def _send_signed_request(url, payload, hostname):
		info = _recallHost(hostname)
		key=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(info['acct_privkey']))
		print key.keydata()
		header = {
		"alg": "RS256",
		"jwk": {
				"e": _b64(key.e),
				"kty": "RSA",
				"n": _b64(key.n),
			},
		}
		payload64 = _b64(json.dumps(payload).encode('utf8'))
		signer= key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
		signer.update(payload64.encode('utf-8'))
		signature=signer.finalize()
		message=json.dumps({"header":header, "payload":payload64, "signature":signature})
		resp = urlopen(url, data.encode('utf8'))
		return resp.getcode(), resp.read()

def _register(hostname):
	existing_regr = None
	#see if hostname exists in our DB
	info = _recallHost(hostname)
	if info == None:
		_storeKeypair(hostname, _generateKeypair(), _generateKeypair())
		info = _recallHost(hostname)
	key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(info['acct_privkey']))
	client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
	print client
	if info['reg_json'] == None:
		# Create a new registration.
		print ("Registering a new account with Let's Encrypt.")
		regr = client.register()
	else:
		print ("Validating existing account for hostname %s." % hostname)

		# Validate existing registration by querying for it from the server.
		regr = acme.messages.RegistrationResource.json_loads(info['reg_json'])
		existing_regr = regr.json_dumps()
		try:
			regr = client.query_registration(regr)
		except acme.messages.Error as e:
			if e.typ == "urn:acme:error:unauthorized":
				# There is a problem accessing our own account. This probably
				# means the stored registration information is not valid.
				raise AccountDataIsCorrupt(storage)
			raise

	# If this call is to agree to a terms of service agreement, update the
	# registration.
	regr = client.update_registration(regr.update(body=regr.body.update(agreement=TERMS)))

	# Write new or updated registration (if it changed, and hopefully json_dumps is stable).
	if existing_regr != regr.json_dumps():
		if existing_regr is not None:
			print ("Saving updated account information.")
		_updateHost(hostname, 'reg_json', regr.json_dumps_pretty())
	return regr

def _getChallenges(hostname):
	# Load the cache of challenges.
	# Load any existing challenges we've requested for domains so we
	# can track the challenges we've requested across sessions.
	challenges = []
	domain = hostname + DOMAIN
	info = _recallHost(hostname)
	key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
	client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
	regr = acme.messages.RegistrationResource.json_loads(info['reg_json'])
	if not info['authz_json'] == None:
		challenges = json.loads(info['authz_json'])

	# Convert from JSON to ACME objects.
	for i in range(len(challenges)):
		challenges[i] = acme.messages.AuthorizationResource.from_json(challenges[i])

	# Drop any challenges that have expired or have been revoked.
	challenges = [challg for challg in challenges if not challg.body.status.name == "revoked" and ((challg.body.expires.replace(tzinfo=None)-datetime.now()) > timedelta(seconds=60))]

	# If challenges exist for this domain, reuse it.
	# We've already dropped expired and revoked challenges, so we don't have
	# to check that here.
	for i, challg in enumerate(challenges):
		if challg.body.identifier.typ.name == "dns" and challg.body.identifier.value == domain:
			print ("Reusing existing challenges for %s." % domain)

			# Refresh the record because it may have been updated with validated challenges.
			try:
				challg, resp = client.poll(challg)
			except acme.messages.Error as e:
				if e.typ in ("urn:acme:error:unauthorized", "urn:acme:error:malformed"):
					# There is a problem accessing our own account. This probably
					# means the stored registration information is not valid.
					raise AccountDataIsCorrupt(challenges_file)
				raise

			# Check that the refreshed record is still valid.
			if  not challg.body.status.name == "revoked" and ((challg.body.expires.replace(tzinfo=None)-datetime.now()) > timedelta(seconds=60)):
				# If so, keep it.
				challenges[i] = challg
				break
	else:
		# None found.
		challg = None
		resp = None

	if challg is None:
		# Get new challenges for a domain.
		print ("Requesting new challenges for %s." % domain)
		try:
			challg = client.request_domain_challenges(domain, regr.new_authzr_uri)
		except acme.messages.Error as e:
			#if e.typ == "urn:acme:error:malformed":
				#print e.detail
			print e.detail
			raise

		# Add into our existing challenges.
		challenges.append(challg)

	# Write a cache of challenges.
	_updateHost(hostname, 'authz_json', json.dumps([c.to_json() for c in challenges], sort_keys=True, indent=4))
	

	# Return the new challenges for this domain, and if we updated it,
	# then the response object so we can know how long to wait before
	# polling again.
	return (challg, resp)

def getDNSToken(hostname):
	try:
		_register(hostname)
		_getChallenges(hostname)
		info = _recallHost(hostname)
		key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
		client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
		regr = acme.messages.RegistrationResource.json_loads(info['reg_json'])
		authz = json.loads(info['authz_json'])
		answer={}
		for i in range(len(authz)):
			for j in range(len(authz[i]['body']['challenges'])):
				if authz[i]['body']['challenges'][j]['type'] == "dns-01":
					answer=authz[i]['body']['challenges'][j]
					jwk=jose.jwk.JWK.load(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
					h = hmac.HMAC(key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()), hashes.SHA256(), backend=default_backend())
					h.update(str(answer['token'] + '.' + _b64(jwk.thumbprint())))
					keyAuthorization = _b64(h.finalize())
					return keyAuthorization


		
		return {'Error':'No DNS-01 challenge received'}
	except Exception, e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
		return {'Error':e.message}

		
def submit_domain_validation(hostname):
	# try:
	_register(hostname)
	_getChallenges(hostname)
	info = _recallHost(hostname)
	key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
	client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
	regr = acme.messages.RegistrationResource.json_loads(info['reg_json'])
	authz = json.loads(info['authz_json'])
	answer={}
	for i in range(len(authz)):
		for j in range(len(authz[i]['body']['challenges'])):
			if authz[i]['body']['challenges'][j]['type'] == "dns-01":
				answer=authz[i]['body']['challenges'][j]
				jwk=jose.jwk.JWK.load(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
				h = hmac.HMAC(key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()), hashes.SHA256(), backend=default_backend())
				h.update(str(answer['token'] + '.' + _b64(jwk.thumbprint())))
				keyAuthorization = _b64(h.finalize())
				payload={"keyAuthorization":keyAuthorization}
				code, resp=_send_signed_request(answer['uri'], payload, hostname)
				print 'here'
				print jws

	
	return {'Error':'No DNS-01 challenge received'}
	# except Exception, e:
	# 	print {'Er':e.message}
	# 	return {'Error':e.message}


def getCertificate(hostname):
	return 0
	#register with LE
	#register('host9')

	#get challenges
	#getChallenges('host9')

	#submit challenge
#submit_domain_validation('host9')

#print getDNSToken('host9')
	#generate CSR

	#submit CSR

	#get certificate

