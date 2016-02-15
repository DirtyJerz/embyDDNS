#!/usr/bin/python
import os, sys, base64, json, OpenSSL, acme.client, acme.messages, requests, logging, db, hashlib, time, textwrap
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Util import asn1
from datetime import datetime, timedelta
from acme import jose
from app import domain

logger = logging.getLogger(__name__)

#CA = "https://acme-staging.api.letsencrypt.org/directory"
#CA = "https://acme-v01.api.letsencrypt.org/directory"
CA = "http://127.0.0.1:4000/directory"
TERMS = "http://127.0.0.1:4001/terms/v1"
#TERMS = "https://letsencrypt.org/documents/LE-SA-v1.0.1-July-27-2015.pdf"

DOMAIN='.' + domain

#LE b64 encoding
def _b64(b):
	return base64.urlsafe_b64encode(b).decode('ascii').replace("=", "")

def _get_link(header, type):
	links = (header or '').split(',')
	for link in links:
		link = link.strip()
		if type in link:
			return link[1:link.index('>')]

def _send_signed_request(url, payload, hostname, headers={'Content-Type': 'application/json'}):
	info = db.recallHost(hostname)
	priv=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(info['acct_privkey']))
	key=serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']), password=None, backend=default_backend()) 
	header = {
	"alg": "RS256",
	"jwk": jose.JWKRSA(key=jose.ComparableRSAKey(key.public_key())).to_partial_json(),
	}
	payload64 = _b64(json.dumps(payload).encode('utf8'))
	protected64 = _b64(json.dumps({"nonce":requests.get(CA).headers['Replay-Nonce'].encode('utf8')}))
	signature64 = _b64(OpenSSL.crypto.sign(priv, str(protected64) + '.' + str(payload64), 'sha256'))
	message=json.dumps({"header":header,"protected":protected64, "payload":payload64, "signature":signature64})
	resp = requests.post(url, data=message, headers=headers)
	return resp

def _register(hostname):
	existing_regr = None
	#see if hostname exists in our DB
	logger.debug('Recalling Host')
	info = db.recallHost(hostname)
	if info == None:
		logger.debug('Host not found in DB. Creating new entry')
		db.storeKeypair(hostname, db.generateKeypair(), db.generateKeypair())
		info = db.recallHost(hostname)
	key=serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
	client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
	if info['reg_json'] == None:
		# Create a new registration.
		logger.info("Registering a new account with Let's Encrypt.")
		regr = client.register()
	else:
		logger.info("Validating existing account for hostname %s." % hostname)

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
			logger.info("Saving updated account information.")
		db.updateHost(hostname, 'reg_json', regr.json_dumps_pretty())
	
def _getChallenges(hostname):
	# Load the cache of challenges.
	# Load any existing challenges we've requested for domains so we
	# can track the challenges we've requested across sessions.
	challenges=[]
	domain = hostname + DOMAIN
	info = db.recallHost(hostname)
	key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
	client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
	regr = acme.messages.RegistrationResource.json_loads(info['reg_json'])

	if info['authz_json'] == None:
		# None found.
		logger.info("No Challenges found")
		logger.info("Requesting new challenges for %s." % hostname)
		authz = client.request_domain_challenges(domain, regr.new_authzr_uri)
		db.updateHost(hostname, 'authz_json', json.dumps(authz.to_json(), sort_keys=True, indent=4))
	else:
		logger.info('Validating existing challenges')
		authz = json.loads(info['authz_json'])
		challenges = [ch for ch in authz.get('body').get('challenges')]
		for i, challg in enumerate(challenges):
			resp = requests.get(challg.get('uri'))
			#logger.info(resp.text)
			# Check if the refreshed record is valid.
			if challg.get('status') == "revoked" or challg.get('status') == "invalid":# or ((time.strptime(authz.get('body')['expires'], "%Y-%m-%dT%H:%M:%SZ")-time.strptime(datetime.now(),"%Y-%m-%dT%H:%M:%SZ")) > timedelta(seconds=60)):
				# If so, remove it
				logger.info('Removing {} challenge {}'.format(challg.get('status'), challg.get('type')))
				challenges.remove(challg)
			else:
				logger.info('Updating challenge {}'.format(challg.get('type')))
				challenges[i]=json.loads(resp.text)
			
		try:
			[ch for ch in challenges if ch.get('type') == 'dns-01'][0]
			authz.get('body')['challenges']=challenges
		except IndexError:
			logger.exception("A valid or pending dns-01 challenge was not found.")
			logger.info("Requesting new challenges for %s." % hostname)
			authz = client.request_domain_challenges(domain, regr.new_authzr_uri).to_json()
		# Write a cache of challenges.
		db.updateHost(hostname, 'authz_json', json.dumps(authz, sort_keys=True, indent=4))

def _generate_jwk_thumbprint(account_key):
	"""
	Generates a JWK thumbprint for the specified account key.
	"""
	jwk=jose.JWKRSA(key=jose.ComparableRSAKey(account_key.public_key()))
	return _b64(jwk.thumbprint())

def getTXTRecord(hostname):
	try:
		_register(hostname)
		_getChallenges(hostname)
		info = db.recallHost(hostname)
		key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
		thumbprint=_generate_jwk_thumbprint(key)
		authz = json.loads(info['authz_json'])
		logger.debug(json.dumps(authz))
		auth = acme.messages.AuthorizationResource.from_json(authz).to_json().get('body')
		
		# Find the DNS challenge
		try:
			challenge = [ch for ch in auth.get('challenges', []) if ch.get('type') == 'dns-01'][0]
		except IndexError:
			logger.exception("The server did not return a dns-01 challenge.")
			return 1
		keyAuthorization = '{}.{}'.format(challenge.get('token'), thumbprint)
		sha256 = hashes.Hash(hashes.SHA256(), default_backend())
		sha256.update(keyAuthorization.encode('utf-8'))
		TXTRecord=_b64(sha256.finalize())
		# digest=hashlib.sha256()
		# digest.update(keyAuthorization.encode('utf-8'))
		# TXTRecord=_b64(digest.digest())
		return TXTRecord

	except Exception, e:
		logger.exception('')
		return 1

def submit_domain_validation(hostname):
	# try:
	info = db.recallHost(hostname)
	key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
	thumbprint=_generate_jwk_thumbprint(key)
	authz = json.loads(info['authz_json'])
	auth = acme.messages.AuthorizationResource.from_json(authz).to_json().get('body')
	# Find the DNS challenge
	try:
		challenge = [ch for ch in auth.get('challenges', []) if ch.get('type') == 'dns-01'][0]
		if challenge.get('status')=='valid':
			return True
	except IndexError:
		logger.exception("The server did not return a dns-01 challenge.")
		return False
	keyAuthorization = '{}.{}'.format(challenge.get('token'), thumbprint)
	payload={
			"resource":"challenge",
			"type":"dns-01",
			"keyAuthorization":keyAuthorization,
			}

	resp=_send_signed_request(challenge['uri'], payload, hostname)
	if str(resp.status_code).startswith('2'):
		return True
	else:
		logger.error(resp.text)
	return False

def checkAuth(hostname):
	status='pending'
	logger.info('Checking Auth')
	info = db.recallHost(hostname)
	authz = json.loads(info['authz_json'])
	auth = acme.messages.AuthorizationResource.from_json(authz).to_json().get('body')
	challenge = [ch for ch in auth.get('challenges', []) if ch.get('type') == 'dns-01'][0]
	while status == 'pending':
		response = requests.get(challenge['uri']).json()
		status = response.get('status')
		if status == 'valid':
			logger.info("{}: OK! Authorization lasts until {}.".format(domain, response.get('expires', '(not provided)')))
			[ch for ch in auth.get('challenges', []) if ch.get('type') == 'dns-01']

			return True
		elif status != 'pending':
			error_type, error_reason = "unknown", "N/A"
			try:
				error_type = response.get('error').get('type')
				error_reason = response.get('error').get('detail')
			except (ValueError, IndexError, AttributeError, TypeError):
				pass
			logger.error("{}: {} ({})".format(domain, error_reason, error_type))
			return False
		logger.info("{}: waiting for verification. Checking in 5 seconds.".format(domain))
		time.sleep(5)

def downloadCert(hostname):
	domain = hostname + DOMAIN
	info = db.recallHost(hostname)
	csr_key = serialization.load_pem_private_key(base64.b64decode(info['csr_privkey']),password=None, backend=default_backend())
	key = serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']),password=None, backend=default_backend())
	client = acme.client.Client(CA,jose.JWKRSA(key=jose.ComparableRSAKey(key)))
	authz = json.loads(info['authz_json'])

	logger.info('Creating CSR')
	(csr_pem, csr_der, csr)=generate_csr([domain],csr_key)
	csr = acme.jose.util.ComparableX509(csr)

	payload={
		"resource":"new-cert",
		"csr": _b64(csr_der)
	}

	logger.info('Requesting a certificate.')	
	cert_response = _send_signed_request(authz['new_cert_uri'], payload, hostname)
	#logger.info(cert_response.text)

	if cert_response.status_code == 201:
		logger.info(cert_response.headers)
		# chain = _get_link(cert_response.headers.get('Link'), 'up')
		# if chain:
		# 	chain = requests.get(chain).content
		def cert_to_pem(der):
			return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----""".format("\n".join(textwrap.wrap(base64.b64encode(der), 64)))
		cert_pem = cert_to_pem(cert_response.content)
		#chain = list(map(cert_to_pem, chain))
		#db.updateHost(hostname,'certificate',cert_pem)
		#db.updateHost(hostname, 'certificate_chain', chain)

		return {'status': 200,
				'cert': cert_pem,
				#'chain':chain,
		}
	else: 
		logger.error(cert_response.text)
		return {'status':400}

def generate_csr_pyca(domains, key):
	# Generates a CSR and returns a pyca/cryptography CSR object.
	from cryptography import x509
	from cryptography.x509.oid import NameOID
	from cryptography.hazmat.primitives import hashes
	from cryptography.hazmat.backends import default_backend

	import sys
	if sys.version_info < (3,):
		# In Py2, pyca requires the CN to be a unicode instance.
		domains = [domain.decode("ascii") for domain in domains]
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
		x509.NameAttribute(NameOID.COMMON_NAME, domains[0]),
	])).add_extension(
		x509.SubjectAlternativeName([x509.DNSName(domain) for domain in domains]),
		critical=False,
	).sign(key, hashes.SHA256(), default_backend())
	return csr

def generate_csr(domains, key):
	# Generates a CSR and returns a OpenSSL.crypto.X509Req object.
	from cryptography.hazmat.primitives import serialization
	csr = generate_csr_pyca(domains, key)
	csr_pem = csr.public_bytes(serialization.Encoding.PEM)  # put into PEM format (bytes)
	csr_der = csr.public_bytes(serialization.Encoding.DER)
	# Convert the CSR in PEM format to an OpenSSL.crypto.X509Req object.
	csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, csr_pem)
	return (csr_pem, csr_der, csr)
