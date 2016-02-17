#!/usr/bin/python
import base64, json, OpenSSL, requests, logging, db, ddns, time, ast
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
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

def _send_signed_request(url, payload, hostname, nonce, headers={'Content-Type': 'application/json'}):
	info = db.recallHost(hostname)
	priv=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(info['acct_privkey']))
	key=serialization.load_pem_private_key(base64.b64decode(info['acct_privkey']), password=None, backend=default_backend()) 
	header = {
		"alg": "RS256",
		"jwk": jose.JWKRSA(key=jose.ComparableRSAKey(key.public_key())).to_partial_json(),
	}
	payload64 = _b64(json.dumps(payload).encode('utf8'))
	protected64 = _b64(json.dumps({"nonce":nonce}))
	signature64 = _b64(OpenSSL.crypto.sign(priv, str(protected64) + '.' + str(payload64), 'sha256'))
	message=json.dumps({"header":header,"protected":protected64, "payload":payload64, "signature":signature64})
	resp = requests.post(url, data=message, headers=headers)
	return resp

def _generate_jwk_thumbprint(account_key):
	key=serialization.load_pem_private_key(base64.b64decode(account_key), password=None, backend=default_backend())
	jwk=jose.JWKRSA(key=jose.ComparableRSAKey(key.public_key()))
	return _b64(jwk.thumbprint())

def _createCertRequest(pkey, name, digest="md5"):
    pkey=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(pkey))
    req = OpenSSL.crypto.X509Req()
    subj = req.get_subject()
    for (key,value) in name.items():
        setattr(subj, key, value)
    req.set_pubkey(pkey)
    req.sign(pkey, digest)
    return OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_ASN1, req)

def Register(info):
	hostname=info['hostname']
	resp=requests.get(CA)
	nonce=resp.headers['Replay-Nonce'].encode('utf8')
	LEdir=json.loads(resp.text)
	payload={
		"resource":"new-reg",
	}
	logger.debug('Registering {} with LetsEncrypt.'.format(hostname))
	registration = _send_signed_request(LEdir['new-reg'], payload, hostname, nonce)
	#logger.debug('Reg Response Content: \n{}'.format(resp.content))
	logger.debug('Reg response: {}\n{}:{}'.format(registration.headers, registration.status_code, registration.text))
	if registration.status_code==201:
		#look for terms
		TERMS=registration.links['terms-of-service']
		logger.info('TERMS: {}'.format(TERMS))
		if TERMS!=None:
			logger.debug('Agreeing to terms')
			payload={
				"resource":"reg",
				"agreement":TERMS.get('url'),
			}
			resp=_send_signed_request(registration.headers.get('Location'), payload, hostname, registration.headers.get('Replay-Nonce'))
			logger.debug('Terms resp: {}\n{}:{}'.format(resp.headers, resp.status_code, resp.text))

		reg_json={
			"body":{
				"agreement":TERMS.get('url'),
				"key":registration.json().get('key'),
				},
			"new_authzr_uri":registration.links['next'].get('url'),
			"terms_of_service":TERMS.get('url'),
			"uri":registration.headers.get('Location')
			}
		db.updateHost(hostname,'reg_json', json.dumps(reg_json))
		return True
	if registration.status_code==409:
		#already registered
		logger.debug('{} is already registered.'.format(hostname))
		return True
	return False

def RequestChallenges(info):
	hostname=info['hostname']
	resp=requests.get(CA)
	nonce=resp.headers['Replay-Nonce'].encode('utf-8')
	payload={
		"resource":"new-authz",
		"identifier": {
			"type": "dns",
			"value": hostname+DOMAIN,
		}
	}
	logger.debug('Getting Authz')
	resp=_send_signed_request(ast.literal_eval(info['reg_json']).get('new_authzr_uri'), payload, hostname, nonce)
	logger.debug('Authz resp: {}\n{}:{}'.format(resp.headers, resp.status_code, resp.text))
	if resp.status_code==201:
		authz_json={
			"body":resp.json(),
			"new_cert_uri":resp.links['next'].get('url'),
			"uri":resp.headers.get('Location')
		}
		db.updateHost(hostname,'authz_json', json.dumps(authz_json))
		return True
	return False

def AnswerChallenges(info, secret):
	authz=json.loads(info['authz_json'])
	for ch in authz.get('body').get('challenges'):
		if ch.get('type')=='dns-01':
			challenge=ch
	if not 'challenge' in locals():
		return False

	hostname = info['hostname']
	resp=requests.get(CA)
	nonce=resp.headers['Replay-Nonce'].encode('utf-8')

	#todo this is bullshit. make it ourself.
	thumbprint = _generate_jwk_thumbprint(info['acct_privkey'])

	keyAuthorization = '{}.{}'.format(challenge.get('token'),thumbprint)
	sha256 = hashes.Hash(hashes.SHA256(), default_backend())
	sha256.update(keyAuthorization.encode('utf-8'))
	TXTRecord=_b64(sha256.finalize())

	if ddns.addTXTRecord(hostname,secret,TXTRecord)!=0:
		return False

	logger.info('Waiting 10 seconds for DNS changes to propogate before answering challenge')
	time.sleep(10)

	payload={
		"resource": "challenge",
		"type": "dns-01",
		"keyAuthorization": keyAuthorization,
	}

	resp=_send_signed_request(challenge.get('uri'), payload, hostname, nonce)
	logger.debug('Answer challenge resp: {}\n{}:{}'.format(resp.headers, resp.status_code, resp.text))
	if resp.status_code==200 or resp.status_code==202: #spec says should be 200. local boulder is returning 202.
		return True
	db.setDBNull(hostname,'authz_json')
	return False

def Poll(info):
	authz=json.loads(info['authz_json'])
	resp=requests.get(authz.get('uri'))
	logger.debug('Poll resp: {}\n{}:{}'.format(resp.headers, resp.status_code, resp.text))
	if resp.status_code==200:#Challenge accepted & Valid keep polling until status is valid
		while True:
			time.sleep(5)
			resp=requests.get(authz.get('uri'))
			logger.debug('Poll resp: {}\n{}:{}'.format(resp.headers, resp.status_code, resp.text))
			if resp.json().get('status')=='valid':
				break
		authz_json={
			"body":resp.json(),
			"new_cert_uri":resp.links['next'].get('url'),
			"uri":authz.get('uri')
		}
		db.updateHost(info['hostname'],'authz_json', json.dumps(authz_json))
		return True
	if resp.status_code==202:#Challenge accepted but not validated yet.#look for retry-after header.
		if resp.headers.get('Retry-After') != None:
			while True:
				logger.info('Waiting {} seconds for LetsEncrypt to verify challenge.'.format(resp.headers.get('Retry-After')))
				time.sleep(resp.headers.get('Retry-After'))
				resp=requests.get(authz.get('uri'))
				if resp.status_code!=202:
					break
		return True
	return False

def RequestIssuance(info):
	#create csr
	hostname = info['hostname']
	fqdn= hostname + DOMAIN
	authz=json.loads(info['authz_json'])
	csr = _createCertRequest(info['csr_privkey'], name={'CN': fqdn}, digest="sha256")
	payload={
		"resource":"new-cert",
		"csr":_b64(csr),
	}
	resp=requests.get(CA)
	nonce=resp.headers['Replay-Nonce'].encode('utf-8')
	resp=_send_signed_request(authz.get('new_cert_uri'), payload, hostname, nonce)
	logger.debug('NewCert resp: {}:{}'.format(resp.status_code, resp.headers))
	if resp.status_code==201:
		db.updateHost(hostname, 'certificate', resp.headers.get('Location'))
		logger.info('Certificate issued!')
		return True
	if resp.status_code==202:
		while True:
			resp=requests.get(resp.url)
			logger.debug('NewCert resp: {}:{}'.format(resp.status_code, resp.headers))
			if resp==201:
				db.updateHost(hostname, 'certificate', resp.headers.get('Location'))
				return True
			if resp!=202:
				time.sleep(resp.headers('Retry-After'))
	return False