#!/usr/bin/python
from flask import request, Blueprint
import rsa, jose, base64, logging, json, le, ddns, db, requests, textwrap

embyapi = Blueprint('embyapi', __name__)
logger = logging.getLogger(__name__)

priv_jwk = {}
with open('app/keys/private_key.pem') as privfile:
	keydata=privfile.read()
	priv_jwk = {'k': keydata}

@embyapi.route('/api/v0.1/publickey')
def pubKey():
	with open('app/keys/public_key.pem') as publicfile:
		keydata = publicfile.read()
		publickey = rsa.PublicKey.load_pkcs1(keydata,'PEM')
	logger.debug('Sending publickey')
	return keydata

@embyapi.route('/api/v0.3/getcert', methods=['POST'])
def getCert_v03():
	#register with ddns
	logger.debug('Registering')
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddress = jwt[1]['ipaddr']
		hostname = jwt[1]['hostname']
		alg = jwt[1]['alg']
		secret = jwt[1]['secret']
		privkey = jwt[1]['privkey'] #to be used with LE
	except KeyError, e:
		return 'KeyError', 400

	code, resp=ddns.addDDNSHost(hostname, ipaddress, secret, alg)
	if code!=0:
		return resp, 400
	code, resp=ddns.updateDDNSHost(hostname,ipaddress,secret)
	if code!=0:
		return resp, 400

	info = db.recallHost(hostname)
	if info == None:
		logger.debug('Host not found in DB. Creating new entry')
		db.storeKeypair(hostname, privkey, db.generateKeypair())
		info = db.recallHost(hostname)

	if info['reg_json']==None:
		if not le.Register(info):#201 updateDB
			return 'Error in LetsEncrypt Registration', 400
		info=db.recallHost(hostname)

	if info['authz_json']==None:
		authzStatus=''
	else:
		authzStatus = json.loads(info['authz_json']).get('body').get('status') or None

	logger.debug('authzStatus:{}'.format(authzStatus))
	if authzStatus!="pending" and authzStatus !="valid":
		if not le.RequestChallenges(info):#201 updateDB
			return 'Error in LetsEncrypt Challenge Request', 400
		info=db.recallHost(hostname)

	if authzStatus!="valid":
		if not le.AnswerChallenges(info, secret):#DNS-01 only for now because we control it
			return 'Error in LetsEncrypt Challenge Answer', 400
		info=db.recallHost(hostname)

	if authzStatus!="valid":
		if not le.Poll(info):
			return 'Error in LetsEncrypt Polling', 400
		info=db.recallHost(hostname)

	if info['certificate']==None:
		if not le.RequestIssuance(info):
			return 'Error in LetsEncrypt Cert Request Issuance', 400
		info=db.recallHost(hostname)
	certificate=requests.get(info['certificate']).content

	def cert_to_pem(der):
			return """-----BEGIN CERTIFICATE-----\n{0}\n-----END CERTIFICATE-----""".format("\n".join(textwrap.wrap(base64.b64encode(der), 64)))

	return cert_to_pem(certificate), 201

	return 'Made it through', 200
