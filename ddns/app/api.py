#!/usr/bin/python
from flask import Flask, request, Response, jsonify, Blueprint
from json import dumps, loads, JSONEncoder, JSONDecoder
import os, sys, rsa, jose, base64, hashlib, re, subprocess, le, time,logging, ddns
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update 
from app import domain

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

#JWK claims:
#hostname
#publickey
#algorithm
#secret
#ipaddr

#Responses:
#409 Conflict
#201 Created
#400 Bad Request

@embyapi.route('/api/v0.1/register', methods=['POST']) #register IP with DDNS
def register_v01():
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddr = jwt[1]['ipaddr']
		regid = jwt[1]['hostname']
		alg = jwt[1]['alg']
		secret = jwt[1]['secret']
	except KeyError, e:
		return 'KeyError', 400
	# check if host exists
	try:
		response = dns.resolver.query(jwt[1]['hostname'] + '.'+ domain + '.','A')
		return 'hostname already exists', 409 #Conflict: hostname already exists
	except dns.resolver.NXDOMAIN:
		#New registration: 
		#Add key to file
		if jwt[1]['hostname'] + '.' + domain in open('/etc/bind/'+domain+'.keys','r').read():
			return 'hostname already exists', 409
		with open('/etc/bind/'+domain+'.keys','a') as f:
			f.write('key \"{0}\" '.format(jwt[1]['hostname'] + '.'+ domain) + '{\n')
			f.write('\talgorithm {0};'.format(jwt[1]['alg']) + '\n')
			f.write('\tsecret \"{0}\";'.format(jwt[1]['secret']) + '\n')
			#f.write('\tvalid-until \"{0}\";'.format())
			f.write('};\n')

		#run rndc reconfig
		subprocess.call(['rndc','reload'])

		#Add initial A record
		tsig = dns.tsigkeyring.from_text({jwt[1]['hostname'] + '.'+ domain: str(jwt[1]['secret'])})
		action = dns.update.Update(domain, keyring=tsig)
		action.replace(str(jwt[1]['hostname']), 300, 'A', str(jwt[1]['ipaddr']))
		try:
			response = dns.query.tcp(action, 'ns1.'+ domain) 
		except:
			e=sys.exc_info()[0]
			resp['error'] = 'DNS request failed'
			resp['exception'] = str(e)
			return str(resp), 400
		if response.rcode() == 0:
			return str('OK'), 201
		else:
			resp['error'] = 'DNS request failed'
			return str(resp), 400

@embyapi.route('/api/v0.1/update', methods=['POST']) #update IP with DDNS
def update_v01():
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddr = jwt[1]['ipaddr']
		regid = jwt[1]['hostname']
	except KeyError, e:
		return 'KeyError', 400
	# check if host exists
	try:
		response = dns.resolver.query(jwt[1]['hostname'] + '.' + domain + '.','A')
		#Add initial A record
		tsig = dns.tsigkeyring.from_text({jwt[1]['hostname'] + '.' + domain: str(jwt[1]['secret'])})
		action = dns.update.Update(domain, keyring=tsig)
		action.replace(str(jwt[1]['hostname']), 300, 'A', str(jwt[1]['ipaddr']))
		try:
			response = dns.query.tcp(action, 'ns1.' + domain) 
		except:
			e=sys.exc_info()[0]
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			logger.debug(exc_type, fname, exc_tb.tb_lineno)
			resp['error'] = 'DNS request failed'
			resp['exception'] = str(e)
			return str(resp), 400
		if response.rcode() == 0:
			return str('OK'), 201
		else:
			resp['error'] = 'DNS request failed'
			return str(resp), 400

	except dns.resolver.NXDOMAIN:
		return 'Hostname Not Found', 404 #Not Found: hostname does not exist
	except Exception, e:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		logger.debug(exc_type, fname, exc_tb.tb_lineno)
		resp['error'] = 'ERROR'
		resp['except'] = str(e)
		return str(resp), 400

@embyapi.route('/api/v0.1/getcert', methods=['POST'])
def getCert_v01():
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddr = jwt[1]['ipaddr']
		regid = jwt[1]['hostname']
	except KeyError, e:
		return 'KeyError', 400
	# check if host exists
	try:
		response = dns.resolver.query(jwt[1]['hostname'] + '.' + domain + '.','A')
		#Add initial A record
		tsig = dns.tsigkeyring.from_text({jwt[1]['hostname'] + '.' + domain: str(jwt[1]['secret'])})
		action = dns.update.Update(domain, keyring=tsig)
		action.replace(str(jwt[1]['hostname']), 300, 'A', str(jwt[1]['ipaddr']))
		try:
			response = dns.query.tcp(action, 'ns1.' + domain) 
		except:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			logger.debug(exc_type, fname, exc_tb.tb_lineno)
			e=sys.exc_info()[0]
			resp['error'] = 'DNS request failed'
			resp['exception'] = str(e)
			return str(resp), 400
		if response.rcode() == 0:
			pass
		else:
			exc_type, exc_obj, exc_tb = sys.exc_info()
			fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
			logger.debug(exc_type, fname, exc_tb.tb_lineno)
			resp['error'] = 'DNS request failed'
			return str(resp), 400
	except dns.resolver.NXDOMAIN:
		return 'Hostname Not Found', 404 #Not Found: hostname does not exists
	
	#register and get auths for LetsEncrypt
	keyauthorization = le.getDNSToken(jwt[1]['hostname'])
	logger.debug('keyAuthorization: {}'.format(keyauthorization))
	m=hashlib.sha256()
	m.update(keyauthorization.encode('ascii'))
	TXTRecord=base64.urlsafe_b64encode(m.digest()).decode('ascii').replace("=", "")
	logger.debug('TXTRecord: {}'.format(TXTRecord))
	if 'Error' in TXTRecord:
		return str(TXTRecord)
	tsig = dns.tsigkeyring.from_text({jwt[1]['hostname'] + '.' + domain: str(jwt[1]['secret'])})
	action = dns.update.Update(domain, keyring=tsig)
	action.replace('_acme-challenge.' + str(jwt[1]['hostname']), 300, 'TXT', str(TXTRecord))
	try:
		response = dns.query.tcp(action, 'ns1.' + domain) 
	except:
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		logger.debug(exc_type, fname, exc_tb.tb_lineno)
		e=sys.exc_info()[0]
		resp['error'] = 'DNS request failed'
		resp['exception'] = str(e)
		return str(resp), 400
	if response.rcode() == 0:
		pass
	else:
		resp['error'] = 'DNS request failed'
		resp['rcode'] = response.rcode()
		resp['respons'] = str(response)
		return str(resp), 400

	time.sleep(1)
	return str(le.submit_domain_validation(jwt[1]['hostname'])),400

	#get cert
	#send to user


	return 'Added TXTRecord',201

@embyapi.route('/api/v0.1/checkhostname', methods=['POST'])
def checkhostname_v01():
	return 'Not Implimented', 503



@embyapi.route('/api/v0.2/register', methods=['POST']) #register IP with DDNS
def register_v02():
	logger.debug('Registering')
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddress = jwt[1]['ipaddr']
		hostname = jwt[1]['hostname']
		alg = jwt[1]['alg']
		secret = jwt[1]['secret']
	except KeyError, e:
		return 'KeyError', 400

	if ddns.addDDNSHost(hostname, ipaddress, secret, alg)!=0:
		return 'DDNS Error', 400

	return 'OK', 201

@embyapi.route('/api/v0.2/update', methods=['POST']) #update IP with DDNS
def update_v02():
	logger.debug('Updating')
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddress = jwt[1]['ipaddr']
		hostname = jwt[1]['hostname']
		secret = jwt[1]['secret']
	except KeyError, e:
		return 'KeyError', 400

	if ddns.updateDDNSHost(hostname, ipaddress, secret)!=0:
		return 'DDNS Error', 400
	return 'OK', 201


@embyapi.route('/api/v0.2/getcert', methods=['POST'])
def getCert_v02():
	resp={}
	content = request.data
	jwt = jose.decrypt(jose.deserialize_compact(content), priv_jwk)
	try:
		ipaddress = jwt[1]['ipaddr']
		hostname = jwt[1]['hostname']
		secret = jwt[1]['secret']
	except KeyError, e:
		return 'KeyError', 400


	#register and get txt record for DNS-01 challenge
	TXTRecord = le.getTXTRecord(hostname)
	if TXTRecord==1:
		return 'TXTRecord Error', 400

	if ddns.addTXTRecord(hostname,ipaddress,secret,TXTRecord)!=0:
		return 'DDNS Error', 400

	logger.info('Waiting 10s for DDNS changes to propogate.')
	time.sleep(10)
	
	if le.submit_domain_validation(hostname): #submit answer to challenge
		if le.checkAuth(hostname):#check on the status of the challenge.
			resp=le.downloadCert(hostname)#get the LE cert and pass to client.
			if resp['status']==200:
				return resp['cert'], 200
			logger.info(resp['status'])
			return 'OK', 201
	return 'Could not pass challenge', 400


	#get cert
	#send to user

@embyapi.route('/api/v0.2/checkhostname', methods=['POST'])
def checkhostname_v02():
	return 404