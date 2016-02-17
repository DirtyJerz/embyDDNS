import dns, logging, subprocess, time
import dns.query
import dns.resolver
import dns.tsigkeyring
import dns.update 
from app import domain

logger = logging.getLogger(__name__)

# Add new hostname
# 0=Successful or host exists
# 1=Error
def addDDNSHost(hostname, ipaddress, secret, alg):
	#Add key to file
	if hostname + '.' + domain in open('/etc/bind/'+domain+'.keys','r').read():
		logger.debug('Hostname Exists')
		return 0, '' # Host already exists on DDNS
	logger.debug('Adding host {}.{}'.format(hostname,domain))
	with open('/etc/bind/'+domain+'.keys','a') as f:
		f.write('key \"{0}\" '.format(hostname + '.'+ domain) + '{\n')
		f.write('\talgorithm {0};'.format(alg) + '\n')
		f.write('\tsecret \"{0}\";'.format(secret) + '\n')
		#f.write('\tvalid-until \"{0}\";'.format())
		f.write('};\n')
	#run rndc reconfig
	subprocess.call(['rndc','reload'])

	#let changes propogate
	time.sleep(3) 

	#Add initial A record
	return updateDDNSHost(hostname,ipaddress,secret)

# update host ip
#1=Host ip update failed
#0=Host ip updated
def updateDDNSHost(hostname, ipaddress, secret):
	try:
		tsig = dns.tsigkeyring.from_text({hostname + '.' + domain : secret})
		action = dns.update.Update(domain, keyring=tsig)
		action.replace(str(hostname), 5, 'A', str(ipaddress))
		response = dns.query.tcp(action, 'ns1.' + domain) 
		if response.rcode() == 0:
			logger.info('\'A\' record updated for {}'.format(hostname))
			return 0, ''
		else:
			logger.error('DNS request failed')
			return 1, 'DNS request failed: {}'.format(response)
	except dns.resolver.NXDOMAIN:
		logger.error('Domain does not exist on DDNS')
		return 1, 'Domain does not exist on DDNS'
	except dns.tsig.PeerBadSignature:
		logger.error('Client\'s private key does not match DDNS host\'s private key')
		return 1, 'Client\'s private key does not match DDNS host\'s private key'
	except:
		logger.error('DNS request failed')
		return 1, 'DNS request failed: {}'.format(response)

def addTXTRecord(hostname,secret,txtrecord):
	try:
		tsig = dns.tsigkeyring.from_text({hostname + '.' + domain : str(secret)})
		action = dns.update.Update(domain, keyring=tsig)
		action.replace('_acme-challenge.' + str(hostname), 5, 'TXT', txtrecord.encode('utf-8'))
		response = dns.query.tcp(action, 'ns1.' + domain) 
		if response.rcode() == 0:
			logger.info('\'TXT\' record updated for {}'.format(hostname))
			return 0
		else:
			logger.error('TXT Record DDNS request failed: {}'.format(response))
			return 1
	except:
		logger.error('DNS request failed')
		return 1
	
