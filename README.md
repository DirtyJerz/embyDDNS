# embyDDNS

embyDDNS is a Docker container based off of the phusion-passenger image that contains a BIND9 server and the necessary API to interact with LetsEncrypt.org to obtain an SSL/TLS certificate for client EmbyServers.


**DOES NOT ISSUE CERTIFICATES YET.**
*Currently Let'sEncrypt does not yet have the DNS-01 challenge implemented in the production server. Once it is implemented, this repo will be updated. For now this will only act as a DDNS. Feel free to test it out and leave issues to help me make it more robust.*

# Usage

Building image (**./build.sh**):

```
docker build -t embyddns --rm=true .
```

Running the container (**./run.sh**):
```
docker run -d --net=host -e "DDNS=ddns.host.com" --name EmbyDDNS embyddns
```
Where **-e** represents a subdomain with a widely resolvable A name. This must be a sub domain of a host under a TLD. **"emby.media" will not work here. It must be "DDNS.emby.media"**

There must also be a resolvable nameserver associated with this sub domain witht eh name **"ns1"**. Example: **"ns1.ddns.host.com"**


# API

The API is laid out as follows:

**Server Public Key**
>*url={host}:5000/api/v0.1/publickey*
*Type=GET*
>>returns=PEM encoded public key of server (publickeystring)

**Get Certificate** 
>url={host}:5000/api/v0.1/getcert*
*type=POST*
>>*returns certificate in PEM format*

**POST body format**
*body=JWT with claims encrypted with server public key:*
```
jwk= {'k' : "publickeystring"}
```
```
claims = {
    'hostname': "hostname",
    'privkey': "privatekey",
    'alg' : "alg",
    'secret' : "secret",
    'ipaddr' : "ipaddr",
    
}
```
Where :
**"hostname"**= String(subdomain of user)
**"privatekey"**= Base64(PEM encoded client public key)
**"alg"**= String('hmac-md5')
**"secret"**= Base64(MD5-HMAC of hostname signed with client's RSA private key) 
**"ipaddr"**= String(Public IP address of subdomain trying to register with this DDNS)

