#!/usr/bin/env python3

import argparse
import requests
import json
import base64
import math
import time
import hashlib
import traceback
import http.server, ssl
import threading
import os

from dnslib import RR
from dnslib.server import DNSServer, DNSLogger

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec,rsa,utils
from cryptography.x509.oid import NameOID

def to_bytes(x):
    return x.to_bytes(math.ceil(math.log2(x)/8),byteorder='big')
def base64url(s):
     return base64.urlsafe_b64encode(s).decode('ascii').replace('=','')
def base64url_d(s):
    try:
        return base64.urlsafe_b64decode(s)
    except e:
        traceback.print_exc()
        pass
    try:
        return base64.urlsafe_b64decode(s+"=")
    except e:
        traceback.print_exc()
        pass
    return base64.urlsafe_b64decode(s+"==")

def jwt(url,action,key,priv_key,pload,accept = None):
    # fast polling causes invalid nonce
    r=action.__self__.head(newNonce)
    nonce=r.headers['Replay-Nonce'];

    protected = base64url(json.dumps({
        "alg": "ES256",
        **key,
        "nonce": nonce,
        "url": url
    }).encode('utf-8'))
    if pload != '':
        payload = base64url(json.dumps(pload).encode('utf-8'))
    else:
        payload = ""
    comb=protected+"."+payload
    (r,s) = utils.decode_dss_signature(priv_key.sign((comb).encode('utf-8'), signature_algorithm=ec.ECDSA(hashes.SHA256())))
    signature=base64url(to_bytes(r)+to_bytes(s))
    action.__self__.headers.update({'Accept': accept})
    r=action(url, json.dumps({"protected":protected, "payload":payload, "signature":signature}))
    nonce=r.headers['Replay-Nonce'];
    return r

###############################
# ARGS
###############################
print("ARGS ....")
parser = argparse.ArgumentParser()
parser.add_argument("challenge_type", choices=["dns01","http01"],
                    help="(required, {dns01 | http01}) indicates which ACME challenge type the client" +
                    "should perform. Valid options are dns01 and http01 for the dns-01 and http-01"+
                    "challenges, respectively.")
parser.add_argument("--dir", type=str,
                    help="(required) DIR URL is the directory URL of the ACME server that should be used.",
                    required=True)
parser.add_argument("--record", type=str,
                    help="(required) IPv4 ADDRESS is the IPv4 address which must be returned by your DNS"+
                    "server for all A-record queries.",
                    required=True)
parser.add_argument("--domain", type=str, action='append',
                    help="(required, multiple) DOMAIN is the domain for which to request the certificate. If"+
                    "multiple --domain flags are present, a single certificate for multiple domains should"
                    "be requested. Wildcard domains have no special flag and are simply denoted by,"
                    "e.g., *.example.net.",
                    required=True)
parser.add_argument("--revoke",
                    help="If present, your application should immediately revoke the certificate"+
                    "after obtaining it. In both cases, your application should start its HTTPS server"+
                    "and set it up to use the newly obtained certificate.",
                    action="store_true")
args = parser.parse_args()

########################
# DNS
########################
print("DNS ....")

# start dns
class RecordResolver:
    answers = ["*. 60 A {}".format(args.record)]
    def resolve(self,request,handler):
        reply = request.reply()
        [reply.add_answer(*RR.fromZone(a)) for a in self.answers]
        return reply
resolver = RecordResolver()
dns = DNSServer(resolver,port=10053,address="0.0.0.0" )#, logger=DNSLogger("-request,-reply,-truncated"))
dns.start_thread()

#######################
# HTTP 
#######################
print("HTTP ....")
http01 = http.server.HTTPServer(('0.0.0.0', 5002), http.server.SimpleHTTPRequestHandler)
threading.Thread(target=http01.serve_forever).start()

class httpShutHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"")
        os.system(r'ps o pid,comm | \
                     grep python | \
                     sed -ne "s/^[[:space:]]*\([0-9]*\)[[:space:]].*$/\1/p" | \
                     xargs kill -15 ')
http_shut = http.server.HTTPServer(('0.0.0.0', 5003), httpShutHandler)
threading.Thread(target=http_shut.serve_forever).start()


######################
# key
######################
print("KEY ....")
ES256_priv_key = ec.generate_private_key(
    ec.SECP256R1(), default_backend()
)

x=ES256_priv_key.public_key().public_numbers().x
y=ES256_priv_key.public_key().public_numbers().y

ES256_out_key = ec.generate_private_key(
    ec.SECP256R1(), default_backend()
)
with open("./ec_priv_key.pem", "wb") as f:
    f.write(ES256_out_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("./ec_pub_key.pem", "wb") as f:
    f.write(ES256_out_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

jwk = {
    "kty":"EC",
    "crv":"P-256",
    "x":base64url(to_bytes(x)),
    "y":base64url(to_bytes(y)),
}
jwk_str = json.dumps(jwk, sort_keys=True).replace(' ','').encode('utf-8').decode('ascii')
ES256_thumb = base64url(hashlib.sha256(jwk_str.encode('utf-8')).digest())

######################
# CSR
######################
print("CSR ....")
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"  "),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u" "),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u" "),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u" "),
    x509.NameAttribute(NameOID.COMMON_NAME, u" "),
])).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(domain) for domain in args.domain]),
    critical=False,
).sign(ES256_out_key, hashes.SHA256(), default_backend())
with open("./csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

######################
# requests session
######################
print("requests session ....")
s = requests.Session()
s.verify = './pebble_https_ca.pem'
s.headers.update({'Content-Type': 'application/jose+json'})

######################
# ACME dir structure
######################
print("ACME dir ....")
do_while = True
while do_while:
    do_while = False
    try:
        r=s.get(args.dir)
        newNonce=json.loads(r.content)['newNonce']
        newAccount=json.loads(r.content)['newAccount']
        newOrder=json.loads(r.content)['newOrder']
        revokeCert=json.loads(r.content)['revokeCert']
    except Exception as e:
        traceback.print_exc()
        print('>- ERROR ------------')
        print('--- HEAD ------------')
        print(r.headers)
        print('--- CONTENT ------------')
        print(r.content)
        print('<- ERROR ------------')
        do_while = True

######################
# ACME new Account
######################
print("ACME new Account ....")
do_while = True
while do_while:
    do_while = False
    try:
        r = jwt(newAccount,
                     s.post,
                     {'jwk': jwk},
                     ES256_priv_key,
                     {"termsOfServiceAgreed": True})
        account=r.headers['Location'];
    except Exception as e:
        traceback.print_exc()
        print('>- ERROR ------------')
        print('--- HEAD ------------')
        print(r.headers)
        print('--- CONTENT ------------')
        print(r.content)
        print('<- ERROR ------------')
        do_while = True

######################
# ACME new Order
######################
print("ACME new Order ....")
do_while = True
while do_while:
    do_while = False
    try:
        r = jwt(newOrder,s.post,{"kid":account}, ES256_priv_key,
             {"identifiers":
              [ { "type": "dns", "value": domain } for domain in args.domain ]
             })
        order=r.headers['Location'];
        finalize=json.loads(r.content)['finalize']
        authorizations=json.loads(r.content)['authorizations']
    except Exception as e:
        traceback.print_exc()
        print('>- ERROR ------------')
        print('--- HEAD ------------')
        print(r.headers)
        print('--- CONTENT ------------')
        print(r.content)
        print('<- ERROR ------------')
        do_while = True

os.makedirs('./.well-known/acme-challenge/', exist_ok=True)
        
######################
# ACME start authorization
######################
print("ACME new Auth ....")
for a in authorizations:
    do_while = True
    while do_while:
        do_while = False
        try:
            r = jwt(a,s.post,{"kid":account}, ES256_priv_key, "")
            challenges=json.loads(r.content)['challenges']
            for c in challenges:
                if args.challenge_type == "dns01" and c['type'] == "dns-01":
                    challenge=c
                    resolver.answers.append("_acme-challenge.{}. 300 IN TXT {}".format(
                        json.loads(r.content)['identifier']['value'],
                        base64url(hashlib.sha256((c['token']+'.'+ES256_thumb).encode('utf-8')).digest())))
                    break
                if args.challenge_type == "http01" and c['type'] == "http-01":
                    challenge=c
                    with open('./.well-known/acme-challenge/'+c['token'],'wb') as f:
                        f.write(hashlib.sha256((c['token']+'.'+ES256_thumb).encode('utf-8')).digest())
                    break
        except Exception as e:
            traceback.print_exc()
            print('>- ERROR ------------')
            print('--- HEAD ------------')
            print(r.headers)
            print('--- CONTENT ------------')
            print(r.content)
            print('<- ERROR ------------')
            do_while = True

    
    do_while = True
    while do_while:
        do_while = False
        try:
            r = jwt(challenge['url'],s.post,{"kid":account}, ES256_priv_key, {})
        except Exception as e:
            traceback.print_exc()
            print('>- ERROR ------------')
            print('--- HEAD ------------')
            print(r.headers)
            print('--- CONTENT ------------')
            print(r.content)
            print('<- ERROR ------------')
            do_while = True

######################
# ACME wait authorization
######################
print("ACME wait Auth ....")
for a in authorizations:
    do_while = True
    while do_while:
        do_while = False
        try:
            r = jwt(a,s.post,{"kid":account}, ES256_priv_key, "")
            assert(json.loads(r.content)['status'] != 'invalid')
            print("- status: {}".format(json.loads(r.content)['status']))
            if json.loads(r.content)['status'] != "valid":
                time.sleep(2)
                do_while = True
        except Exception as e:
            traceback.print_exc()
            print('>- ERROR ------------')
            print('--- HEAD ------------')
            print(r.headers)
            print('--- CONTENT ------------')
            print(r.content)
            print('<- ERROR ------------')
            do_while = True

######################
# ACME finalize
######################
print("ACME finalize ....")
do_while = True
while do_while:
    do_while = False
    try:
        r = jwt(finalize,s.post,{"kid":account}, ES256_priv_key, {
            "csr": base64url(csr.public_bytes(serialization.Encoding.DER))
        })
        if r.status_code  >= 400:
            do_while=True
    except Exception as e:
        do_while=True
        traceback.print_exc()
        print('>- ERROR ------------')
        print('--- HEAD ------------')
        print(r.headers)
        print('--- CONTENT ------------')
        print(r.content)
        print('<- ERROR ------------')
        #do_while = True

######################
# ACME wait cert
######################
print("ACME wait cert ....")
do_while = True
while do_while:
    do_while = False
    try:
        r = jwt(order,s.post,{"kid":account}, ES256_priv_key, "")
        if not "certificate" in json.loads(r.content):
            time.sleep(2)
            do_while = True
        else:
            cert = json.loads(r.content)["certificate"]
    except Exception as e:
        traceback.print_exc()
        print('>- ERROR ------------')
        print('--- HEAD ------------')
        print(r.headers)
        print('--- CONTENT ------------')
        print(r.content)
        print('<- ERROR ------------')
        do_while = True

######################
# ACME download cert
######################
print("ACME download cert ....")
do_while = True
while do_while:
    do_while = False
    try:
        r = jwt(cert,s.post,{"kid":account}, ES256_priv_key, "", "application/pem-certificate-chain")
        assert(r.status_code == 200)
    except Exception as e:
        traceback.print_exc()
        print('>- ERROR ------------')
        print('--- HEAD ------------')
        print(r.headers)
        print('--- CONTENT ------------')
        print(r.content)
        print('<- ERROR ------------')
        do_while = True

with open("./ec_cert.pem", "wb") as f:
    f.write(r.content)

######################
# HTTPS serve
######################
print("HTTPS serve ....")
http_cert = http.server.HTTPServer(('0.0.0.0', 5001), http.server.SimpleHTTPRequestHandler)
http_cert.socket = ssl.wrap_socket(http_cert.socket,
                                   server_side=True,
                                   certfile='ec_cert.pem',
                                   keyfile='ec_priv_key.pem',
                                   ssl_version=ssl.PROTOCOL_TLS)
threading.Thread(target=http_cert.serve_forever).start()

while True:
    print("Zzzzzz! Zzzzzz! ")
    time.sleep(30)
