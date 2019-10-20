#!/bin/python3

import argparse
import requests
import json
import base64
import math
import time

from dnslib import RR
from dnslib.server import DNSServer
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
    except:
        pass
    try:
        return base64.urlsafe_b64decode(s+"=")
    except:
        pass
    return base64.urlsafe_b64decode(s+"==")

def jwt(url,action,key,priv_key,pload):
    global nonce
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
    r=action(url, json.dumps({"protected":protected, "payload":payload, "signature":signature}))
    nonce=r.headers['Replay-Nonce'];
    return r

# Generate private key
ES256_priv_key = ec.generate_private_key(
    ec.SECP256R1(), default_backend()
)

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

# start dns
class RecordResolver:
    def resolve(self,request,handler):
        reply = request.reply()
        reply.add_answer(*RR.fromZone("*. 60 A {}".format(args.record)))
        return reply
resolver = RecordResolver()
dns = DNSServer(resolver,port=10053,address="localhost")
dns.start_thread()

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"  "),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u" "),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u" "),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u" "),
    x509.NameAttribute(NameOID.COMMON_NAME, u" "),
])).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(domain) for domain in args.domain]),
    critical=False,
).sign(ES256_priv_key, hashes.SHA256(), default_backend())
with open("./csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

s = requests.Session()
s.verify = './pebble_https_ca.pem'
s.headers.update({'Content-Type': 'application/jose+json'})

r=s.get(args.dir)
newNonce=json.loads(r.content)['newNonce']
newAccount=json.loads(r.content)['newAccount']
keyChange=json.loads(r.content)['keyChange']
newOrder=json.loads(r.content)['newOrder']
revokeCert=json.loads(r.content)['revokeCert']

r=s.head(newNonce)
nonce=r.headers['Replay-Nonce'];

x=ES256_priv_key.public_key().public_numbers().x
y=ES256_priv_key.public_key().public_numbers().y
with open("./ec_priv_key.pem", "wb") as f:
    f.write(ES256_priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
with open("./ec_pub_key.pem", "wb") as f:
    f.write(ES256_priv_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

r = jwt(newAccount,
             s.post,
             {'jwk':{
                 "kty":"EC",
                 "crv":"P-256",
                 "x":base64url(to_bytes(x)),
                 "y":base64url(to_bytes(y)),
             }},
             ES256_priv_key,
             {"termsOfServiceAgreed": True})
account=r.headers['Location'];

r = jwt(newOrder,s.post,{"kid":account}, ES256_priv_key,
             {"identifiers":
              [ { "type": "dns", "value": domain } for domain in args.domain ]
             })
finalize=json.loads(r.content)['finalize']
authorizations=json.loads(r.content)['authorizations']

for a in authorizations:
    r = jwt(a,s.post,{"kid":account}, ES256_priv_key, "")
    challenges=json.loads(r.content)['challenges']

    for c in challenges:
        if args.challenge_type == "dns01" and c['type'] == "dns-01":
            challenge=c
            break
        if args.challenge_type == "http01" and c['type'] == "http-01":
            challenge=c
            break

    r = jwt(c['url'],s.post,{"kid":account}, ES256_priv_key, {})
    print(r.headers)
    print(r.content)
