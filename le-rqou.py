import Crypto.PublicKey.RSA
import jose.jwk
import json
import urllib.request

# Constants of various types
USE_STAGING = True
if USE_STAGING:
    API_EP = 'https://acme-staging.api.letsencrypt.org/directory'
else:
    API_EP = 'https://acme-v01.api.letsencrypt.org/directory'

NONCE_HEADER = 'Replay-Nonce'

def get_directory(url):
    req = urllib.request.Request(url=url)
    with urllib.request.urlopen(req) as f:
        return (json.loads(f.read().decode('utf-8')), f.headers[NONCE_HEADER])

#print(get_directory(API_EP))

def load_private_key(file):
    with open(file, 'r') as f:
        privkey = json.loads(f.read())

    # Only support RSA keys
    assert privkey['kty'] == "RSA"

    n = jose.jwk.base64_to_long(privkey['n'])
    e = jose.jwk.base64_to_long(privkey['e'])
    d = jose.jwk.base64_to_long(privkey['d'])
    p = jose.jwk.base64_to_long(privkey['p'])
    q = jose.jwk.base64_to_long(privkey['q'])
    qi = jose.jwk.base64_to_long(privkey['qi'])

    if False:
        # Validate key
        assert p * q == n
        assert (d * e) % ((p - 1) * (q - 1)) == 1
        assert (q * qi) % p == 1

    return Crypto.PublicKey.RSA.construct((n, e, d, p, q, qi))

print(load_private_key("account_key.json"))
