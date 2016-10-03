import Crypto.PublicKey.RSA
import jose.constants
import jose.jwk
import jose.jws
import json
import urllib.error
import urllib.request

# Constants of various types
USE_STAGING = True
if USE_STAGING:
    API_EP = 'https://acme-staging.api.letsencrypt.org/directory'
else:
    API_EP = 'https://acme-v01.api.letsencrypt.org/directory'

NONCE_HEADER = 'Replay-Nonce'
NONCE_RETRIES = 3

# Returns (dict, nonce)
def get_directory(url):
    req = urllib.request.Request(url=url)
    with urllib.request.urlopen(req) as f:
        return (json.loads(f.read().decode('utf-8')), f.headers[NONCE_HEADER])

directory, nonce = get_directory(API_EP)
new_reg_url = directory['new-reg']
#print(new_reg_url)
#print(get_new_nonce(API_EP))

# Really ugly, assumes all functions return the nonce as second arg
def nonce_retry(fn):
    pass

def load_private_key(file):
    with open(file, 'r') as f:
        privkey = json.loads(f.read())

    # Only support RSA keys
    assert privkey['kty'] == 'RSA'

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

    # WARNING! The PyCrypto API expects the last argument to be p^{-1} mod q,
    # but the JSON file that certbot uses stores q^{-1} mod p. We therefore
    # exchange p and q here.
    fullkey = Crypto.PublicKey.RSA.construct((n, e, d, q, p, qi))
    pubkey = {'kty': 'RSA', 'e': privkey['e'], 'n': privkey['n']}
    return (fullkey, pubkey)

privkey, pubkey = load_private_key("account_key.json")

# Returns ((uri, tos_old, tos_new), nonce)
def do_account_register(url, nonce, acckeypriv, acckeypub, email):
    payload = {
        'contact': ['mailto:' + email]
    }
    protected = {
        'nonce': nonce,
        'url': url,
        'jwk': acckeypub
    }
    sig = jose.jws.sign(payload, acckeypriv, protected,
                        algorithm=jose.constants.ALGORITHMS.RS256)

    # Somewhat silly resplit of the concatenated data
    enc_protected, enc_payload, enc_sig = sig.split('.')

    fullpayload = json.dumps({
        'protected': enc_protected,
        'payload': enc_payload,
        'signature': enc_sig
    }).encode('utf-8')

    req = urllib.request.Request(url=url, data=fullpayload, method='POST')
    try:
        with urllib.request.urlopen(req) as f:
            return (f.read(), f.headers.as_string())
    except urllib.error.HTTPError as e:
        return (e.read(), e.headers.as_string())

nonce='foo'
print(do_account_register(new_reg_url, nonce, privkey, pubkey, 'rqou@berkeley.edu'))
