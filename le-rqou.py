import asn1crypto.csr
import asn1crypto.pem
import Crypto.PublicKey.RSA
import jose.constants
import jose.jwk
import jose.jws
import json
import link_header
import urllib.error
import urllib.request

# Constants of various types
USE_STAGING = True
if USE_STAGING:
    API_EP = 'https://acme-staging.api.letsencrypt.org/directory'
else:
    API_EP = 'https://acme-v01.api.letsencrypt.org/directory'

BAD_NONCE_ERROR = 'urn:acme:error:badNonce'
NONCE_RETRIES = 3

ACCOUNT_KEY_PATH = 'account_key.json'
CSR_PATH = 'test.csr'
REGISTRATION_EMAIL = 'rqou@berkeley.edu'


class ACMEError(Exception):
    def __init__(self, errdoc, headers):
        self.errdoc = errdoc
        self.headers = headers


# Apparently you can occasionally get a bad nonce error for no reason at all
class ACMENonceError(ACMEError):
    def __init__(self, errdoc, headers, new_nonce):
        super().__init__(errdoc, headers)
        self.new_nonce = new_nonce


# Returns (dict, nonce)
def get_directory(url):
    req = urllib.request.Request(url=url)
    with urllib.request.urlopen(req) as f:
        return (json.loads(f.read().decode('utf-8')),
                f.headers['Replay-Nonce'])


def nonce_retry(fn):
    def _nonce_retry_wrapper(*args):
        for _ in range(NONCE_RETRIES):
            try:
                return fn(*args)
            except ACMENonceError as e:
                print("WARN: Bad nonce happened!")
                # Really ugly, assumes all functions take the nonce as the
                # second arg
                args = list(args)
                args[1] = e.new_nonce
        raise Exception("Too many bad nonces!")
    return _nonce_retry_wrapper


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


def _create_signed_object(payload, nonce, acckeypriv, acckeypub):
    protected = {
        'nonce': nonce,
        # WTF? Why not needed?
        # 'url': url,
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

    return fullpayload


# Returns ((uri, data, headers), nonce)
@nonce_retry
def do_account_register(url, nonce, acckeypriv, acckeypub, email):
    payload = {
        # WTF?
        'resource': 'new-reg',
        'contact': ['mailto:' + email]
    }
    fullpayload = _create_signed_object(payload, nonce, acckeypriv, acckeypub)

    req = urllib.request.Request(url=url, data=fullpayload, method='POST')
    try:
        with urllib.request.urlopen(req) as f:
            reg_uri = f.headers['Location']
            reg_data = json.loads(f.read().decode('utf-8'))
            new_nonce = f.headers['Replay-Nonce']
            return ((reg_uri, reg_data, f.headers), new_nonce)
    except urllib.error.HTTPError as e:
        reg_uri = e.headers['Location']
        reg_data = json.loads(e.read().decode('utf-8'))
        new_nonce = e.headers['Replay-Nonce']
        if reg_data['type'] == BAD_NONCE_ERROR:
            raise ACMENonceError(reg_data, e.headers, new_nonce)
        # Conflict is OK
        if reg_data['status'] == 409:
            return ((reg_uri, reg_data, e.headers), new_nonce)
        raise ACMEError(reg_data, e.headers)


# Returns nonce
@nonce_retry
def do_tos(url, nonce, acckeypriv, acckeypub):
    payload = {
        # WTF?
        'resource': 'reg',
    }
    fullpayload = _create_signed_object(payload, nonce, acckeypriv, acckeypub)

    req = urllib.request.Request(url=url, data=fullpayload, method='POST')
    old_tos = None
    new_tos = None
    try:
        with urllib.request.urlopen(req) as f:
            reg_data = json.loads(f.read().decode('utf-8'))
            nonce = f.headers['Replay-Nonce']

            if 'agreement' in reg_data:
                old_tos = reg_data['agreement']

            for link in f.headers.get_all('Link'):
                # We always have only one link
                parsed_link = link_header.parse(link).links[0]
                for attr_key, attr_val in parsed_link.attr_pairs:
                    if attr_key == 'rel' and attr_val == 'terms-of-service':
                        new_tos = parsed_link.href
                        break
    except urllib.error.HTTPError as e:
        reg_data = json.loads(e.read().decode('utf-8'))
        new_nonce = e.headers['Replay-Nonce']
        if reg_data['type'] == BAD_NONCE_ERROR:
            raise ACMENonceError(reg_data, e.headers, new_nonce)
        raise ACMEError(reg_data, e.headers)

    if old_tos != new_tos:
        print("Agreeing to new TOS...")

        payload = {
            # WTF?
            'resource': 'reg',
            'agreement': new_tos
        }
        fullpayload = _create_signed_object(payload, nonce,
                                            acckeypriv, acckeypub)

        req = urllib.request.Request(url=url, data=fullpayload, method='POST')

        try:
            with urllib.request.urlopen(req) as f:
                reg_data = json.loads(f.read().decode('utf-8'))
                nonce = f.headers['Replay-Nonce']
        except urllib.error.HTTPError as e:
            reg_data = json.loads(e.read().decode('utf-8'))
            new_nonce = e.headers['Replay-Nonce']
            if reg_data['type'] == BAD_NONCE_ERROR:
                raise ACMENonceError(reg_data, e.headers, new_nonce)
            raise ACMEError(reg_data, e.headers)

    return nonce


# Returns (csr_der, domains)
def load_csr(path):
    with open(path, 'rb') as f:
        csr_pem = f.read()
    _, _, csr_der = asn1crypto.pem.unarmor(csr_pem)
    csr_obj = asn1crypto.csr.CertificationRequest.load(csr_der)

    domains = set()

    # CN
    subj = csr_obj['certification_request_info']['subject'].native
    if 'common_name' in subj:
        cn = subj['common_name']
        domains.add(cn)

    # SAN
    attribs = csr_obj['certification_request_info']['attributes'].native
    san = None
    for attrib in attribs:
        if attrib['type'] == 'extension_request':
            extns_set = attrib['values']
            for extns in extns_set:
                for extn in extns:
                    if extn['extn_id'] == 'subject_alt_name':
                        # Can't have multiple SAN blocks??
                        assert san is None
                        san = extn['extn_value']
                        break
    if san is not None:
        domains = domains.union(san)

    assert len(domains) > 0
    return (csr_der, domains)


def main():
    print("Loading account key...")
    privkey, pubkey = load_private_key(ACCOUNT_KEY_PATH)

    print("Loading CSR...")
    print(load_csr(CSR_PATH))
    return

    print("Poking directory...")
    directory, nonce = get_directory(API_EP)
    new_reg_url = directory['new-reg']
    new_authz_url = directory['new-authz']
    new_cert_url = directory['new-cert']
    print("URLs are:\n\tnew-reg: {}\n\tnew-authz: {}\n\tnew-cert: {}".format(
        new_reg_url, new_authz_url, new_cert_url))

    print("Finding registration...")
    ((reg_url, _, _), nonce) = do_account_register(new_reg_url, nonce,
                                                   privkey, pubkey,
                                                   REGISTRATION_EMAIL)
    nonce = do_tos(reg_url, nonce, privkey, pubkey)
    print("Registration is {}".format(reg_url))

if __name__ == '__main__':
    main()
