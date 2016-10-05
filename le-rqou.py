import asn1crypto.csr
import asn1crypto.pem
import Crypto.PublicKey.RSA
import datetime
import hashlib
import jose.constants
import jose.jwk
import jose.jws
import jose.utils
import json
import link_header
import os
import time
import urllib.error
import urllib.request

# Constants of various types
USE_STAGING = True
if USE_STAGING:
    API_ROOT = 'https://acme-staging.api.letsencrypt.org'
    API_EP = API_ROOT + '/directory'
else:
    API_ROOT = 'https://acme-v01.api.letsencrypt.org'
    API_EP = API_ROOT + '/directory'

BAD_NONCE_ERROR = 'urn:acme:error:badNonce'
NONCE_RETRIES = 3

ACCOUNT_KEY_PATH = 'account_key.json'
CSR_PATH = 'test.csr'
REGISTRATION_EMAIL = 'rqou@berkeley.edu'
MAX_POLL_ATTEMPTS = 10
ACME_CHALLENGE_DIR = '.'
CERT_PATH_TMPL = 'test-{}.pem'
CERT_PATH_SYMLINK = 'test.pem'
CHAIN_PATH = 'chain.pem'


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


# Returns ((uri, data, headers), nonce)
@nonce_retry
def do_new_authz(url, nonce, acckeypriv, acckeypub, domain):
    payload = {
        'resource': 'new-authz',
        'identifier': {
            'type': 'dns',
            'value': domain
        }
    }
    fullpayload = _create_signed_object(payload, nonce, acckeypriv, acckeypub)

    req = urllib.request.Request(url=url, data=fullpayload, method='POST')
    try:
        with urllib.request.urlopen(req) as f:
            authz_uri = f.headers['Location']
            authz_data = json.loads(f.read().decode('utf-8'))
            new_nonce = f.headers['Replay-Nonce']
            return ((authz_uri, authz_data, f.headers), new_nonce)
    except urllib.error.HTTPError as e:
        authz_data = json.loads(e.read().decode('utf-8'))
        new_nonce = e.headers['Replay-Nonce']
        if authz_data['type'] == BAD_NONCE_ERROR:
            raise ACMENonceError(authz_data, e.headers, new_nonce)
        raise ACMEError(authz_data, e.headers)


# Returns the challenge object for the http challenge
def find_http_challenge(authz_data):
    for combination in authz_data['combinations']:
        if len(combination) == 1:
            idx = combination[0]
            challenge = authz_data['challenges'][idx]
            if challenge['type'] == 'http-01':
                return challenge

    raise Exception("Can't find http-01 challenge!")


# Returns nonce
# FIXME: The spec isn't too clear what exactly this should return
@nonce_retry
def do_authz_response(url, nonce, acckeypriv, acckeypub, keyauth):
    payload = {
        'resource': 'challenge',
        'keyAuthorization': keyauth.decode('utf-8')
    }
    fullpayload = _create_signed_object(payload, nonce, acckeypriv, acckeypub)

    req = urllib.request.Request(url=url, data=fullpayload, method='POST')
    try:
        with urllib.request.urlopen(req) as f:
            new_nonce = f.headers['Replay-Nonce']
            return new_nonce
    except urllib.error.HTTPError as e:
        authz_data = json.loads(e.read().decode('utf-8'))
        new_nonce = e.headers['Replay-Nonce']
        if authz_data['type'] == BAD_NONCE_ERROR:
            raise ACMENonceError(authz_data, e.headers, new_nonce)
        raise ACMEError(authz_data, e.headers)


# FIXME: Don't poll immediately?
# Returns data
def poll_authz(url):
    req = urllib.request.Request(url=url, method='GET')
    try:
        with urllib.request.urlopen(req) as f:
            authz_data = json.loads(f.read().decode('utf-8'))
            return authz_data
    except urllib.error.HTTPError as e:
        authz_data = json.loads(e.read().decode('utf-8'))
        raise ACMEError(authz_data, e.headers)


# Returns (url, nonce)
@nonce_retry
def do_new_cert(url, nonce, acckeypriv, acckeypub, csr):
    payload = {
        'resource': 'new-cert',
        'csr': jose.utils.base64url_encode(csr).decode('utf-8')
    }
    fullpayload = _create_signed_object(payload, nonce, acckeypriv, acckeypub)

    req = urllib.request.Request(url=url, data=fullpayload, method='POST')
    try:
        with urllib.request.urlopen(req) as f:
            cert_loc = f.headers['Location']
            new_nonce = f.headers['Replay-Nonce']
            return (cert_loc, new_nonce)
    except urllib.error.HTTPError as e:
        new_cert_data = json.loads(e.read().decode('utf-8'))
        new_nonce = e.headers['Replay-Nonce']
        if new_cert_data['type'] == BAD_NONCE_ERROR:
            raise ACMENonceError(new_cert_data, e.headers, new_nonce)
        raise ACMEError(new_cert_data, e.headers)


# FIXME: Don't poll immediately?
# Returns (data, up)
def poll_cert(url):
    req = urllib.request.Request(url=url, method='GET')
    try:
        with urllib.request.urlopen(req) as f:
            cert_data = f.read()
            up_link = None
            link_headers = f.headers.get_all('Link')
            if link_headers is not None:
                for link in link_headers:
                    # We always have only one link
                    parsed_link = link_header.parse(link).links[0]
                    for attr_key, attr_val in parsed_link.attr_pairs:
                        if attr_key == 'rel' and attr_val == 'up':
                            up_link = parsed_link.href
                            break
            return (cert_data, up_link)
    except urllib.error.HTTPError as e:
        cert_err_data = e.read()
        raise ACMEError(authz_data, e.headers)


def key_thumbprint(pubkey):
    pubkey_json = json.dumps(pubkey, sort_keys=True, separators=(',', ':'))
    sha256 = hashlib.sha256(pubkey_json.encode('utf-8')).digest()
    return jose.utils.base64url_encode(sha256)


def provision_challenge_file(token, keyauth):
    print("Provisioning: {} -> {}".format(keyauth, token))
    with open("{}/{}".format(ACME_CHALLENGE_DIR, token), 'wb') as f:
        f.write(keyauth)


def main():
    print("Loading account key...")
    privkey, pubkey = load_private_key(ACCOUNT_KEY_PATH)
    thumbprint = key_thumbprint(pubkey)

    print("Loading CSR...")
    csr, domains = load_csr(CSR_PATH)

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

    for domain in domains:
        print("Doing auth for \"{}\"...".format(domain))
        ((auth_url, auth_data, _), nonce) = do_new_authz(new_authz_url, nonce,
                                                         privkey, pubkey,
                                                         domain)

        http_challenge = find_http_challenge(auth_data)

        keyauth = http_challenge['token'].encode('utf-8') + b'.' + thumbprint

        challenge_url = http_challenge['uri']

        provision_challenge_file(http_challenge['token'], keyauth)

        nonce = do_authz_response(challenge_url, nonce, privkey, pubkey,
                                  keyauth)

        # Poll
        print("Polling for completion...")
        for _ in range(MAX_POLL_ATTEMPTS):
            auth_data = poll_authz(auth_url)

            if auth_data['status'] != 'pending':
                break

            time.sleep(1)

        # Delete provisioned file
        os.remove("{}/{}".format(ACME_CHALLENGE_DIR, http_challenge['token']))

        if auth_data['status'] != 'valid':
            raise Exception("Authorization failed: " + str(auth_data))

    print("Requesting cert...")
    cert_url, nonce = do_new_cert(new_cert_url, nonce, privkey, pubkey, csr)

    print("Cert is at {}".format(cert_url))

    print("Polling for completion...")
    cert_data = ""
    cert_chain_url = ""
    for _ in range(MAX_POLL_ATTEMPTS):
        cert_data, cert_chain_url = poll_cert(cert_url)
        # FIXME: This is a hack and doesn't work in all cases
        if cert_chain_url is not None and cert_chain_url[0] == '/':
            cert_chain_url = API_ROOT + cert_chain_url

        # FIXME: Ignores status code and poll interval
        if len(cert_data) > 0:
            break

        time.sleep(1)

    chain = []
    while cert_chain_url is not None:
        print("Downloading chain ({})...".format(cert_chain_url))
        chain_data, cert_chain_url = poll_cert(cert_chain_url)
        # FIXME: This is a hack and doesn't work in all cases
        if cert_chain_url is not None and cert_chain_url[0] == '/':
            cert_chain_url = API_ROOT + cert_chain_url
        chain.append(chain_data)

    print("Saving files...")
    cert_path = CERT_PATH_TMPL.format(
        datetime.datetime.now().strftime('%Y%m%d'))
    with open(cert_path, 'wb') as f:
        f.write(asn1crypto.pem.armor('CERTIFICATE', cert_data))
        # Write the chain as well
        for chaincert in chain:
            f.write(asn1crypto.pem.armor('CERTIFICATE', chaincert))

    # Do the symlink update
    try:
        os.unlink(CERT_PATH_SYMLINK)
    except FileNotFoundError:
        pass
    os.symlink(cert_path, CERT_PATH_SYMLINK)

    with open(CHAIN_PATH, 'wb') as f:
        for chaincert in chain:
            f.write(asn1crypto.pem.armor('CERTIFICATE', chaincert))


if __name__ == '__main__':
    main()
