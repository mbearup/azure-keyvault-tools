#!/usr/bin/python3
# Uses API described here: https://msdn.microsoft.com/en-us/library/azure/jj154123.aspx

import requests

from base64 import b64encode
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.hashes import SHA1

class rdfe_client:
    cert_path = ''
    management_endpoint = ''
    subscription_id = ''
    url = ''
    version_header = {'x-ms-version': '2012-03-01'}
    
    def __init__(self, _subscription_id : str,
        _cert_path : str,
        _endpoint: str = "management.core.windows.net"):
        self.cert_path = _cert_path
        self.management_endpoint = _endpoint
        self.subscription_id = _subscription_id
        self.url = 'https://{0}/{1}/certificates'.format(self.management_endpoint, self.subscription_id)
        
    def create_session(self):
        session = requests.Session()
        session.cert = self.cert_path
        session.headers.update(self.version_header)
        return session
        
    def list_certs(self):
        session = self.create_session()
        response = session.get(self.url)
        success = (response.status_code is 200)
        return success, response

    def delete_management_cert(self, old_cert_path: str):
        session = self.create_session()
        old_cert_bytes = open(old_cert_path, 'rb').read()
        old_cert = load_pem_x509_certificate(old_cert_bytes, default_backend())
        old_cert_thumbprint = old_cert.fingerprint(SHA1()).hex()
        delete_url = "{0}/{1}".format(self.url, old_cert_thumbprint)
        response = session.delete(delete_url)
        success = (response.status_code == 200)
        return success, response
        
    def update_management_cert_bytes(self, new_cert_bytes: bytes):
        session = self.create_session()
        session.headers.update({'Content-Type': 'application/xml'})
        
        # Get Thumbprint, base64-encoded pubkey, and base64-encoded cert
        new_cert = load_pem_x509_certificate(new_cert_bytes, default_backend())
        new_cert_thumbprint = new_cert.fingerprint(SHA1()).hex()
        new_pubkey_b64 = b64encode(new_cert.public_key().public_bytes(Encoding.DER, PublicFormat.PKCS1)).decode('utf-8')
        new_cert_b64 = b64encode(new_cert.public_bytes(Encoding.DER)).decode('utf-8')

        content = """<SubscriptionCertificate xmlns="http://schemas.microsoft.com/windowsazure">
       <SubscriptionCertificatePublicKey>{0}</SubscriptionCertificatePublicKey>
       <SubscriptionCertificateThumbprint>{1}</SubscriptionCertificateThumbprint>
       <SubscriptionCertificateData>{2}</SubscriptionCertificateData>
    </SubscriptionCertificate>""".format(new_pubkey_b64, new_cert_thumbprint, new_cert_b64)
        response = session.post(self.url, data=content)
        success = (response.status_code is 201)
        return success, response
        
        
    def update_management_cert(self, new_cert_path: str):
        new_cert_bytes = open(new_cert_path, 'rb').read()
        return self.update_management_cert_bytes(new_cert_bytes)