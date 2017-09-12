#!/usr/bin/python3
# Wrap the KeyVaultClient class to gain some efficiency

from azure.common.credentials import ServicePrincipalCredentials
from azure.keyvault import KeyVaultClient
from azure.keyvault.models import CertificateBundle
from base64 import b64decode
from OpenSSL.crypto import load_pkcs12, dump_privatekey, dump_certificate, FILETYPE_PEM
from tempfile import mkstemp

class keyvault_client:
    kv_client = ''
    base_url = ''
    cert_path = ''

    def __init__(self, _app_id : str,
        _token : str,
        _base_url : str,
        _tenant : str):
        credentials = ServicePrincipalCredentials(client_id = _app_id,
            secret = _token, tenant = _tenant)
        self.kv_client = KeyVaultClient(credentials)
        self.base_url = _base_url
        
    def pfx_bytes_to_pem_file(self, pfx_bytes: bytes):
        status, out_file = mkstemp()
        pfx = load_pkcs12(pfx_bytes, '')
        with open(out_file, 'wb') as f:
            f.write(dump_privatekey(FILETYPE_PEM, pfx.get_privatekey()))
            f.write(dump_certificate(FILETYPE_PEM, pfx.get_certificate()))
        return out_file
        
    def get_pub_certificate_to_bytes(self, secret_name: str,
        secret_version: str = ""):
        cert = self.kv_client.get_secret(self.base_url, secret_name, secret_version)
        pfx = load_pkcs12(b64decode(cert.value), '')
        ret_bytes = dump_certificate(FILETYPE_PEM, pfx.get_certificate())
        return ret_bytes
        
    def get_certificate_to_file(self, secret_name: str, 
        secret_version: str = ""):
        # Have to use files on disk, to pass them to session.cert
        # Using mkstemp, which creates secure, named files
        cert = self.kv_client.get_secret(self.base_url, secret_name, secret_version)
        out_file = self.pfx_bytes_to_pem_file(b64decode(cert.value))
        return out_file
        
    def get_secret_versions(self, secret_name: str):
        versions = self.kv_client.get_certificate_versions(self.base_url, secret_name)
        ret_versions = []
        for version in versions:
            version_id = version.id.split('/')[-1]
            print("Parsed {0}".format(version_id))
            # Parsing https://vault_name.vault.azure.net/certificates/secret_name/VERSION_ID
            ret_versions.append(version_id)
        print("Got {0} version(s)".format(len(ret_versions)))
        return ret_versions