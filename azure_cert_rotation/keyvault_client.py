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

    def __init__(self, 
        _keyvault_name : str,
        _keyvault_sufix : str,
        _app_id : str,
        _token : str,
        _tenant : str):
        self.keyvault_name = _keyvault_name
        self.keyvault_suffix = _keyvault_suffix
        self.base_url = "https://{0}.{1}/".format(_keyvault_name, _keyvault_suffix)
        if _app_id is not None and _token is not None and _tenant is not None:
            # Use App ID
            credentials = ServicePrincipalCredentials(client_id = _app_id,
                secret = _token, tenant = _tenant)
            self.kv_client = KeyVaultClient(credentials)
            return
        # Try IMDS first and fallback to MSI if needed
        success, imds_msg = self._try_get_identity_token()
        if success:
            self.kv_client = KeyVaultClient(self.token)
            return
        success, msi_msg = self._try_get_identity_token(False)
        if success:
            self.kv_client = KeyVaultClient(self.token)
            return
        raise Exception('Failed to get Identity token: [{0}] - [{1}]'.format(
            imds_msg, msi_msg))
            
        
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
        
    def _try_get_identity_token(self, use_imds=True):
        '''
        Attempts to get AAD token for KeyVault using IMDS (default) or MSI
        - If successful, return True and empty string
        - If failed, return False and an error message
        '''
        headers = {'Metadata':'true'}
        resource = 'https://{0}'.format(self.keyvault_suffix)
        msi_data = {'resource': resource}
        msi_url = 'http://localhost:50342/oauth2/token'
        imds_url = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={0}'.format(
            resource)
        error_template = 'Failed to get token from {0} due to'
        try:
            if use_imds:
                error_prefix = error_template.format('IMDS')
                resp = requests.get(imds_url, headers=headers)
            else:
                error_prefix = error_template.format('MSI')
                resp = requests.post(msi_url, data=msi_data, headers=headers)
        except ConnectionError as ex:
            return False, '{0} connection error: {1}'.format(error_prefix, str(ex))
        if resp.status_code != 200:
            return False, '{0} status code {1}'.format(error_prefix, resp.status_code)
        try:
            self.token = json.loads(resp.text)['access_token']
        except ValueError as ex:
            return False, '{0} JSON decoding error: {1}'.format(error_prefix, str(ex))
        except KeyError as ex:
            return False, '{0} missing JSON key [access_token]'.format(error_prefix)
        return True, ''