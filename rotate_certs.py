#!/usr/bin/python3
# Simple tool to publish management certs from Azure KeyVault to RDFE.

import argparse
import json
import os
import sys

from azure_cert_rotation import rdfe_client
from azure_cert_rotation import keyvault_client


def process_config(config_file: str):
    config = parse_config(config_file)
    for entry in config['ManagementCerts']:
        if not process_keyvault_entry(entry):
            print("ERROR: Exiting due to failure.")
            sys.exit(1)
    print("OK: All management certs processed successfully")
        

def parse_config(config_file: str):
    # TODO capture errors (file missing, file is not JSON)
    print("Parsing config file {0}".format(config_file))
    with open(config_file) as json_file:
        return json.load(json_file)
        
def get_keyvault_client(entry):
    kv_name = entry['KeyVaultName']
    kv_suffix = entry['KeyVaultSuffix']
    kv_app_id = os.environ[kv_name + '_appid']
    kv_token = os.environ[kv_name + '_token']
    kv_tenant = entry['Tenant']
    kv_base_url = "https://{0}.{1}/".format(kv_name, kv_suffix)
    print("Processing KeyVault {0}".format(kv_name))
    return keyvault_client(kv_app_id, kv_token, kv_base_url, kv_tenant)
    
def rdfe_can_list_certs(subscription_id : str, cert_file : str):
    rdfe = rdfe_client(subscription_id, cert_file)
    success, response = rdfe.list_certs()
    return success

def keyvault_find_valid_management_cert(kv_client, 
    secret_name: str, subscription_id: str):
    # Try every version of this secret to discover 
    # the 'old' cert that is valid for this subscription
    
    # Get list of secret versions
    for version in kv_client.get_secret_versions(secret_name):
        cert_file = kv_client.get_certificate_to_file(secret_name, version)
        if (rdfe_can_list_certs(subscription_id, cert_file)):
            # If successful, return True AND path to cert
            print("OK: Found valid cert for subscription {0}".format(subscription_id))
            return True, cert_file
        else:
            # If failed, SECURELY delete cert file
            print("TODO: Shred unneeded cert")
    # If all failed, return false
    print("FAIL: No valid management cert found for subscription id {0}".format(subscription_id))
    return False, ""
    
def try_rotate_certs(kv_client, secret_name: str, subscription_id: str):
    success, old_cert = keyvault_find_valid_management_cert(kv_client, secret_name, subscription_id)
    if not success:
        # No valid management certs were found for this sub. 
        return False
    # Get the *new* cert (PEM format, no private key) and upload to RDFE
    pub_bytes = kv_client.get_pub_certificate_to_bytes(secret_name)
    rdfe = rdfe_client(subscription_id, old_cert)
    success, response = rdfe.update_management_cert_bytes(pub_bytes)
    if success:
        print("OK: Uploaded new management cert")
        print("TODO: Delete old cert from RDFE")
        return True
    print("FAIL: Unable to upload cert: {0}".format(response.status_code))
    return False
    
def process_keyvault_entry(entry):
    # TODO error if fields do not exist
    kv_client = get_keyvault_client(entry)    
    
    for subscription in entry['Subscriptions']:
        secret_name = subscription['KeyVaultSecretName']
        subscription_id = subscription['SubscriptionID']
        print("Processing subscription {0}".format(subscription_id))
        cert_file = kv_client.get_certificate_to_file(secret_name)
        
        # Test the current cert to see if it's valid...
        if (rdfe_can_list_certs(subscription_id, cert_file)):
            print("OK: The latest {0} certificate is still valid for subscription {1}".format(
                secret_name, subscription_id))
            print("TODO: Delete certs from disk")
            continue

        print("WARNING: The newest {0} certificate is not valid for subscription {1}. Need to rotate.".format(
            secret_name, subscription_id))
        if not try_rotate_certs(kv_client, secret_name, subscription_id):
            print("ERROR: Unable to proceed.")
            print("TODO: Delete certs from disk")
            return False
        else:
            print("OK: Uploaded new management cert for subscription {0}".format(subscription_id))
            print("TODO: Delete certs from disk")
    print("OK: All subscriptions associated with this key vault were processed successfully")
    return True

# Parse command line arguments
def ParseArguments():
    parser = argparse.ArgumentParser(description='Manage RDFE management certs')
    parser.add_argument(
        '-c', '--config', help='Path to JSON config file. Reference sample.json for example.')
    args = parser.parse_args()
    return args
    
def main():
    args = ParseArguments()
    if not args.config:
        print("ERROR: Must specify path to JSON config file via --config option")
        sys.exit(1)
    if not os.path.isfile(args.config):
        print("ERROR: File {0} does not exist".format(args.config))
    process_config(args.config)
    
# Main functionality
main()