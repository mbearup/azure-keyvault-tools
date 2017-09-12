# azure-keyvault-tools
A simple tool to fetch management certs from Azure KeyVault and publish them to RDFE

## Prerequisites
* Create an azure KeyVault
* Create a management certificate, either self-signed or directly within KeyVault
* Set a KeyVault policy to renew the certificate at a regular interval
* Upload the public .cer of this certificate to RDFE

## Execution
* Use the provided sample.json to create a config file which references your KeyVault and subscription ID
* Run `rotate_certs.py -c your_config.json`

## Flow
* Connects to RDFE with the newest cert. If this succeeds, then no changes necessary.
* If this fails, get a list of all certificate versions stored under this name.
* Try all certificates until can successfully authenticate with RDFE.
* Use the *old* cert to publish the *new* cert.
* Then use the *new* cert to remove the *old cert.
