#!/usr/bin/python3

# Sample code
subscriptionID = 'SUBSCRIPTION_ID'
old_cert_path = '/path/to/old_cert.pem'
new_cert_path = '/path/to/new_cert.cer'
rdfe = rdfe_client(subscriptionID, old_cert_path)

print("Adding cert {0} to subscripiton".format(new_cert_path))
success, response = rdfe.update_management_cert(new_cert_path)
if(success):
    print("Success!")
else:
    print("Failure! {0}".format(response.status_code))

print("Listing certs")
success, response = rdfe.list_certs()
if(success):
    print("Success!")
else:
    print("Failure! {0}".format(response.status_code))
    
print("Deleting cert {0} from subscription".format(new_cert_path))
success, response = rdfe.delete_management_cert(new_cert_path)
if(success):
    print("Success!")
else:
    print("Failure! {0}".format(response.status_code))
