from azure.mgmt.storage import StorageManagementClient
from msrestazure.azure_local_creds_prober import AzureLocalCredentialProber

prober = AzureLocalCredentialProber()
client = StorageManagementClient(prober, prober.subscription_id)
accounts = list(client.storage_accounts.list())
print('Found {} accounts'.format(len(accounts)))
