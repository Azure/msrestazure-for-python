#--------------------------------------------------------------------------
#
# Copyright (c) Microsoft Corporation. All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the ""Software""), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#--------------------------------------------------------------------------


from azure.mgmt.storage import StorageManagementClient
from azure.multiapi.storage.v2018_03_28.blob.blockblobservice import BlockBlobService
from msrestazure.azure_local_creds_prober import (get_client_through_local_creds_probing,
                                                  get_creds_through_local_probing)

# test management plane
client = get_client_through_local_creds_probing(StorageManagementClient)
accounts = list(client.storage_accounts.list())
print('Found {} accounts'.format(len(accounts)))

# test storage data plane
creds = get_creds_through_local_probing(resource="https://storage.azure.com/")
test_storage_account, container, blob, file_to_upload = 'teststor12345678', 'temp', 'hey.exe', r'c:\temp\hey.exe'
storage_data_client = BlockBlobService(token_credential=creds, account_name=test_storage_account)
storage_data_client.create_blob_from_path(container, blob, file_to_upload)
print('uploaded')

