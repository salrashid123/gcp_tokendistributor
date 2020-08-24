import logging
import time
import grpc
import tokenservice_pb2
import tokenservice_pb2_grpc
import base64
import json

from google.cloud import storage

import google.oauth2.id_token

from google.auth.transport import requests
from google.oauth2 import service_account

target_audience = "https://tokenserver"

tokenServerAddress = '35.238.237.173:50051'

def run_standard():

    cert = open('tokenclient.crt', 'rb').read()
    key = open('tokenclient.key', 'rb').read()
    ca_cert = open('tls-ca.crt', 'rb').read()
    scc = grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=key,
        certificate_chain=cert
    )

    ## Get ID Token
    request = requests.Request()
    id_token = google.oauth2.id_token.fetch_id_token(request, target_audience)
    tok = grpc.access_token_call_credentials(id_token)
    ccc = grpc.composite_channel_credentials(scc, tok)
    options=(('grpc.ssl_target_name_override', 'tokenservice.esodemoapp2.com'),)

    channel = grpc.secure_channel(tokenServerAddress, ccc, options)
    stub = tokenservice_pb2_grpc.TokenServiceStub(channel)
    response = stub.GetToken(tokenservice_pb2.TokenRequest(requestId='sal',processID="df"))


    ## Get secrets
    logging.info("ResponseID: " + response.responseID)
    logging.info("AESKey: " + response.sealedAESKey.decode('ISO-8859-1'))
    logging.info("RSAKey: " + response.sealedRSAKey.decode('utf-8'))
    logging.info("RawKey: " + response.rawKey.decode('utf-8'))

    ## If the rawKey is a GCP Service Account, then load that to bootstrap GCP Credentials
    sa_cert= json.loads(response.rawKey.decode('utf-8'))
    creds = service_account.Credentials.from_service_account_info(sa_cert)
    scoped_creds = creds.with_scopes(['https://www.googleapis.com/auth/cloud-platform'])
    storage_client = storage.Client(credentials=scoped_creds) 
    bucket = storage_client.bucket('tssecret')
    blob = bucket.get_blob('secretfile.txt')
    secret_data = blob.download_as_string()
    print(secret_data) 

    ## If the "sealedAESKey" is a symmetric CSEK key, use that to download an object

    encryption_key = base64.b64decode(response.sealedAESKey.decode('utf-8'))
    blob = bucket.get_blob('cseksecretfile.txt', encryption_key=encryption_key)
    secret_data = blob.download_as_string()
    print(secret_data) 

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    run_standard()
