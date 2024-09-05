import hashlib
import hmac
import os

import requests
from urllib.parse import urlencode, quote_plus
from datetime import datetime

# Your IAM User Credentials (Replace these with your own credentials)
ACCESS_KEY = os.getenv('AWS_ACCESS_KEY_ID')
SECRET_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
# SESSION_TOKEN = os.getenv('AWS_SESSION_TOKEN')

# AWS and OpenSearch Configuration
SERVICE_NAME = 'opensearch'  # OpenSearch service name in AWS
REGION = os.getenv('REGION')
DASHBOARDS_ENDPOINT = os.getenv('DASHBOARDS_ENDPOINT')

# Create the canonical request for AWS Signature V4
def create_canonical_request(method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash):
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ])
    return canonical_request

# Generate the string to sign
def create_string_to_sign(algorithm, request_datetime, credential_scope, canonical_request_hash):
    string_to_sign = "\n".join([
        algorithm,
        request_datetime,
        credential_scope,
        canonical_request_hash
    ])
    return string_to_sign

# Calculate the signature
def calculate_signature(signing_key, string_to_sign):
    return hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

# Get the signing key
def get_signature_key(key, date_stamp, region, service):
    k_date = hmac.new(('AWS4' + key).encode('utf-8'), date_stamp.encode('utf-8'), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode('utf-8'), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode('utf-8'), hashlib.sha256).digest()
    k_signing = hmac.new(k_service, 'aws4_request'.encode('utf-8'), hashlib.sha256).digest()
    return k_signing

# Generate the signed URL
def generate_signed_url():
    method = 'GET'
    canonical_uri = '/_login/'  # Path to the OpenSearch resource
    host = DASHBOARDS_ENDPOINT
    algorithm = 'AWS4-HMAC-SHA256'
    content_type = 'application/json'
    request_payload = ''  # Empty for GET request
    payload_hash = hashlib.sha256(request_payload.encode('utf-8')).hexdigest()

    # Time-based values for the signature
    now = datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')  # e.g. 20240902T120000Z
    date_stamp = now.strftime('%Y%m%d')  # e.g. 20240902

    # Create canonical headers and query string
    canonical_headers = f'host:{host}\n'
    signed_headers = 'host'

    # Credential scope
    credential_scope = f'{date_stamp}/{REGION}/{SERVICE_NAME}/aws4_request'

    # Create the canonical query string
    canonical_querystring = urlencode({
        'X-Amz-Algorithm': algorithm,
        'X-Amz-Credential': f'{access_key}/{credential_scope}',
        'X-Amz-Date': amz_date,
        'X-Amz-Expires': '300',  # URL expiry in seconds
        'X-Amz-SignedHeaders': signed_headers
    }, quote_via=quote_plus)

    # canonical_querystring = urlencode({
    #     'X-Amz-Algorithm': algorithm,
    #     'X-Amz-Credential': f'{access_key}/{credential_scope}',
    #     'X-Amz-Date': amz_date,
    #     'X-Amz-Expires': '300',  # URL expiry in seconds
    #     'X-Amz-SignedHeaders': signed_headers,
    #     'X-Amz-Security-Token': SESSION_TOKEN
    # }, quote_via=quote_plus)

    # Create the canonical request
    canonical_request = create_canonical_request(method, canonical_uri, canonical_querystring, canonical_headers, signed_headers, payload_hash)

    # Create the string to sign
    canonical_request_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    string_to_sign = create_string_to_sign(algorithm, amz_date, credential_scope, canonical_request_hash)

    # Calculate the signature
    signing_key = get_signature_key(secret_key, date_stamp, REGION, SERVICE_NAME)
    signature = calculate_signature(signing_key, string_to_sign)

    # Add the signature to the query string
    canonical_querystring += f'&X-Amz-Signature={signature}'

    # Generate the signed URL
    signed_url = f'https://{host}{canonical_uri}?{canonical_querystring}'
    return signed_url

if __name__ == '__main__':
    signed_url = generate_signed_url()
    print("Generated Signed URL:")
    print(signed_url)
