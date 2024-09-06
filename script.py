import hashlib
import hmac
import requests
from urllib.parse import urlencode, quote_plus
from datetime import datetime

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.session import Session
from botocore import crt

# AWS and OpenSearch Configuration
SERVICE_NAME = 'opensearch'  # OpenSearch service name in AWS
REGION = 'us-west-2'  # Ensure this matches the region of your OpenSearch cluster
DASHBOARDS_ENDPOINT = 'dashboards-cgliugamedayidc0904-f46qvyl4u4b0c6cb3c3a.us-west-2.opensearch-beta.amazonaws.com'

# Create the canonical request for AWS Signature V4
def create_canonical_request(method, canonical_uri, canonical_querystring, canonical_headers, signed_headers,
                             payload_hash):
    canonical_request = "\n".join([
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    ])
    print("Canonical Request:\n", canonical_request)
    return canonical_request


# Generate the string to sign
def create_string_to_sign(algorithm, request_datetime, credential_scope, canonical_request_hash):
    string_to_sign = "\n".join([
        algorithm,
        request_datetime,
        credential_scope,
        canonical_request_hash
    ])
    print("String to Sign:\n", string_to_sign)
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
def create_aws_signed_request():
    # Initialize a session to retrieve credentials
    session = Session()

    # Set up the request
    url = f'https://{DASHBOARDS_ENDPOINT}/_login/'
    method = 'GET'
    headers = {
        'Host': DASHBOARDS_ENDPOINT
    }

    # Create the AWSRequest object (similar to signableRequest in Java)
    request = AWSRequest(method=method, url=url, headers=headers)
    print("!!!! not yet signed request headers")
    print(request.headers)

    # Sign the request using SigV4Auth
    credentials = session.get_credentials().get_frozen_credentials()
    signer = crt.auth.CrtSigV4Auth(session.get_credentials(), SERVICE_NAME, REGION)
    print("!!!!!before signing request!!!!!")
    print(request.headers)
    signer.add_auth(request)
    print("!!!!!after signing request!!!!!")
    print(request.headers)

    # Extract the signed headers and URL
    signed_url = request.url
    signed_headers = request.headers

    print("!!!! signed request headers")
    print(request.headers)

    return signed_url, signed_headers


def generate_signed_url():
    method = 'GET'
    canonical_uri = '/_login/'  # Path to the OpenSearch resource
    host = DASHBOARDS_ENDPOINT
    algorithm = 'AWS4-HMAC-SHA256'
    request_payload = ''  # Empty for GET request
    payload_hash = hashlib.sha256(request_payload.encode('utf-8')).hexdigest()

    # Time-based values for the signature
    # now = datetime.utcnow()
    # amz_date = now.strftime('%Y%m%dT%H%M%SZ')  # e.g. 20240904T223312Z
    # date_stamp = now.strftime('%Y%m%d')  # e.g. 20240904

    signed_url, signed_headers = create_aws_signed_request()

    amz_date = signed_headers.get('X-Amz-Date')
    auth_header = signed_headers.get('Authorization')
    auth_arr = auth_header.split(",")

    signature = ""
    signed_headers = ""
    credential = ""
    for auth_h in auth_arr:
        key_val = auth_h.split("=")
        if key_val[0].strip().lower() == "signature":
            signature = key_val[1].strip()
        elif key_val[0].strip().lower() == "signedheaders":
            signed_headers = key_val[1].strip()
        elif key_val[0].strip().lower() == "aws4-hmac-sha256 credential":
            credential = key_val[1].strip()

    print("^^^^^^^^^^^")
    print(signature)
    print(signed_headers)
    print(credential)

    # Canonical headers (including x-amzn-account-id and other context-specific headers)
    # canonical_headers = (
    #     f'host:{host}\n'
    #     f'x-aoss-client-ip-address:10.20.30.40\n'  # This IP address is static per original Java script
    # )

    # Additional context headers like in the Java script
    # additional_headers = {
    #     'x-amzn-service-code': 'aoss',
    #     'x-amzn-aosd-application-id': 'nshdgahsfdg',
    #     'x-amzn-aosd-application-name': 'abcd',
    #     'x-amzn-vpce-policy-version': 's3://phhedau-nlb-logs/resourcePolicy',
    #     'x-amzn-vpce-config': '1',
    #     'x-amzn-aoss-sgw-cell-id': 'c00',
    # }

    # Add headers to the canonical headers and signed headers
    # for key, value in additional_headers.items():
    #     canonical_headers += f'{key}:{value}\n'

    # signed_headers = 'host;x-amzn-account-id;x-aoss-client-ip-address;x-amzn-service-code;x-amzn-aosd-application-id;x-amzn-aosd-application-name;x-amzn-vpce-policy-version;x-amzn-vpce-config;x-amzn-aoss-sgw-cell-id'
    # signed_headers = 'host;x-amz-date'

    # Credential scope
    # credential_scope = f'{date_stamp}/{REGION}/{SERVICE_NAME}/aws4_request'

    # Create the canonical query string
    query_params = {
        'X-Amz-Date': amz_date,
        'X-Amz-Algorithm': algorithm,
        'X-Amz-Credential': credential,
        'X-Amz-SignedHeaders': signed_headers
    }

    # If using temporary credentials, include the security token in the query string
    # if SESSION_TOKEN:
    #     query_params['X-Amz-Security-Token'] = SESSION_TOKEN

    canonical_querystring = urlencode(query_params, quote_via=quote_plus)

    # Create the canonical request
    # canonical_request = create_canonical_request(method, canonical_uri, canonical_querystring, None,
    #                                              signed_headers, payload_hash)

    # Create the string to sign
    # canonical_request_hash = hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()
    # string_to_sign = create_string_to_sign(algorithm, amz_date, credential_scope, canonical_request_hash)

    # Calculate the signature
    # signing_key = get_signature_key(SECRET_KEY, date_stamp, REGION, SERVICE_NAME)
    # signature = calculate_signature(signing_key, string_to_sign)

    # Add the signature to the query string
    canonical_querystring += f'&X-Amz-Signature={signature}'

    # Generate the signed URL
    signed_url = f'https://{host}{canonical_uri}?{canonical_querystring}'
    print("Signed URL:\n", signed_url)
    return signed_url


if __name__ == '__main__':
    signed_url = generate_signed_url()
