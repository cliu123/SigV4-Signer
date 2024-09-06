# How to use the script
# Install dependencies
`pip install -r requirements.txt`

# Set environment variables
export AWS_ACCESS_KEY_ID=<access_key_of_iam_user>
export AWS_SECRET_ACCESS_KEY=<secret_key_of_iam_user>
export REGION=<region_of_neo_app> // e.g us-west-2
export DASHBOARDS_ENDPOINT= <Neo_dashboards_url> // e.g'dashboards-cgliugamedayidc0904-f46qvyl4u4b0c6cb3c3a.us-west-2.opensearch-beta.amazonaws.co
# Run script.py
`Python script.py`
# Example Output
```
Signed URL:
 https://dashboards-cgliugamedayidc0904-f46qvyl4u4b0c6cb3c3a.us-west-2.opensearch-beta.amazonaws.com/_login/?X-Amz-Date=20240906T072049Z&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA5MIG5PUPCAWJQNGB%2F20240906%2Fus-west-2%2Fopensearch%2Faws4_request&X-Amz-SignedHeaders=host%3Bx-amz-date&X-Amz-Signature=310d1023672452a07f60349b9b035ed84c2fb8afc69f3e4de051c56898f18a2f

