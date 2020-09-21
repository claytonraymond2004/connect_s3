import json
import urllib.request

# Hold response to Forescout EyeExtend Connect
# Like the action response, the response object must have a "succeeded" field to denote success. It can also optionally have
# a "result_msg" field to display a custom test result message.
response = {}

# Get Elasticsearch API Details (To delete data from)
s3_bucket = params["connect_s3_bucket"]
s3_key = params["connect_s3_key"]
s3_doc_id = params["cookie"]


try:
    # Prepare API request to elastic
    credentials = ('%s:%s' % (s3_bucket, s3_key))
    encoded_credentials = base64.b64encode(credentials.encode('ascii'))
    s3_headers = {
        "Content-Type": "application/json",
        'Authorization': 'Basic %s' % encoded_credentials.decode("ascii")
    }
    s3_request = urllib.request.Request(s3_bucket + "/" + s3_bucket + "/_doc/" + s3_doc_id, headers=s3_headers, method='DELETE')

    # Make API request to elasticsearch API to put document
    s3_resp = urllib.request.urlopen(s3_request, context=ssl_context) # To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
    s3_resp_parse = json.loads(s3_resp.read().decode('utf-8'))
    logging.debug(s3_resp_parse)
    
    # Check response from elasticsearch
    if "result" in s3_resp_parse:
        logging.error("Failed to delete host data in S3!")
        response["succeeded"] = False
        response["result_msg"] = "Failed API request to S3!"
    else:
        logging.info("Deleted host data to S3!")
        response["succeeded"] = True
        response["result_msg"] = "Made delete API request to S3!"
except Exception as e:
    logging.error(e)
    response["succeeded"] = False
    response["result_msg"] = "Exception! Something went wrong! See the debug logs for more info."