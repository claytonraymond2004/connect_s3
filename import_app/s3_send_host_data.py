import json
from urllib import request
from urllib.parse import quote_plus , urlparse
import base64, datetime, hashlib, hmac, urllib
import re
import fnmatch

# HELPER FUNCTIONS FOR AWS API 
# Key derivation functions. See:
# http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html#signature-v4-examples-python
def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'aws4_request')
    return kSigning

# Hold response to Forescout EyeExtend Connect
# Like the action response, the response object must have a "succeeded" field to denote success. It can also optionally have
# a "result_msg" field to display a custom test result message.
response = {}

# Get Forescout OIM Web API Details (We connect to OIM to get data)
forescout_url = params["connect_s3_forescout_url"]
forescout_jwt_token = params["connect_authorization_token"]

# Get AWS S3 API Details (To send data to)
s3_baseUrl = params["connect_s3_baseurl"]
if params["connect_s3_send_host_data_baseurl_override"] != "null":
    s3_baseUrl = params["connect_s3_send_host_data_baseurl_override"]
s3_bucket = params["connect_s3_bucket"]
if params["connect_s3_send_host_data_bucket_override"] != "null":
    s3_bucket = params["connect_s3_send_host_data_bucket_override"]
s3_region = params["connect_s3_region"]
if params["connect_s3_send_host_data_region_override"] != "null":
    s3_region = params["connect_s3_send_host_data_region_override"]
s3_accesskey = params["connect_s3_accesskey"]
s3_secretkey = params["connect_s3_secretkey"]

# Get parameter details from action dialog
host_ip = params["ip"] # Host IP address
send_all_data = params["connect_s3_send_host_data_allfields"] == "true" # If all data should be included from host
specified_data = params["connect_s3_send_host_data_hostfields"] # or specific parsed version
host_data = {} # don't have host data yet

# Create request to get host data from Forescout
forescout_headers = {"Authorization": forescout_jwt_token}
forescout_request = urllib.request.Request(forescout_url + "/api/hosts/ip/" + host_ip, headers=forescout_headers)

logging.debug("Preparing to get host data from Forescout Web API")

try:
    # Make API request to Forescout Web API For host
    forescout_resp = urllib.request.urlopen(forescout_request, context=ssl_context) # To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
    if forescout_resp.getcode() == 200:
        logging.debug("Got data from Forescout Web API")
        # Load response data
        host_data = json.loads(forescout_resp.read().decode('utf-8'))

        # Process host data with respect to EyeExtend Connect Send Data action specification
        logging.debug("Preparing S3 payload")
        s3_payload = {}
        if(send_all_data):
            # If send all is checked, we send all, not need for extra formatting
            s3_payload = host_data["host"]
        else: 
            # Add IP and mac field to data and setup for fields data
            s3_payload["time"] = datetime.now().isoformat()
            s3_payload["ip"] = host_data["host"]["ip"]
            s3_payload["mac"] = host_data["host"]["mac"]
            s3_payload["id"] = host_data["host"]["id"]
            s3_payload["fields"] = {}

            # Take user input and extract requested fields and alias name
            specified_fields = specified_data.split(",") # split the stirng format at commas

            # Take each field specification and get the data form the host_data
            for field_token in specified_fields:
                re_match = re.match("(?P<field_name>.*)\((?P<alias_name>.*)\)", field_token) # Regex to break up the format
                field_name = re_match.group('field_name')
                alias_name = re_match.group('alias_name')

                # Check if there is a wildcard character in the field speccification
                if '*' in field_name:
                    # Make sure only 1 wildcard character entered
                    if field_name.count("*") > 1 or alias_name.count("*") > 1:
                        raise Exception("Only 1 wildcard (*) character allowed in a field or alias specification")
                    elif alias_name.count("*") < 1:
                        raise Exception("Wildcard (*) character not expressed in alias field -- must be provided to preserve uniqueness of findings in output.")
                    else:
                        # convert wildcard to regex and make a token for what the wildcard matches
                        dynamic_match_re = field_name.replace("*", "(?P<token>.*)")
                        # search through all keys looking for any matches
                        for key in host_data["host"]["fields"].keys():
                            match = re.match(dynamic_match_re, key)
                            if match:
                                s3_payload["fields"][alias_name.replace("*", match.group("token"))] = host_data["host"]["fields"][key]
                else:
                    # Normal find key value and put in payload
                    if field_name in host_data["host"]["fields"]:
                        #if field name starts with script_result, it may be JSON data we can parse before sending over
                        if "script_result" in field_name:
                            try:
                                #logging.debug("Trying parse script_result value as JSON: {},{}".format(field_name, alias_name))
                                s3_payload["fields"][alias_name] = {
                                    "timestamp": host_data["host"]["fields"][field_name]["timestamp"],
                                    "value": json.loads(host_data["host"]["fields"][field_name]["value"])
                                }
                                logging.debug("Parsed script_result value as JSON: {},{}".format(field_name, alias_name))
                            except Exception as e:
                                s3_payload["fields"][alias_name] = host_data["host"]["fields"][field_name]
                                logging.debug("Unable to parse script_result value as JSON: {},{}".format(field_name, alias_name))
                        else:
                            s3_payload["fields"][alias_name] = host_data["host"]["fields"][field_name]

        # Debugging, drop payload that will be sent to S3 after any processing/renmaing/field drops
        logging.debug("Payload being sent to S3: %s" % json.dumps(s3_payload))

        # Prepare API request to AWS S3
        # Set some request variables
        s3_method = 'PUT'
        s3_service = 's3'
        s3_host = urlparse(s3_baseUrl).netloc
        s3_algorithm = 'AWS4-HMAC-SHA256'
        s3_content_type = 'application/json'
        s3_canonical_uri = '/%s/%s.json' % (s3_bucket, host_ip)
        s3_request_url = "https://%s%s" % (s3_host, s3_canonical_uri)
        s3_canonical_querystring = ''

        # Get date/time for request
        t = datetime.datetime.utcnow()
        s3_amz_date = t.strftime('%Y%m%dT%H%M%SZ') # Format date as YYYYMMDD'T'HHMMSS'Z'
        s3_datestamp = t.strftime('%Y%m%d') # Date w/o time, used in credential scope

        # create some hashes of content
        s3_payload_bytes = bytes(json.dumps(s3_payload), encoding="utf-8")
        s3_payload_hash_sha256 = hashlib.sha256(s3_payload_bytes).hexdigest()
        s3_payload_hash_md5 = base64.b64encode(hashlib.md5(s3_payload_bytes).digest()).decode('utf-8')

        # Create the canonical headers. Header names must be trimmed and lowercase, and sorted in code point order from low to high. Note that there is a trailing \n.
        s3_canonical_headers = 'content-md5:' + s3_payload_hash_md5 + '\n' +'content-type:' + s3_content_type + '\n' + 'host:' + s3_host + '\n' + 'x-amz-date:' + s3_amz_date + '\n'

        # Create the list of signed headers. This lists the headers in the canonical_headers list, delimited with ";" and in alpha order. Note: The request can include any headers; canonical_headers and signed_headers include those that you want to be included in the hash of the request. "Host" and "x-amz-date" are always required. For DynamoDB, content-type and x-amz-target are also required.
        s3_signed_headers = 'content-md5;content-type;host;x-amz-date'

        #  Combine elements to create canonical request
        s3_canonical_request = s3_method + '\n' + s3_canonical_uri + '\n' + s3_canonical_querystring + '\n' + s3_canonical_headers + '\n' + s3_signed_headers + '\n' + s3_payload_hash_sha256

        # CREATE THE STRING TO SIGN
        s3_credential_scope = s3_datestamp + '/' + s3_region + '/' + s3_service + '/' + 'aws4_request'
        s3_string_to_sign = s3_algorithm + '\n' +  s3_amz_date + '\n' +  s3_credential_scope + '\n' +  hashlib.sha256(s3_canonical_request.encode('utf-8')).hexdigest()

        # Create the signing key using the function defined above.
        s3_signing_key = getSignatureKey(s3_secretkey, s3_datestamp, s3_region, s3_service)

        # Sign the string_to_sign using the signing_key
        s3_signature = hmac.new(s3_signing_key, (s3_string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

        # Put the signature information in a header named Authorization.
        s3_authorization_header = s3_algorithm + ' ' + 'Credential=' + s3_accesskey + '/' + s3_credential_scope + ', ' +  'SignedHeaders=' + s3_signed_headers + ', ' + 'Signature=' + s3_signature

        # Create the actual headers for the HTTP Request
        s3_headers = {
            'Content-Type': s3_content_type,
            'host': s3_host,
            'X-Amz-Date': s3_amz_date,
            'X-Amz-Content-Sha256': s3_payload_hash_sha256,
            'Content-MD5': s3_payload_hash_md5,
            'Authorization': s3_authorization_header
        }

        logging.debug("PUT request to S3 URL: %s" % s3_request_url)
        logging.debug("PUT request headers: %s" % s3_headers)

        s3_request = urllib.request.Request(s3_request_url, data=s3_payload_bytes, headers=s3_headers, method='PUT')

        # Make API request to AWS S3 API to put document
        try:
            s3_resp = urllib.request.urlopen(s3_request, context=ssl_context) # To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
            logging.debug("S3 Response headers: %s" % s3_resp.info())
            response["succeeded"] = True
            response["result_msg"] = "Host data successfully dropped in S3 Bucket"
        except urllib.error.HTTPError as e:
            logging.error("Failed API Request to AWS S3!")
            logging.error("HTTP ERROR %s" % e.code)
            logging.error(e.read())
            response["succeeded"] = False
            response["result_msg"] = "Failed API Request to AWS S3! (HTTP Error)"
        except Exception as e:
            logging.error("Failed API Request to AWS S3!")
            logging.debug(e.code)
            logging.debug(e.read())
            response["succeeded"] = False
            response["result_msg"] = "Failed API Request to AWS S3! (General Exception)"
    else:
        logging.error("Failed API Request to Forescout to get host data!")
        response["succeeded"] = False
        response["result_msg"] = "Failed API request to Forescout Web API server!"
except Exception as e:
    logging.error("Exception: {}".format(e))
    response["succeeded"] = False
    response["result_msg"] = "Exception! Something went wrong! Couldn't talk to Forescout, action parsing failed, or message to Elastic failed. See the debug logs for more info."