import json
from urllib import request
from urllib.parse import quote_plus , urlparse
import base64, datetime, hashlib, hmac, urllib

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
forescout_jwt_token = ""

# Making an API call to get the Forescout JWT token
headers = {"Content-Type": "application/x-www-form-urlencoded"}
data = {"username": params["connect_s3_forescout_username"], "password": params["connect_s3_forescout_password"]}
request = urllib.request.Request(params["connect_s3_forescout_url"] + "/api/login", headers=headers, data=bytes(urllib.parse.urlencode(data), encoding="utf-8"))

# To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
response = {} # respones to forecout EyeExtend Connect
try:
   # Make API request
   resp = urllib.request.urlopen(request, context=ssl_context)
   # If we are authorized continue test
   if resp.getcode() == 200:
      logging.info("Received new Forescout OIM Web API JWT")
      forescout_jwt_token = resp.read().decode('utf-8')

      # Get AWS S3 API Details (To send data to)
      s3_baseUrl = params["connect_s3_baseurl"]
      s3_bucket = params["connect_s3_bucket"]
      s3_region = params["connect_s3_region"]
      s3_accesskey = params["connect_s3_accesskey"]
      s3_secretkey = params["connect_s3_secretkey"]

      s3_payload = {"test": True} # test data

      # Debugging, drop payload that will be sent to S3 after any processing/renmaing/field drops
      logging.debug("Payload being sent to S3: %s" % json.dumps(s3_payload))

      # Prepare API request to AWS S3
      # Set some request variables
      s3_method = 'PUT'
      s3_service = 's3'
      s3_host = urlparse(s3_baseUrl).netloc
      s3_algorithm = 'AWS4-HMAC-SHA256'
      s3_content_type = 'application/json'
      s3_canonical_uri = '/%s/%s.json' % (s3_bucket, "test")
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
         response["result_msg"] = "Test data successfully dropped in S3 Bucket. Please delete test.json in the bucket to avoid potentially unwanted data ingestion!"
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
      logging.error("Failed to get new Forescout OIM Web API JWT")
      response["succeeded"] = False
      response["result_msg"] = "Failed to authenticate to Forescout OIM Web API!"
except:
   forescout_jwt_token = ""
   response["succeeded"] = False
   response["result_msg"] = "Could not connect to Forescout OIM Web Service"