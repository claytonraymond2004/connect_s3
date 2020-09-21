import json
import urllib.request
import base64
import re
import fnmatch
from datetime import datetime

######################################################################################################################################################################################################################################################
######################################################################################################################################################################################################################################################
# CLI Testing
######################################################################################################################################################################################################################################################
######################################################################################################################################################################################################################################################

# import logging
# import sys
# import ssl
# logging.getLogger().setLevel(logging.DEBUG)
# ssl_context = ssl.create_default_context()
# ssl_context.check_hostname = False
# ssl_context.verify_mode = ssl.CERT_NONE
# params = {
#     "connect_s3_forescout_url": "https://forescout.lab.davsol.net",
#     "ip": "10.1.20.5",
#     "connect_s3_forescout_username": "demo",
#     "connect_s3_forescout_password": "demo",
#     "connect_s3_send_host_data_allfields": "false",
#     "connect_s3_send_host_data_hostfields": "in-group(in-group),script_result.138eb8efdf5a14a4897bef3f75732d0d(C365softCerts),script_result.dd44b524158d83cf07b55e56280e0021(C365nonSmartCardEnabledUsers),nessus_last_scan(nessus_last_scan),nessus_scan_results(nessus_scan_results),scap::*::oval_check_result(scap::*::oval_check_result),hostname(hostname),nbthost(nbthost),segment_path(segment_path),online(online),nbtdomain(nbtdomain),dhcp_hostname(dhcp_hostname),user(user),va_netfunc(va_netfunc),nessus_scan_status(nessus_scan_status)",
#     "connect_s3_bucket": "forescout",
#     "connect_s3_key": "test123",
#     "connect_s3_send_host_data_bucket_override": "null",
# }

# # Making an API call to get the Forescout JWT token
# headers = {"Content-Type": "application/x-www-form-urlencoded"}
# data = {"username": params["connect_s3_forescout_username"], "password": params["connect_s3_forescout_password"]}
# request = urllib.request.Request(params["connect_s3_forescout_url"] + "/api/login", headers=headers, data=bytes(urllib.parse.urlencode(data), encoding="utf-8"))

# # To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
# response = {} # respones to forecout EyeExtend Connect
# try:
#     # Make API request
#     resp = urllib.request.urlopen(request, context=ssl_context)
#     # If we are authorized return to EyeExtend Connect
#     if resp.getcode() == 200:
#         logging.info("Received new Forescout OIM Web API JWT")
#         params["connect_authorization_token"] = resp.read().decode('utf-8')
#     else:
#         logging.error("Failed to get new Forescout OIM Web API JWT")
#         params["connect_authorization_token"] = ""
# except:
#     params["connect_authorization_token"] = ""

######################################################################################################################################################################################################################################################
######################################################################################################################################################################################################################################################
# END CLI TESTING
######################################################################################################################################################################################################################################################
######################################################################################################################################################################################################################################################

# Hold response to Forescout EyeExtend Connect
# Like the action response, the response object must have a "succeeded" field to denote success. It can also optionally have
# a "result_msg" field to display a custom test result message.
response = {}

# Get Forescout OIM Web API Details (We connect to OIM to get data)
forescout_url = params["connect_s3_forescout_url"]
forescout_jwt_token = params["connect_authorization_token"]

# Get Elasticsearch API Details (To send data to)
s3_bucket = params["connect_s3_bucket"]
if params["connect_s3_send_host_data_bucket_override"] != "null":
    s3_bucket = params["connect_s3_send_host_data_bucket_override"]
s3_key = params["connect_s3_key"]

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

        # Prepare API request to AWS S3
        logging.debug(json.dumps(s3_payload))
        credentials = ('%s:%s' % (s3_bucket, s3_key))
        encoded_credentials = base64.b64encode(credentials.encode('ascii'))
        s3_headers = {
            "Content-Type": "application/json",
            'Authorization': 'Basic %s' % encoded_credentials.decode("ascii")
        }
        s3_request = urllib.request.Request(s3_bucket + "/" + s3_bucket + "/_doc/", headers=s3_headers, data=bytes(json.dumps(s3_payload), encoding="utf-8"))

        # Make API request to AWS S3 API to put document
        s3_resp = urllib.request.urlopen(s3_request, context=ssl_context) # To use the server validation feature, use the keyword 'ssl_context' in the http reqeust
        s3_resp_parse = json.loads(s3_resp.read().decode('utf-8'))
        logging.debug(s3_resp_parse)
        
        # Check response from elasticsearch
        if "result" in elastic_resp_parse and (elastic_resp_parse["result"] == "created" or elastic_resp_parse["result"] == "updated"):
            logging.info("Sent host data to S3 succesfully!")
            response["succeeded"] = True
            response["result_msg"] = "Successfully sent data!"
            response["cookie"] = elastic_resp_parse["_id"]
        else:
            logging.error("Failed to send host data to S3!")
            logging.debug(elastic_resp.read().decode('utf-8'))
            response["succeeded"] = False
            response["result_msg"] = "Failed API request to S3!"
    else:
        logging.error("Failed API Request to Forescout to get host data!")
        response["succeeded"] = False
        response["result_msg"] = "Failed API request to Forescout Web API server!"
except Exception as e:
    logging.error("Exception: {}".format(e))
    response["succeeded"] = False
    response["result_msg"] = "Exception! Something went wrong! Couldn't talk to Forescout, action parsing failed, or message to Elastic failed. See the debug logs for more info."