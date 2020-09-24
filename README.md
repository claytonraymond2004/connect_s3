
  

# connect_s3

  

Forescout EyeExtend Connect app for Amazon AWS S3

  

This app allows you to send host information from Forescout to an Amazon AWS S3 bucket as a JSON file. The app has a singular action Audit > "AWS S3: Put Host Data" that will allow you to select one or more attributes of a host and uploads it to an S3 bucket as a .json file.

## About
This S3 app for Forescout EyeExtend Connect allows you to send data from Forescout into an S3 bucket.
- The app makes an API request directly to the AWS S3 API.
- The app leverages the Forescout EyeExtend Connect Web Service API (previously called the Open Integration Module [OIM] Web API) in order to obtain the data about a host and then send to S3, consequently, data is sent to S3 in nearly the same format as if you were consuming it via the `/host/<host_id>` API
- There is support for selecting custom host fields as well as renaming fields

## Setup
1. Enable the Forescout Web API module
2. Configure the Web API Module
- Create a credential the app (the EyeExtend App for S3) can use to call the Forescout Web API
- Set the authentication token expiration time (or note the setting, needed during app configuration so EyeExtend Connect can refresh the Forescout API JWT)
- Ensure that the connecting appliance running the app can access the Web API (`Client IPs` tab)
3. Install the EyeExtend Connect Elasticsearch app
4. Configure
- S3 Connection
	- Set an S3 API service endpoint address in the "S3 Base URL" field. This is the base of the S3 Bucket URL to call. It should be the REST API  endpoint address (as opposed to the s3-website dash/dot address). Examples include `https://s3.us-east-2.amazonaws.com/` or `https://s3-fips.us-gov-west-1.amazonaws.com/`. See the [AWS Service Endpoints documentation](https://docs.aws.amazon.com/general/latest/gr/rande.html) or [AWS GovCloud Service Endpints documentation](https://docs.aws.amazon.com/govcloud-us/latest/UserGuide/using-govcloud-endpoints.html) for more information.
	- Set the AWS Region for what the S3 bucket resides in the "S3 Region" field. Examples include `us-east-2` or `us-gov-west-1`.
	- Set the name of the AWS S3 bucket where data will be sent in the "S3 Bucket" field.
	- Set the API Access Key ID in the "AWS API Access Key ID" field. This should be the ID of a IAM user with "Programmatic access" to the S3 bucket. It must have write permission to the bucket (it does not need read, list, or any other access).
	- Set the API Access Secret Key in the "AWS API Secret Key" field for the user defined above.
	- Verify the Secret Key in the "Verify AWS API Secret Key" field.
- Forescout Web API Connection
	- Set the URL to the Forescout EM hosting the Forescout Web API. Include the protocol (https://) and port if different
	- Set the Username/Password for the Web API user configured in step 2.
	- Assign the CounterACT appliance to connect to the Forescout API and S3 API
	- Set the proxy server to use (if applicable)
	- Set the API rate limits and the Forescout Web API refresh interval. The S3 API has a default throttle rate of 3500 PUT requests/second. This may exceed the Forescout API request threshold for your specific deployment. Tune as necessary to balance performance of your Forescout Web API and AWS S3 API limits. The Forescout Web API refresh interval should be less than the value configured in step 2 (token expiration time).



## Actions
In order for this App to do anything, it must be configured as an action inside a policy. The supported actions are listed below.

### Send Host Data
Found under the `Audit` menu, this action allows you to send host data to S3. When you select the action, you can select to either send `All Data` or make a selection of fields via a free-form text box (`Forescout host field list`).

If the `All Data` checkmark is selected (value == `true`), all data will be sent to Forescout, regardless of what is typed into the `Forescout host field list` textbox.

The `Forescout host field list` field takes a comma seperated list of host properties to send to S3 from the Forescout `/host/<host_id>` API response. It supprots feild renaming via a parenthesis after the field name. The field renaming specification is required (it can be the same name as the field attribute). The `configuration_utility` app can help you generate this comma seperated list. Additionally, a single wildcard character, `*`, can be included in a field specification to include fields matchinga certain pattern. The `*` character must be included in the field rename specificiation -- the wildcard matched characters are replaced in the field rename specification.

An example specification follow:
`in-group(device_groups),scap::*::oval_check_result(scap::*::oval_check_result),hostname(hostname),nbthost(nbthost),segment_path(segment_path),online(online),nbtdomain(nbtdomain),dhcp_hostname(dhcp_hostname),user(user),va_netfunc(va_netfunc)`

Above we've renamed the `in-group` property to `device_groups`, included a wildcarded inclusion of SCAP scan results, and some additional host properties. In the example above, the string that is matched via the `*` in the host data is used to replaced the `*` in the rename field naming (in this case, it is the name of the SCAP Benchmark content that is executed by Forescout).

Note that in the app package there is also a GUI based utility to help generate the string required in the host field list (if you do not wish to send all fields). The app allows you to connect to the Forescout API and pull the `/api/hostfields` and select which host fields you wish to select in the action and it will generate the string required for the action field. 

To run this app make sure you have Node.JS and npm installed.
1. Open a terminal and go to the configuration_utility directory.2
2. Run `npm install` then `npm start` to launch the utility. 
3. Enter the Forescout API addres (`https://<em ip>`) and a user/password that has access.
4. The utility will then load all avaialble host fields on the left hand side. 
	- You can the scroll through the list or search for specific fields.
5. Double click a field to select it.
6. In the Selected fields column in the middle, you can rename the field in the resultant JSON document from the app in S3 by typing a new name. By default it will keep the name from the Forescout API.
7. In the right column, you will find the string to copy-paste into the app action in Forescout.

Note that the app does not support the wildcard selectior (*). You should manually edit the string as required to include.

## Installing from Source
### Allow unsigned app install on Forescout
When you import an app, the signature of the app is validated to see if it has a valid Forescout signature. If the validation succeeds, the app is imported. If the validation fails, an error message is displayed and the app is not imported. To allow an app with an invalid signature to be imported use the following command on the Enterprise Manager:

`fstool allow_unsigned_connect_app_install true`

This is a global command. It disables the enforcement of signature validation for all apps that are imported after the command is run, including apps with invalid or missing signatures.

### Creating zip
You have to make sure to not include any "extra" files when zipping up the app for import into Forescout. If you use the default "Compress" item in Finder on macOS, an `__macosx` folder is included which will cause Forescout to balk. Avoid this by opening terminal and going into the `app` directory and running the zip command manually:

`rm -f connect_s3.zip; zip connect_s3.zip ./*`

Note the above command also deletes the `connect_s3.zip` file if it's there so you have a fresh copy.