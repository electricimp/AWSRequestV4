# AWSRequestV4

To add this library to your model, add the following line to the top of your agent code: `#require "AWSRequestV4.class.nut:1.0.2"`

This class can be used to generate correctly structured requests intended for AWS endpoints,
sign the requests using Amazon's "Signature Version 4", and send them. It's intended to be used
internally by wrapper classes for specific AWS services.

To use the class yourself, for example if there is no corresponding wrapper class for the service
you're working with, you'll need the following info:

* Service name (e.g. `"iam"` or `"firehose"`)
* Region (e.g. `"us-east-1"`)
* Access Key ID and Secret Access Key (from IAM)
* Knowledge of the required headers and request body contents and formatting

## Class Methods

### constructor(service, region, accessKeyId, secretAccessKey)

All parameters are strings.

Currently, this auto-generates the endpoint URL in the form
`https://<service>.<region>.amazonaws.com/`
though that may change if it turns out not to be that generalizable.

### request(method, path, queryString, headers, body, cb)

    Parameter   |   Type   | Description
--------------- | -------- | -----------
**method**      | string   | `"POST"`, `"GET"`, etc.
**path**        | string   | This is frequently just `"/"` (the actual URL for the request is generated from the service and region.)
**queryString** | string   | Everything after the `?` in the URL (if applicable - otherwise just pass `""`)
**headers**     | table    | Any additional headers necessary for the request. General stuff like `X-Amz-Date` is included automatically, but service-specific headers like `X-Amz-Target` must be added here.
**body**        | string   | The request body. (Hint: create a table and then pass it through `http.jsonencode()`.)
**callback**    | function | A callback function that will be called when the request completes. It should take one argument - a response table

### post(path, headers, body, cb)

Wrapper for `request(...)` where `method="POST"` and `queryString=""`

(See the section on that method above for parameter info.)

## Example

```squirrel
#require "AWSRequestV4.class.nut:1.0.2"

const ACCESS_KEY_ID = "YOUR_KEY_ID_HERE";
const SECRET_ACCESS_KEY = "YOUR_KEY_HERE";

aws <- AWSRequestV4("firehose", "us-east-1", ACCESS_KEY_ID, SECRET_ACCESS_KEY);

local headers = {
    "X-Amz-Target": "Firehose_20150804.PutRecord"
};

local body = {
    "DeliveryStreamName": "myDeliveryStream",
    "Record": {
        "Data": http.base64encode("my super important data string")
    }
};

aws.post("/", headers, http.jsonencode(body), function(response) {
    server.log(response.statuscode + ": " + response.body);
});
```