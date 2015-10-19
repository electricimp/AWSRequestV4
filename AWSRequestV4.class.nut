class AWSRequestV4 {
    static version = [1, 0, 0];

    static ALGORITHM = "AWS4-HMAC-SHA256";

    _service = null;
    _region = null;
    _accessKeyId = null;
    _secretAccessKey = null;

    _date = null;
    _dateTime = null;
    _signedHeaders = null;

    _serviceUrl = null;
    _serviceHost = null;

    constructor(service, region, accessKeyId, secretAccessKey) {
        _service = service;
        _region = region;
        _accessKeyId = accessKeyId;
        _secretAccessKey = secretAccessKey;
        _serviceUrl = format("https://%s.%s.amazonaws.com/", service, region);
        _serviceHost = format("%s.%s.amazonaws.com", service, region);
    }

    // Join array items into a string, separated by a delimiter.
    // (i.e. the last part will not have a trailing delimiter)
    function _strJoin(parts, delimiter) {
        local result = "";
        for (local i = 0; i < parts.len() - 1; i++) {
            result += parts[i] + delimiter;
        }
        result += parts[parts.len() - 1];
        return result;
    }

    function _blobToHexString(data) {
        local str = "";
        foreach (byte in data) {
            str += format("%02x", byte);
        }
        return str;
    }

    function _updateTimestamps() {
        local date = date();
        _dateTime = format("%04d%02d%02dT%02d%02d%02dZ",
            date.year, date.month + 1, date.day,
            date.hour, date.min, date.sec);
        _date = _dateTime.slice(0, 8);
    }

    function _getHashedCanonicalRequest(method, path, queryString, headerTable, payload) {
        // Format headers according to AWS spec (lowercase, whitespace trimmed, alphabetical order, etc)
        // TODO: extra spaces between non-quoted header values should be removed as well
        local headerArray = [];
        local signedHeaderArray = [];
        foreach (key, val in headerTable) {
            headerArray.push(key.tolower() + ":" + strip(val) + "\n");
            signedHeaderArray.push(key.tolower());
        }
        headerArray.sort();
        signedHeaderArray.sort();
        local headers = _strJoin(headerArray, "");
        _signedHeaders = _strJoin(signedHeaderArray, ";");
        // Hash the payload and convert to a lowercase hex string
        local payloadHash = _blobToHexString(http.hash.sha256(payload));
        // Create the canonical request and return a hex-encoded hash of it
        local canonicalRequest = _strJoin([method, path, queryString, headers, _signedHeaders, payloadHash], "\n");
        return _blobToHexString(http.hash.sha256(canonicalRequest));
    }

    function _getCredentialScope() {
        return _date + format("/%s/%s/aws4_request", _region, _service);
    }

    function _deriveSigningKey() {
        local kDate = http.hash.hmacsha256(_date, "AWS4" + _secretAccessKey);
        local kRegion = http.hash.hmacsha256(_region, kDate);
        local kService = http.hash.hmacsha256(_service, kRegion);
        local kSigning = http.hash.hmacsha256("aws4_request", kService);
        return kSigning;
    }

    function _getSignature(method, path, queryString, headers, body) {
        // Get the bits and bobs we need to sign a request
        local hashedCanonicalRequest = _getHashedCanonicalRequest(method, path, queryString, headers, body);
        local stringToSign = _strJoin([ALGORITHM, _dateTime, _getCredentialScope(), hashedCanonicalRequest], "\n");
        local signingKey = _deriveSigningKey();
        // Return the signature
        return _blobToHexString(http.hash.hmacsha256(stringToSign, signingKey));
    }

    // TODO: parse queryString properly from the URL
    function request(method, path, queryString, headers, body, cb) {
        _updateTimestamps();

        // These headers are used in the request signature
        headers["Host"] <- _serviceHost;
        headers["Content-Type"] <- "application/x-amz-json-1.1"

        // Add the signature to the headers
        local signature = _getSignature(method, path, queryString, headers, body);
        headers["Authorization"] <- format("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
            ALGORITHM, _accessKeyId, _getCredentialScope(), _signedHeaders, signature);

        // This header is added after the request is signed
        headers["X-Amz-Date"] <- _dateTime;

        http.request(method, _serviceUrl, headers, body).sendasync(cb);
    }

    // function get(path, headers, cb) {
    //     return request("GET", path, "", headers, "", cb);
    // }

    function post(path, headers, body, cb) {
        return request("POST", path, "", headers, body, cb);
    }
}