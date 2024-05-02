/*function authorize(r) {
    var signature = r.variables.access_token;

    if (!signature) {
        r.error("No signature");
        r.return(401);
        return;
    }

    if (r.method != 'GET') {
        r.error(`Unsupported method: ${r.method}`);
        r.return(401);
        return;
    }

    var args = r.variables.args;

    var h = require('crypto').createHmac('sha1', process.env.SECRET_KEY);

    h.update(r.uri).update(args ? args : "");

    var req_sig = h.digest("base64");

    if (req_sig != signature) {
        r.error(`Invalid signature: ${req_sig}\n`);
        r.return(401);
        return;
    }

    r.return(200);
}*/

function authorize(r) {
    // Prepare Authorization header for the introspection request
    var authHeader = "";
    
    if (r.variables.oauth_client_id.length) {
        var basicAuthPlaintext = r.variables.oauth_client_id + ":" + r.variables.oauth_client_secret;
        // authHeader = "Basic " + Buffer.from(basicAuthPlaintext).toString('base64url');    
        authHeader = "Basic c21tcHJveHk6UUFTVHc5aXBZSUlDNVNyRGVGcUNBWUNCV0FDUXBHZUI=";
    } else {
        authHeader = "Bearer " + r.variables.oauth_client_secret;
    }

    // Make the OAuth 2.0 Token Introspection request
    
    r.error("OAuth sending introspection request with token: " + r.variables.access_token);
    r.subrequest("/_oauth2_send_introspection_request", "token=" + r.variables.access_token + "&authorization=" + authHeader,
        function(reply) {
            if (reply.status != 200) {
                r.error("OAuth unexpected response from authorization server (HTTP " + reply.status + "). " + reply.body);
                r.return(401);
            }

            // We have a response from authorization server, validate it has expected JSON schema
            try {
                r.error("OAuth token introspection response text: " + reply.responseText)
                Object.keys(reply).forEach((prop)=> r.error(prop));
                var response = JSON.parse(reply.responseText);
                // TODO: check for errors in the JSON response first
                // We have a valid introspection response
                // Check for validation success
                if (response.active == true) {
                    r.error("OAuth token introspection found ACTIVE token");
                    // Iterate over all members of the response and return them as response headers
                    for (var p in response) {
                        if (!response.hasOwnProperty(p)) continue;
                        r.log("OAuth token value " + p + ": " + response[p]);
                        r.headersOut['token-' + p] = response[p];
                    }
                    r.status = 204;
                    r.sendHeader();
                    r.finish();
                } else {
                    r.error("OAuth token introspection found inactive token");
                    r.return(403);
                }
            } catch (e) {
                r.error("OAuth token introspection response is not JSON: " + reply.body);
                r.return(401);
            }
        }
    );
    r.return(401);
}

export default {authorize}
