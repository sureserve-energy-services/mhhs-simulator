//  Headers for signed message",
const addSignatureHeaders = (forgeLib) => {
    const timestamp = new Date().toISOString();
    const hostnameVariable = "hostname";
    const hostName = pm.variables.get(hostnameVariable);
    const url = pm.request.url.toString().replace("{{" + hostnameVariable + "}}", hostName);

    pm.request.headers.add({ key: "X-DIP-Signature-Date", value: timestamp });
    // Your certificate excluding private key in PEM format",
    const pemCert = pm.environment.get("SigningClientCertPEM");
    // Private key for certificate",
    const pemPrivateKey = pm.environment.get("SigningClientPrivateKeyPEM");
    let messageBody = (pm.request && pm.request.body && pm.request.body.raw ) ? pm.request.body.raw : "{}";
    // Replace schema version since pre request scripts don"t have replaced variables",
    if (messageBody.includes("{{schema_version_if}}")) {
        messageBody = messageBody.replace("{{schema_version_if}}", pm.collectionVariables.get("schema_version_if"))
    }
    if (messageBody.includes("{{schema_version_rep}}")) {
        messageBody = messageBody.replace("{{schema_version_rep}}", pm.collectionVariables.get("schema_version_rep"))
    }
    // Compute SHA-256 hash of body",
    const md = forgeLib.md.sha256.create();
    md.update(messageBody);
    // Get a 256 hash of the body.  This will output in lowercase hex.",
    const hashBytes = md.digest().getBytes();
    // base64Encode hash",
    const base64Hash = forgeLib.util.encode64(hashBytes);
    pm.request.headers.add({ key: "X-DIP-Content-Hash", value: base64Hash });
    const signature = pm.request.method.toUpperCase() + ";" + url.toLowerCase() + ";" + timestamp + ";" + base64Hash;
    const signatureBytes = forgeLib.util.encodeUtf8(signature);
    // base64Encode certificate",
    const base64Certificate = forgeLib.util.encode64(pemCert);
    // Add header with certificate minus private key",
    pm.request.headers.add({ key: "X-DIP-Signature-Certificate", value: base64Certificate });
    const privateKey = forgeLib.pki.privateKeyFromPem(pemPrivateKey);
    var mdx = forgeLib.md.sha256.create();
    // Set the message for the digest",
    mdx.update(signatureBytes);
    // Sign the message digest",
    var sign = privateKey.sign(mdx);
    const signBas64 = forgeLib.util.encode64(sign);
    pm.request.headers.add({ key: "X-DIP-Signature", value: signBas64 });
}

window = {};
const hasSigningVariables = pm.environment.has("SigningClientCertPEM") && pm.environment.has("SigningClientPrivateKeyPEM")

if (hasSigningVariables) {
    if (!pm.collectionVariables.get("forge_library")) {
        pm.sendRequest("https://cdnjs.cloudflare.com/ajax/libs/forge/1.3.1/forge.min.js", (err, res) => {
            // Convert the response to text and save it as a collection variable",
            pm.collectionVariables.set("forge_library", res.text());
            // eval will evaluate the JavaScript code and initialize forge library.",
            eval(pm.collectionVariables.get("forge_library"));
            addSignatureHeaders(window.forge);
        });
    } else {
        // eval will evaluate the JavaScript code and initialize the forge library.",
        eval(pm.collectionVariables.get("forge_library"));
        addSignatureHeaders(window.forge);
    }
} else {
    console.log("variables 'SigningClientCertPEM' and 'SigningClientPrivateKeyPEM' must be set on the environment to enable signing");
}