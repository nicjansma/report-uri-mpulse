//
// Imports
//
const fastify = require("fastify")({
    logger: true
});
const mPulse = require("mpulse");
const appLookup = require("./apps.json");
const JSURL = require("jsurl");

//
// Constants
//
const SERVER_PORT = 3000;
const INCLUDE_FULL_REPORT = false;

//
// Locals
//
let apps = {};

//
// Routes
//

// Declare a route
fastify.post("/report/:apiKey", (request, reply) => {
    //
    // Validate input
    //
    const body = request.body;
    const ua = request.headers["user-agent"];
    const ip = request.headers["x-forwarded-for"] || request.ip;

    if (!body) {
        return reply.send(new Error("No Request body"));
    }

    const apiKey = request.params.apiKey;
    if (!apiKey) {
        return reply.send(new Error("No API Key specified"));
    }

    const restApiSecretKey = appLookup[apiKey];
    if (!restApiSecretKey) {
        return reply.send(new Error("Unknown API key"));
    }

    //
    // App initialization
    //
    if (!apps[apiKey]) {
        request.log.info(`Initializing ${apiKey}`);

        apps[apiKey] = mPulse.init(apiKey, restApiSecretKey, {
            ua: "report-uri-mpulse"
        });
    }

    let reportsHandled = 0;

    if (body && Array.isArray(body)) {
        for (let i = 0; i < body.length; i++) {
            handleReport(body[i], ua, ip);
            reportsHandled++;
        }
    } else {
        handleReport(body, ua, ip);
        reportsHandled++;
    }

    return reply.send({
        success: true,
        handled: reportsHandled
    });
});

function handleReport(body, ua, ip) {
    console.log(body);

    //
    // Data
    //
    const when = +(new Date());

    let data = {
        "rt.tstart": when,
        "rt.end": when,
        "http.initiator": "error",
        ua: ua,
        ip: ip
    };

    //
    // Process the payload
    //

    if (body.type === "csp" || body["csp-report"]) {
        //
        // Content Security Policy (CSP)
        //
        let csp = body["csp-report"] || body.body;

        data.u = csp["document-uri"];

        let blockedUri = csp["blocked-uri"].replace("http://", "").replace("https://", "");
        if (blockedUri.indexOf("/") !== -1) {
            blockedUri = blockedUri.substring(0, blockedUri.indexOf("/"));
        }

        let directive = csp["effective-directive"] || csp["violated-directive"];
        if (directive.indexOf(" ") !== -1) {
            directive = directive.substring(0, directive.indexOf(" "));
        }

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Content Security Policy",
            d: when.toString(36),
            m: `${directive}: ${blockedUri}`,
            f: INCLUDE_FULL_REPORT ? [{
                f: JSON.stringify(csp)
            }] : undefined
        }]);
    } else if (body.type === "network-error") {
        //
        // Network Error Logging (NEL)
        //
        let nel = body.body;

        data.u = body.url;

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Network Error Logging",
            d: when.toString(36),
            m: `${nel.type} ${nel.protocol} ${nel.method} ${nel.status_code}`,
            f: INCLUDE_FULL_REPORT ? [{
                f: JSON.stringify(nel)
            }] : undefined
        }]);
    } else if (body.type === "deprecation") {
        //
        // Reporting API: Deprecation
        //
        let deprecation = body.body;

        data.u = body.url;

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Deprecation",
            d: when.toString(36),
            m: `${deprecation.id} ${deprecation.anticipatedRemoval ? deprecation.anticipatedRemoval : ""}`.trim(),
            f: INCLUDE_FULL_REPORT ?[{
                l: deprecation.lineNumber,
                c: deprecation.columnNumber,
                f: deprecation.sourceFile,
                w: JSON.stringify(deprecation)
            }] : undefined
        }]);
    } else if (body.type === "intervention") {
        //
        // Reporting API: Intervention
        //
        let intervention = body.body;

        data.u = body.url;

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Intervention",
            d: when.toString(36),
            m: `${intervention.id}`,
            f: INCLUDE_FULL_REPORT ? [{
                l: intervention.lineNumber,
                c: intervention.columnNumber,
                f: intervention.sourceFile,
                w: JSON.stringify(intervention)
            }] : undefined
        }]);
    } else if (body.type === "crash") {
        //
        // Reporting API: Crash
        //
        let crash = body.body;

        data.u = body.url;

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Crash",
            d: when.toString(36),
            m: `${crash.reason}`,
            f: INCLUDE_FULL_REPORT ? [{
                f: JSON.stringify(crash)
            }] : undefined
        }]);
    } else if (body.type === "feature-policy-violation") {
        //
        // Feature Policy Violation
        //
        let violation = body.body;

        data.u = body.url;

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Feature Policy Violation",
            d: when.toString(36),
            m: `${violation.policyId}`,
            f: INCLUDE_FULL_REPORT ? [{
                f: JSON.stringify(violation)
            }] : undefined
        }]);
    } else if (body["xss-report"]) {
        //
        // XSS
        //
        let xss = body["xss-report"];

        let requestUrl = xss["request-url"].replace("http://", "").replace("https://", "");

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "XSS Report",
            d: when.toString(36),
            m: `${requestUrl}`,
            f: INCLUDE_FULL_REPORT ? [{
                f: JSON.stringify(xss)
            }] : undefined
        }]);
    } else if (body["expect-ct-report"]) {
        //
        // Expect-CT
        //
        let ct = body["expect-ct-report"];

        data.err = JSURL.stringify([{
            // TODO new via
            v: 0,
            t: "Expect-CT",
            d: when.toString(36),
            m: `${ct.hostname}`
        }]);
    } else {
        //
        // Unknown - log more info
        //
        console.log("Unknown Request");
        console.log(JSON.stringify(body));
    }

    //
    // Send to mPulse
    //
    mPulse.sendBeacon(data);
}

// Run the server!
fastify.listen(SERVER_PORT, (err, address) => {
    if (err) {
        throw err;
    }

    fastify.log.info(`Server listening on ${address}`);
});

//
// Add content parsers for reporting content types
//
function parseJsonContent(req, body, done) {
    try {
        var json = JSON.parse(body);
        done(null, json);
    } catch (err) {
        err.statusCode = 400;
        done(err, undefined);
    }
}

fastify.addContentTypeParser("application/csp-report", { parseAs: "string" }, parseJsonContent);
fastify.addContentTypeParser("application/reports+json", { parseAs: "string" }, parseJsonContent);
fastify.addContentTypeParser("application/expect-ct-report+json", { parseAs: "string" }, parseJsonContent);

//
// Handle ACAO
//
fastify.route({
    method: "OPTIONS",
    url: "/*",
    handler: (request, reply) => {
        reply.code(204)
            .header("Content-Length", "0")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET,HEAD,PUT,PATCH,POST,DELETE")
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization, Content-Length, X-Requested-With")
            .send();
    }
});
