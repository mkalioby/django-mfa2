window.conditionalUI = false;
window.conditionUIAbortController = new AbortController();
window.conditionUIAbortSignal = conditionUIAbortController.signal;

function checkConditionalUI(form) {
    if (window.PublicKeyCredential && PublicKeyCredential.isConditionalMediationAvailable) {
        // Check if conditional mediation is available.
        PublicKeyCredential.isConditionalMediationAvailable().then((result) => {
            window.conditionalUI = result;
            if (window.conditionalUI) {
                authen(true)
            }
        });
    }
}

var GetAssertReq = (getAssert) => {
    getAssert.publicKey.challenge = base64url.decode(getAssert.publicKey.challenge);
    for (let allowCred of getAssert.publicKey.allowCredentials) {
        allowCred.id = base64url.decode(allowCred.id);
    }
    return getAssert
}

function authen(conditionalUI = false) {
    const fido2_begin_auth = JSON.parse(document.getElementById('fido2_begin_auth').textContent);
    const fido2_complete_auth = JSON.parse(document.getElementById('fido2_complete_auth').textContent);
    const mode = JSON.parse(document.getElementById('mode').textContent);
    fetch(fido2_begin_auth, {
        method: 'GET',
    }).then(function (response) {
        if (response.ok) {
            return response.json().then(function (req) {
                return GetAssertReq(req)
            });
        }
        throw new Error('No credential available to authenticate!');
    }).then(function (options) {
        if (conditionalUI) {
            options.mediation = 'conditional';
            options.signal = window.conditionUIAbortSignal;
        } else {
            window.conditionUIAbortController.abort()
        }
        console.log(options)
        return navigator.credentials.get(options);
    }).then(function (assertion) {
        return fetch(fido2_complete_auth, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(publicKeyCredentialToJSON(assertion)),
            }
        ).then(function (response) {
            if (response.ok) return res = response.json()
        }).then(function (res) {
            if (res.status == "OK") {
                $("#msgdiv").addClass("alert alert-success").removeClass("alert-danger")
                $("#msgdiv").html("Verified....please wait")
                if (mode === "auth" || !mode) {
                    window.location.href = res.redirect;
                }
                else if (mode === "recheck") {
                    mfa_success_function();
                }
            } else {
                $("#msgdiv").addClass("alert alert-danger").removeClass("alert-success")
                $("#msgdiv").html("Verification Failed as " + res.message + ", <a href='#' id='failed_authen'> try again</a> or <a href='#' id='failed_history_back'> Go Back</a>")
                $("#failed_history_back").click(function() { history.back() });
                $("#failed_authen").click(function() { authen(); });

                if (mode === "auth") {
                    // do nothing
                }
                else if (mode === "recheck") {
                    mfa_failed_function();
                }
            }
        })
    })
}

$(document).ready(function () {
    if (location.protocol != 'https:') {
        $("#main_paragraph").addClass("alert alert-danger")
        $("#main_paragraph").html("FIDO2 must work under secure context")
    } else {
        ua = new UAParser().getResult()
        if (ua.browser.name == "Safari" || ua.browser.name == "Mobile Safari" || ua.os.name == "iOS" || ua.os.name == "iPadOS") {
            $("#res").html("<button class='btn btn-success' id='ua_authen'>Authenticate...</button>");
            $("#ua_authen").click(function () { authen(); });
        }
        else {
            authen()
        }
    }
});