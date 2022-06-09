function authen() {
    const begin_url = document.getElementById('begin').value;
    const complete_url = document.getElementById('u2f_login').getAttribute('action');
    const recheck_text = document.getElementById('rechecktext')
    const mode = $('u2f_login').attr('name') === 'complete' ? 'auth' : 'recheck';
    fetch(begin_url, {
        method: 'GET',
    }).then(function (response) {
        if (response.ok) return response.arrayBuffer();
        throw new Error('No credential available to authenticate!');
    }).then(CBOR.decode).then(function (options) {
        options.publicKey.userVerification = 'required'
        console.log(options)
        return navigator.credentials.get(options);
    }).then(function (assertion) {
        res = CBOR.encode({
            "credentialId": new Uint8Array(assertion.rawId),
            "authenticatorData": new Uint8Array(assertion.response.authenticatorData),
            "clientDataJSON": new Uint8Array(assertion.response.clientDataJSON),
            "signature": new Uint8Array(assertion.response.signature)
        });
      
        return fetch(complete_url, {

            method: 'POST',
            headers: {'Content-Type': 'application/cbor'},
            body: res,

        }).then(function (response) {
            if (response.ok) return res = response.json()
        }).then(function (res) {
            if (res.status == "OK") {
                $("#msgdiv").addClass("alert alert-success").removeClass("alert-danger")
                $("#msgdiv").html("<p>"+recheck_text+"</p>")
                if (mode == "auth") {
                    window.location.href = res.redirect;
                } else if (mode === "recheck") {
                    window.location.href = '/'
                }

            } else {
                $("#msgdiv").addClass("alert alert-danger").removeClass("alert-success")
                $("#msgdiv").html("Verification Failed as " + res.message + ", <a href='javascript:void(0)' onclick='authen())'> try again</a> or <a href='javascript:void(0)' onclick='history.back()'> Go Back</a>")

                if (mode === "recheck") {
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
        if (ua.browser.name == "Safari" || ua.browser.name == "Mobile Safari")
            $("#res").html("<button class='btn btn-success' onclick='authen()'>Authenticate...</button>")
        else
            authen()
    }
});

