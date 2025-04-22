var MakeCredReq = (makeCredReq) => {
    makeCredReq.publicKey.challenge = base64url.decode(makeCredReq.publicKey.challenge);
    makeCredReq.publicKey.user.id = base64url.decode(makeCredReq.publicKey.user.id);

    for (let excludeCred of makeCredReq.publicKey.excludeCredentials) {
        excludeCred.id = base64url.decode(excludeCred.id);
    }

    return makeCredReq
}

function begin_reg() {
    const fido2_begin_reg = JSON.parse(document.getElementById('fido2_begin_reg').textContent);
    const fido2_complete_reg = JSON.parse(document.getElementById('fido2_complete_reg').textContent);
    const redirect_html = JSON.parse(document.getElementById('redirect_html').textContent);
    const reg_success_msg = JSON.parse(document.getElementById('fido2_complete_reg').textContent);
    const manage_recovery_codes = JSON.parse(document.getElementById('manage_recovery_codes').textContent);
    const RECOVERY_METHOD = JSON.parse(document.getElementById('RECOVERY_METHOD').textContent);
    const mfa_home = JSON.parse(document.getElementById('mfa_home').textContent);
    fetch(fido2_begin_reg, {}).then(function (response) {
        if (response.ok) {
            return response.json().then(function (req) {
                return MakeCredReq(req)
            });
        }
        throw new Error('Error getting registration data!');
    }).then(function (options) {
        //options.publicKey.attestation="direct"
        console.log(options)
        return navigator.credentials.create(options);
    }).then(function (attestation) {
        return fetch(fido2_complete_reg, {
            method: 'POST',
            body: JSON.stringify(publicKeyCredentialToJSON(attestation))
        });
    }).then(function (response) {
        var stat = response.ok ? 'successful' : 'unsuccessful';
        return response.json()
    }).then(function (res) {
        if (res["status"] == 'OK')
            $("#res").html("<div class='alert alert-success'>Registered Successfully, <a href='"+redirect_html+"'>"+reg_success_msg+"</a></div>")
        else if (res['status'] = "RECOVERY") {
            setTimeout(function () {
                location.href = manage_recovery_codes
            }, 2500)
            $("#res").html("<div class='alert alert-success'>Registered Successfully, but <a href='"+manage_recovery_codes+"'>redirecting to "+RECOVERY_METHOD+" method</a></div>")
        } else
            $("#res").html("<div class='alert alert-danger'>Registration Failed as " + res["message"] + ", <a href='javascript:void(0)' onclick='begin_reg()'> try again or <a href='"+mfa_home+"'> Go to Security Home</a></div>")
    }, function (reason) {
        $("#res").html("<div class='alert alert-danger'>Registration Failed as " + reason + ", <a href='javascript:void(0)' onclick='begin_reg()'> try again </a> or <a href='"+mfa_home+"'> Go to Security Home</a></div>")
    })
}

$(document).ready(function () {
    ua = new UAParser().getResult()
    if (ua.browser.name == "Safari" || ua.browser.name == "Mobile Safari") {
        $("#res").html("<button class='btn btn-success' onclick='begin_reg()'>Start...</button>")
    } else {
        setTimeout(begin_reg, 500)
    }
})