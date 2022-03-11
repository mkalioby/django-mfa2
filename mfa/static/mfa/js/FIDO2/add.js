function begin_reg() {
    var formData = new FormData(document.getElementById('fido2_form'));
    fetch('/mfa/fido2/begin_reg', {}).then(function (response) {
        if (response.ok) {
            return response.arrayBuffer();
        }
        throw new Error('Error getting registration data!');
    }).then(CBOR.decode).then(function (options) {
        options.publicKey.attestation = "direct"
        console.log(options)

        return navigator.credentials.create(options);
    }).then(function (attestation) {
        return fetch(formData.get('complete'), {
            method: 'POST',
            headers: {'Content-Type': 'application/cbor'},
            body: CBOR.encode({
                "attestationObject": new Uint8Array(attestation.response.attestationObject),
                "clientDataJSON": new Uint8Array(attestation.response.clientDataJSON),
            })
        });
    }).then(function (response) {

        var stat = response.ok ? 'successful' : 'unsuccessful';
        return response.json()
    }).then(function (res) {
        if (res["status"] == 'OK')
            $("#res").html("<p class='alert alert-success'>Die Registrierung war erfolgreich. Klicken Sie <a class='underlined' href='" + formData.get('redirect') + "'>hier</a>, um die Seite neu zu laden und somit alle Optionen sehen zu können.</p>")
        else
            $("#res").html("<p class='alert alert-danger'>Die Registrierung ist fehlgeschlagen. Klicke Sie <a class='underlined' onclick='begin_reg()'>hier</a> um es erneut zu versuchen.</p>")


    }, function (reason) {
        $("#res").html("<p class='alert alert-danger'>Die Registrierung ist fehlgeschlagen. Klicke Sie <a class='underlined' href='/mfa/fido2/'>hier</a> um es erneut zu versuchen.</p>")
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


    