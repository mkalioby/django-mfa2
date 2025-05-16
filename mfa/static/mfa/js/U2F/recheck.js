$(document).ready(function () {
    if (location.protocol != 'https:') {
        $("#main_paragraph").addClass("alert alert-danger")
        $("#main_paragraph").html("U2F must work under secure context")
    } else {
        const token = JSON.parse(document.getElementById('token').textContent);
        console.log(token)
        const mode = JSON.parse(document.getElementById('mode').textContent);
        const u2f_recheck = JSON.parse(document.getElementById('u2f_recheck').textContent);
        const csrf_token = JSON.parse(document.getElementById('csrf_token').textContent);
        data = JSON.parse(token)
        console.log(data)
        u2f.sign(data.appId, data.challenge, data.registeredKeys, function (response) {
            console.log(response)
            if (response.hasOwnProperty("errorCode") && response.errorCode != 0) {
                if (response.errorCode == 4) {
                    alert("Invalid Security Key, this security isn't linked to your account")
                } else if (response.errorCode == 5) {
                    alert("Verification Timeout, please refresh the page to try again")
                } else {
                    alert("Unspecified error, please try again later or try another browser.")
                }
            }
            else if (mode == "auth") {
                $("#response").val(JSON.stringify(response))
                $("#u2f_login").submit();
            }
            else if (mode == "recheck") {
                $.ajax({
                    "url": u2f_recheck,
                    method: "POST",
                    data: {"csrfmiddlewaretoken": csrf_token, "response": JSON.stringify(response)},
                    success: function (data) {
                        if (data["recheck"]) {
                            mfa_success_function();
                        } else {
                            mfa_failed_function();
                        }
                    }
                })
            }
        }, 5000)
    }
})