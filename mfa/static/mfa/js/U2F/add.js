function addToken() {
    const token = JSON.parse(document.getElementById('token').textContent);
    const bind_u2f = JSON.parse(document.getElementById('bind_u2f').textContent);
    const csrf_token = JSON.parse(document.getElementById('csrf_token').textContent);
    const redirect_html = JSON.parse(document.getElementById('redirect_html').textContent);
    const reg_success_msg = JSON.parse(document.getElementById('reg_success_msg').textContent);
    const manage_recovery_codes = JSON.parse(document.getElementById('manage_recovery_codes').textContent);
    const RECOVERY_METHOD = JSON.parse(document.getElementById('RECOVERY_METHOD').textContent);
    const mfa_home = JSON.parse(document.getElementById('mfa_home').textContent);
    data = JSON.parse(token)
    console.log(data)
    u2f.register(data.appId, data.registerRequests, data.registeredKeys, function (response) {
        $.ajax({
            "url": bind_u2f, method: "POST",
            data: {"csrfmiddlewaretoken": csrf_token, "response": JSON.stringify(response)},
            success: function (data) {
                if (data == 'OK')
                    $("#res").html("<div class='alert alert-success'>Your device is registered successfully, <a href='"+redirect_html+"'> "+reg_success_msg+"</a></div>")
                else if (data == "RECOVERY") {
                    setTimeout(function () {
                        location.href = manage_recovery_codes
                    }, 2500)
                    $("#res").html("<div class='alert alert-success'>Your device is registered successfully, but <a href='"+manage_recovery_codes+"'>redirecting to "+RECOVERY_METHOD+" method</a></div>")
                } else
                    $("#res").html("<div class='alert alert-danger'>Registration failed, please <a href='javascript:void(0)' onclick='addToken()'>try again</a> or <a href='"+mfa_home+"'> Go to Security Home</a></div>")
            },
            error: function (data) {
                $("#res").html("<div class='alert alert-danger'>Registration failed, please <a href='javascript:void(0)' onclick='addToken()'>try again</a> or <a href='"+mfa_home+"'> Go to Security Home</a></div>")
            }
        })
    }, 5000)
}

$(document).ready(addToken())