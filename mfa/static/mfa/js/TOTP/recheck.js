function send_totp() {
    const totp_recheck = JSON.parse(document.getElementById('totp_recheck').textContent);
    const csrf_token = JSON.parse(document.getElementById('csrf_token').textContent);
    $.ajax({
        "url": totp_recheck, method: "POST", dataType: "JSON",
        data: {"csrfmiddlewaretoken": csrf_token, "otp": $("#otp").val()},
        success: function (data) {
            if (data["recheck"])
                mfa_success_function();
            else {
                mfa_failed_function();
            }
        }
    })
}