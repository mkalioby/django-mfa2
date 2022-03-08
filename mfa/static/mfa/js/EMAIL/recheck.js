$(document).ready(function () {
    // 1. If the Document is loaded, add an eventlistener to the object with the id=send-totp
    let sendTotp = document.getElementById('send-totp');
    sendTotp.addEventListener('click', check_mode)
    // 2. If the Django-variable "mode" == "recheck", then call send_totp()

});

function check_mode() {
    const mode = JSON.parse(document.getElementById('recheck-js').textContent);
    if (mode === 'recheck') {
        send_totp();
    }
}

function send_totp() {
    const form = $('#formLogin');
    var formData = new FormData(form);
    $.ajax({
        "url": "{% url 'totp_recheck' %}", method: "POST", dataType: "JSON",
        data: {"csrfmiddlewaretoken": formData.get('csrf_token'), "otp": $("#otp").val()},
        success: function (data) {
            if (data["recheck"])
                mfa_success_function();
            else {
                mfa_failed_function();
            }
        }
    })
}