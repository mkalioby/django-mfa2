$(document).ready(function () {
    document.getElementById('send-totp').addEventListener('click', check_mode);
})

function check_mode() {
    const mode = JSON.parse(document.getElementById('recheck-js').textContent);
    if (mode === 'recheck') {
        send_totp();
    }
}

function send_totp() {
    $.ajax({
        "url": "{% url 'totp_recheck' %}", method: "POST", dataType: "JSON",
        data: {"csrfmiddlewaretoken": "{{ csrf_token }}", "otp": $("#otp").val()},
        success: function (data) {
            if (data["recheck"])
                mfa_success_function();
            else {
                mfa_failed_function();
            }
        }
    })

}