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