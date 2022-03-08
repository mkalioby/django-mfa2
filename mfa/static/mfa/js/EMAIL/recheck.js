function send_totp() {
    const form = $('#formLogin');
    var formData = new FormData(form);
    $.ajax({"url":"{% url 'totp_recheck' %}", method:"POST",dataType:"JSON",
        data:{"csrfmiddlewaretoken":formData.get('csrf_token'),"otp":$("#otp").val()},
     success:function (data) {
                        if (data["recheck"])
                            mfa_success_function();
                        else {
                            mfa_failed_function();
                        }
                    }
    })

}