$(document).ready(function addToken() {
    const form = $('#u2f_form');
    var formData = new FormData(form);
    data=JSON.parse(formData.get('token'));
    u2f.register(data.appId,data.registerRequests,data.registeredKeys,function (response) {
        $.ajax({
            "url":form.attr('action'),method:"POST",
            data:{"csrfmiddlewaretoken":formData.get('csrf_token'),"response":JSON.stringify(response)},
            success:function (data) {
                if (data == "OK")
                {
                    alert(formData.get('success'))
                    window.location.href=formData.get('redirect')
                }
            }
        })
    },5000)
})