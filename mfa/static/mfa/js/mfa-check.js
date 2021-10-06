mfa_success_function=null;
mfa_failed_function=null;

function recheck_mfa(success_func,fail_func,must_mfa) {
    if (!must_mfa) success_func()
    window.mfa_success_function=success_func;
    window.mfa_failed_function=fail_func;
    $.ajax({
        "url":"{% url 'mfa_recheck' %}",
        success:function (data) {
            if (data.hasOwnProperty("res")) {
                if (data["res"])
                    success_func();
                else fail_func();
            }
            else
            {
                $("#modal-title").html("Recheck Indentity")
                $("#modal-body").html(data["html"])
                $("#popUpModal").modal()
            }



        }
    })
}