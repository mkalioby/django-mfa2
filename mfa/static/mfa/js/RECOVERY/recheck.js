$(document).ready(function () {
    const mode = JSON.parse(document.getElementById('mode').textContent);
    if (mode == "recheck") {
        $("#send_recovery").click(function () {
            send_recovery()
        });
    }

    showWarningLastBackup();
});

function showWarningLastBackup() {
    const lastBackup = JSON.parse(document.getElementById('lastBackup').textContent);
    const recovery_auth = JSON.parse(document.getElementById('recovery_auth').textContent);
    if (lastBackup) {
        $("#modal-title").html("Last backup code used !")
        $("#modal-body").html("Don't forget to regenerate new backup code after login !")
        $('#modal-footer').html(`<FORM METHOD="GET" ACTION="`+recovery_auth+`" Id="confirmLogin" name="recoveryLastBackupConfirm">
            <input type='submit' class='btn btn-lg btn-success btn-block' value='Continue'>`)
        $("#popUpModal").modal('show')
    }
}

function send_recovery() {
    const recovery_recheck = JSON.parse(document.getElementById('recovery_recheck').textContent);
    const csrf_token = JSON.parse(document.getElementById('csrf_token').textContent);
    $.ajax({
        "url": recovery_recheck, method: "POST", dataType: "JSON",
        data: {"csrfmiddlewaretoken": csrf_token, "recovery": $("#recovery").val()},
        success: function (data) {
            if (data["recheck"])
                mfa_success_function();
            else {
                mfa_failed_function();
            }
        }
    })
}