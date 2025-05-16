$(document).ready(function () {
    const url = JSON.parse(document.getElementById('url').textContent);
    const request_user_username = JSON.parse(document.getElementById('request_user_username').textContent);
    const key = JSON.parse(document.getElementById('key').textContent);
    var qr = new QRious({
        element: document.getElementById('qr'),
        value: url + "?u="+request_user_username+"&k="+key
    });
})

function sendEmail() {
    const td_sendemail = JSON.parse(document.getElementById('td_sendemail').textContent);
    $("#modal-title").html("Send Link")
    $("#modal-body").html("Sending Email, Please wait....");
    $("#popUpModal").modal('show');
    $.ajax({
        "url": td_sendemail,
        success: function (data) {
            alert(data);
            $("#popUpModal").modal('toggle')
        }
    })
}

function failedMFA() {
    $("#modal-body").html("<div class='alert alert-danger'>Failed to validate you, please <a href='#' id='getUserAgent'>try again</a></div>")
    $("#getUserAgent").click(function () { getUserAgent() });
}

function checkMFA() {
    recheck_mfa(trustDevice, failedMFA, true)
}

function trustDevice() {
    const td_trust_device = JSON.parse(document.getElementById('td_trust_device').textContent);
    $.ajax(
        {
            "url": td_trust_device,
            success: function (data) {
                if (data == "OK") {
                    alert("Your are done, your device should show final confirmation")
                    window.location.href = "{% url 'mfa_home' %}"
                }
            }
        }
    )
}

function getUserAgent() {
    const td_get_useragent = JSON.parse(document.getElementById('td_get_useragent').textContent);
    $.ajax({
        "url": td_get_useragent, success: function (data) {
            if (data == "")
                setTimeout('getUserAgent()', 5000)
            else {
                $("#modal-title").html("Confirm Trusted Device")
                $("#actionBtn").remove();
                $("#modal-footer").prepend("<button id='actionBtn' class='btn btn-success'>Trust Device</button>")
                $("#actionBtn").click(function () { checkMFA() })
                $("#modal-body").html(data)
                $("#popUpModal").modal('show');
            }
        }
    })
}
$(document).ready(getUserAgent())