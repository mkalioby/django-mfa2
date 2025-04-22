var key = "";
$(document).ready(function addToken() {
    const get_new_otop = JSON.parse(document.getElementById('get_new_otop').textContent);
    $.ajax({
        "url": get_new_otop, dataType: "JSON",
        success: function (data) {
            window.key = data.secret_key;
            var qr = new QRious({
                element: document.getElementById('qr'),
                value: data.qr
            });
            $("#second_step").show()
        }
    })
});

function showKey() {
    const htmlkey = `
    <div class="row">
        <div class="col-11">
            <pre id="totp_secret">` + window.key + `</pre>
        </div>
        <div class="col-1">
            <span onclick=navigator.clipboard.writeText($("#totp_secret").text()) class="fa fa-clipboard toolbtn"></span>
        </div>
    </div>`
    $("#modal-title").html("Your Secret Key")
    $("#modal-body").html(htmlkey)
    $("#popUpModal").modal('show')
}

function verify() {
    const verify_otop = JSON.parse(document.getElementById('verify_otop').textContent);
    const redirect_html = JSON.parse(document.getElementById('redirect_html').textContent);
    const reg_success_msg = JSON.parse(document.getElementById('reg_success_msg').textContent);
    const manage_recovery_codes = JSON.parse(document.getElementById('manage_recovery_codes').textContent);
    const RECOVERY_METHOD = JSON.parse(document.getElementById('RECOVERY_METHOD').textContent);
    const mfa_home = JSON.parse(document.getElementById('mfa_home').textContent);
    answer = $("#answer").val()
    $.ajax({
        "url": verify_otop + "?key=" + key + "&answer=" + answer,
        success: function (data) {
            if (data == 'Success')
                $("#res").html("<div class='alert alert-success'>Your authenticator is registered successfully, <a href='"+redirect_html+"'> "+reg_success_msg+"</a></div>")
            else if (data == "RECOVERY") {
                setTimeout(function () {
                    location.href = manage_recovery_codes
                }, 2500)
                $("#res").html("<div class='alert alert-success'>Your authenticator is registered successfully, but <a href='"+manage_recovery_codes+"'>redirecting to "+RECOVERY_METHOD+" method</a></div>")
            } else
                $("#res").html("<div class='alert alert-danger'>The code provided doesn't match the key, please try again or <a href='"+mfa_home+"'> Go to Security Home</a></div>")

        }
    })
}

function showTOTP() {
    $("#modal-title").html("One Time Password Apps")
    html = "<div class='row'><ul>" +
        "<li>Android: <a href='https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2' target='_blank'>Google Authenticator</a> | <a href='https://play.google.com/store/apps/details?id=com.authy.authy' target='_blank'>Authy</a></li>"
    html += "<li>iPhone/iPad: <a href='https://itunes.apple.com/us/app/authy/id494168017' target='_blank'>Authy</a></li> "
    html += "<li>Chrome: <a href='https://chrome.google.com/webstore/detail/authenticator/bhghoamapcdpbohphigoooaddinpkbai?hl=en'>Google Authenticator</a> | <a href='https://chrome.google.com/webstore/detail/authy/gaedmjdfmmahhbjefcbgaolhhanlaolb?hl=en' target='_blank'>Authy</a></li>"
    html += "</ul></div>"
    $("#modal-body").html(html)
    $('#popUpModal').modal('show')
}