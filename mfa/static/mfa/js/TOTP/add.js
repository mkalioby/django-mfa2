var key = "";
$(document).ready(function addToken() {
    var start_url = document.getElementById('new_otp');
    $.ajax({
        "url": start_url.value, dataType: "JSON",
        success: function (data) {
            window.key = data.secret_key;
            var qr = new QRious({
                element: document.getElementById('qr'),
                value: data.qr
            });
            $("#second_step").show()
        }
    })

    // Replace Onclick
    // $('showTOTP').on('click', showTOTP);
     document.getElementById('show-TOTP').addEventListener('click', showTOTP);
     document.getElementById('show-key').addEventListener('click', showKey);
     document.getElementById('verify').addEventListener('click', verify);

});

function showKey() {
    $("#modal-title").html("Your Secret Key")
    $("#modal-body").html("<pre>" + window.key + "</pre")
    $("#popUpModal").modal('show')
}

function verify() {
    answer = $("#answer").val();
    var verify_url = document.getElementById('new_otp');
    var redirect_url = document.getElementById('id_redirect');
    var error_text = document.getElementById('id_error');
    var success_text = document.getElementById('id_success');
    $.ajax({
        "url": verify_url.value +"?key=" + key + "&answer=" + answer,
        success: function (data) {
            if (data == "Error")
                alert(error_text.value);
            else {
                alert(success_text.value);
                window.location.href = redirect_url.value;
            }
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