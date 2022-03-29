$(document).ready(function () {
    document.getElementById('formLogin').addEventListener('submit', checkFlag);
})

function checkFlag() {
    if ($("#agree").is(":checked"))
        return true;
    else
        alert("Please agree to the statement first");
    return false;
}

function checkTrusted() {
    var trustedURL = document.getElementById("id_begin").value;
    var secureDeviceURL = document.getElementById('id_secure').value;
    $.ajax({
        url: trustedURL,
        success: function (data) {
            if (data == "OK")
                window.location.href =  secureDeviceURL;
            else
                setTimeout('checkTrusted()', 2000)
        }

    })

}

$(document).ready(checkTrusted())
