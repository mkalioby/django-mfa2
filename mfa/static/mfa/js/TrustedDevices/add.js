function checkFlag() {
    if ($("#agree").is(":checked"))
        return true;
    else
        alert("Please agree to the statement first");
    return false;
}

function checkTrusted() {
    const td_checkTrusted = JSON.parse(document.getElementById('td_checkTrusted').textContent);
    const td_securedevice = JSON.parse(document.getElementById('td_securedevice').textContent);
    $.ajax({
        url: td_checkTrusted,
        success: function (data) {
            if (data == "OK")
                window.location.href = td_securedevice;
            else
                setTimeout('checkTrusted()', 2000)
        }
    })
}
$(document).ready(checkTrusted())