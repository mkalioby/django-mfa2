$(document).ready(function () {
    const mode = JSON.parse(document.getElementById('mode').textContent);
    if (mode == "recheck") {
        $("#send_totp").click(function () {send_totp()});
    }
})