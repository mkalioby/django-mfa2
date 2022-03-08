function checkFlag() {
    if ($("#agree").is(":checked"))
        return true;
    else
        alert("Please agree to the statement first");
    return false;
}

function checkTrusted() {
    $.ajax({
        url: "{% url 'td_checkTrusted' %}",
        success: function (data) {
            if (data == "OK")
                window.location.href = "{% url 'td_securedevice' %}";
            else
                setTimeout('checkTrusted()', 2000)
        }

    })

}

$(document).ready(checkTrusted())