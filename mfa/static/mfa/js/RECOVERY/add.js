var clearCodes;
$(document).ready(function() {
    $("#confirmRegenerateTokens").click(function () { confirmRegenerateTokens() });

    checkTokenLeft();
});

function checkTokenLeft() {
    const get_recovery_token_left = JSON.parse(document.getElementById('get_recovery_token_left').textContent);
    const mfa_redirect = JSON.parse(document.getElementById('mfa_redirect').textContent);
    $.ajax({
        "url": get_recovery_token_left, dataType: "JSON",
        success: function (data) {
            tokenLeft = data.left
            html = ""
            if (!!mfa_redirect) {
                html += "<div class='alert alert-success'>You have enrolled successfully in "+mfa_redirect+" method, please generate recovery codes so that you can use in case you lost access to all your verification methods.</div>"
            }
            if (tokenLeft == 0) {
                html += "<h6>You don't have any backup code linked to your account, please generate new ones !</h6>"
            } else {
                html += "<p>You still have " + tokenLeft + " backup code left."
            }
            document.getElementById('tokens').innerHTML = html
        }
    })
}

function confirmRegenerateTokens() {
    htmlModal = "<h6>Caution! you can only view these token now, else you will need to generate new ones.</h6><div class='text-center'><button id='regenerateTokens' class='btn btn-success'>Regenerate</button></div>"
    $("#modal-title").html("Regenerate your recovery Codes?")
    $("#modal-body").html(htmlModal)
    $("#regenerateTokens").click(function () { regenerateTokens(); })
    $("#popUpModal").modal('show')
}

function copy() {
    navigator.clipboard.writeText($("#recovery_codes").text());
}

function regenerateTokens() {
    const regen_recovery_tokens = JSON.parse(document.getElementById('regen_recovery_tokens').textContent);
    $.ajax({
        "url": regen_recovery_tokens, dataType: "JSON",
        success: function (data) {
            let htmlkey = `<p>Here are the recovery codes, you have to save them now as you won't able to view them again.</p>
        <div class='row'><div class='offset-4 col-md-4 bg-white padding-10'>
            <div class='row'>
            <div class="col-6 offset-6">
            <span id='download_recovery' class='fa fa-download toolbtn' title="Download"></span>&nbsp;&nbsp;
            <span class='fa fa-clipboard toolbtn' id='copy_clipboard' title="Copy"></span>
            </div></div><div id='recovery_codes'><pre>`;
            for (let i = 0; i < data.keys.length; i++) {
                htmlkey += "- " + data.keys[i] + "\n"
            }
            document.getElementById('tokens').innerHTML = htmlkey + "</pre></div></div></div>"
            $("#download_recovery").click(function () {
                download_recovery();
            })
            $("#copy_clipboard").click(function () {
                copy();
            })
            $("#popUpModal").modal('hide')
            clearCodes = data.keys
        }
    })
}

function download_recovery() {
    var element = document.createElement('a');
    var text = "";
    for (let i = 0; i < clearCodes.length; i++) {
        text = text + clearCodes[i]
        if (i < clearCodes.length - 1) {
            text = text + "\n"
        }
    }
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
    element.setAttribute('download', 'Recovery Codes.txt');
    element.hidden = true;
    document.body.appendChild(element);
    element.click();
    console.log(element.innerHTML)
    document.body.removeChild(element);
}