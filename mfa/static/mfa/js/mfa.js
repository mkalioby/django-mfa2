$(document).ready(function () {
    const mfa_keys = document.getElementsByClassName('mfa_key');
    for (let i = 0; i < mfa_keys.length; i++) {
        let mfa_key = mfa_keys[i];

        let key_id = mfa_key.dataset.keyId;
        let key_type = mfa_key.dataset.keyType;
        mfa_key.querySelector(`#toggle_${key_id}`).parentElement.addEventListener('click', function () {
            toggleKey(key_id);
        });
        mfa_key.querySelector(`#delete_${key_id}`).addEventListener('click', function () {
            deleteKey(key_id, String(key_type));
        })
    }
})

function confirmDel(id) {
    const mfa_delKey = JSON.parse(document.getElementById('mfa_delKey').textContent);
    const csrf_token = JSON.parse(document.getElementById('csrf_token').textContent);
    $.ajax({
        url: mfa_delKey,
        method: "POST",
        data: {"id": id, "csrfmiddlewaretoken": csrf_token},
        success: function (data) {
            alert(data)
            window.location.reload();
        }
    })
}

function deleteKey(id, name) {
    $("#modal-title").html("Confirm Delete")
    $("#modal-body").html("Are you sure you want to delete '" + name + "'? you may lose access to your system if this your only 2FA.");
    $("#actionBtn").remove()
    $("#modal-footer").prepend("<button id='actionBtn' class='btn btn-danger'>Confirm Deletion</button>")
    $("#actionBtn").click(function() { confirmDel(id); })
    $("#popUpModal").modal('show')
}

function toggleKey(id) {
    const toggle_key = JSON.parse(document.getElementById('toggle_key').textContent);
    $.ajax({
        url: toggle_key + "?id=" + id,
        success: function (data) {
            if (data == "Error")
                $("#toggle_" + id).toggle()
        },
        error: function (data) {
            $("#toggle_" + id).toggle()
        }
    })
}