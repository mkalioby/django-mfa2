function confirmDel(id,confirm_url) {
    $.ajax({
        url:confirm_url,
        data:{"id":id},
        success:function (data) {
            alert(data)
            window.location.reload();
        }
    })
}
function deleteKey(id,name,confirm_url)
{
    $("#modal-title").html("Confirm Delete")
    $("#modal-body").html("Are you sure you want to delete '"+name+"'? you may lose access to your system if this your only 2FA.");
    $("#actionBtn").remove()
    $("#modal-footer").prepend("<button id='actionBtn' class='btn btn-danger' onclick='confirmDel("+id+","+confirm_url+")'>Confirm Deletion</button>")
    $("#popUpModal").modal()
}

function toggleKey(id,toggle_url) {
    $.ajax({
        url:toggle_url,
        success:function (data) {
            if (data == "Error")
                $("#toggle_"+id).toggle()

        },
        error:function (data) {
            $("#toggle_"+id).toggle()
        }
    })
}