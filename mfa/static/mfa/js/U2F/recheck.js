$(document).ready(function () {
    const form = $('#u2f_form');
    var formData = new FormData(form);
    if (location.protocol != 'https:')
    {
        $("#main_paragraph").addClass("alert alert-danger")
        $("#main_paragraph").html(formData.get('protocol_message'))
    }
    else {


        data = JSON.parse(formData.get('token'))
        console.log(data)
        u2f.sign(data.appId, data.challenge, data.registeredKeys, function (response) {
            console.log(response)
            if (response.hasOwnProperty("errorCode") && response.errorCode != 0  )
            {
             if (response.errorCode == 4)
             {
                 alert("Invalid Security Key, this security isn't linked to your account")
             }
             else if (response.errorCode == 5)
             {
                 alert("Verification Timeout, please refresh the page to try again")
             }
             else
             {
                 alert("Unspecified error, please try again later or try another browser.")
             }
            }
            else if(formData.get('mode') === 'auth')
           {
                $("#response").val(JSON.stringify(response))
                $("#u2f_login").submit();
            }
            else if(formData.get('mode') === 'recheck') {
               var recheckURL = document.getElementById('id_recheck').value;
                $.ajax({
                    "url":recheckURL,
                    method: "POST",
                    data: {"csrfmiddlewaretoken":formData.get('csrfmiddlewaretoken'),"response":JSON.stringify(response)},
                    success:function (data) {
                        if (data["recheck"]) {
                            mfa_success_function();
                        }
                        else {
                            mfa_failed_function();
                        }
                    }

                })

            }
         
        }, 5000)
    }
    })