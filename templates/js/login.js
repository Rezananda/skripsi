$(document).ready(function () {
    $("#login-form").submit(function (event) {
        /* stop form from submitting normally */
        event.preventDefault();

        // Get form data
        var formData = {
            username: $('input[name=username]').val(),
            password: $('input[name=password]').val(),
        };
        $.ajax({
            url: 'http://localhost:5001/api/login',
            type: 'POST',
            dataType: 'json',
            data: formData,
            success: function (data, textStatus, xhr) {
                //var payload = parseJwt(data.token)
                //console.log(payload)
                //location.reload()
                //if (data.admin) {
                //    window.location.replace('http://localhost:5001/admin')
                //}
                //else {
                //    window.location.replace('http://localhost:5001/home')
                //}
            },
            error: function (xhr, textStatus, errorThrown) {
                $('#alert_message').html('<div class="alert alert-danger fade in">' +
                    '<a href="#" class="close" data-dismiss="alert">&times;</a>' +
                    '<strong>Error!</strong> Wrong username or password.</div>');
            }
        });
    });
});