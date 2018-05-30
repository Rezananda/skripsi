$(document).ready(function () {
    fetch_user()

    function fetch_user() {
        $('#user-table').DataTable({
            responsive: true,
            "processing": true,
            "serverSide": true,
            "info": true,
            "stateSave": true,
            "ajax": {
                url: "http://localhost:5001/api/datatables/users", // json datasource
                type: "get",  // method  , by default get
                error: function () {  // error handling
                    $(".user-table-error").html("");
                    $("#user-table").append('<tbody class="employee-grid-error"><tr><th colspan="3">No data found in the server</th></tr></tbody>');
                    $("#user-table-processing").css("display", "none");
                },
            },
            columnDefs: [{ targets: [0], class: "wrap" }],
            "columns": [
                { "data": "username" },
                { "data": "mac_address" },
                { "data": "is_admin" },
                { "data": "action" }
            ]
        });
    }

    $(document).on('click', '#add-user', function () {
        // validate input
        $(".text-danger").remove();

        var username = $("#username").val();
        var password = $("#password").val();
        var mac_address = $("#mac-address").val();
        var is_admin = $("input[name=is-admin]:checked").val();

        if (username == "") {
            $("#username").closest('.form-group').addClass('has-error');
            $("#username").after('<p class="text-danger">Username required</p>');
        } else {
            $("#username").closest('.form-group').removeClass('has-error');
            $("#username").closest('.form-group').addClass('has-success');
            username = true;
        }

        if (password == "") {
            $("#password").closest('.form-group').addClass('has-error');
            $("#password").after('<p class="text-danger">Password required</p>');
        } else {
            $("#password").closest('.form-group').removeClass('has-error');
            $("#password").closest('.form-group').addClass('has-success');
            password = true;
        }

        if (mac_address == "") {
            $("#mac-address").closest('.form-group').addClass('has-error');
            $("#mac-address").after('<p class="text-danger">Mac address required</p>');
        } else {
            $("#mac-address").closest('.form-group').removeClass('has-error');
            $("#mac-address").closest('.form-group').addClass('has-success');
            mac_address = true;
        }


        if (is_admin == undefined) {
            $("input[name=is-admin]").closest('.form-group').addClass('has-error');
        } else {
            $("input[name=is-admin]").closest('.form-group').removeClass('has-error');
            $("input[name=is-admin]").closest('.form-group').addClass('has-success');
            task = true;
        }
    });

    $('#add-user-modal').on('hidden.bs.modal', function (e) {
        $(".text-danger").remove();
        $("#username").closest('.form-group').removeClass('has-error');
        $("#username").closest('.form-group').removeClass('has-success');
        $("#password").closest('.form-group').removeClass('has-error');
        $("#password").closest('.form-group').removeClass('has-success');
        $("#mac-address").closest('.form-group').removeClass('has-error');
        $("#mac-address").closest('.form-group').removeClass('has-success');
        $("input[name=is-admin]").closest('.form-group').removeClass('has-error');
        $("input[name=is-admin]").closest('.form-group').removeClass('has-success');
    })

})