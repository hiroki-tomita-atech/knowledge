$(document).ready(function() {
    let url = $('#login-btn')[0].src.split('google-btn/')[0] + 'google-btn/';

    $('#login-btn').hover(function() {
            $('#login-btn')[0].src = url + 'btn_google_signin_dark_focus_web.png';
        }, function() {
            $('#login-btn')[0].src = url + 'btn_google_signin_dark_normal_web.png';
        })
        .on('click', function() {
            $('#login-btn')[0].src = url + 'btn_google_signin_dark_pressed_web.png';
        });
});