from django.urls import path

from . import FIDO2, U2F, Email, TrustedDevice, helpers, totp, views

urlpatterns = [
    path("totp/start/", totp.start, name="start_new_otop"),
    path("totp/getToken/", totp.get_token, name="get_new_otop"),
    path("totp/verify/", totp.verify, name="verify_otop"),
    path("totp/auth/", totp.auth, name="totp_auth"),
    path("totp/recheck/", totp.recheck, name="totp_recheck"),
    path("email/start/", Email.start, name="start_email"),
    path("email/auth/", Email.auth, name="email_auth"),
    path("u2f/", U2F.start, name="start_u2f"),
    path("u2f/bind/", U2F.bind, name="bind_u2f"),
    path("u2f/auth/", U2F.auth, name="u2f_auth"),
    path("u2f/process_recheck/", U2F.process_recheck, name="u2f_recheck"),
    path("u2f/verify/", U2F.verify, name="u2f_verify"),
    path("fido2/", FIDO2.start, name="start_fido2"),
    path("fido2/auth/", FIDO2.auth, name="fido2_auth"),
    path("fido2/begin_auth/", FIDO2.authenticate_begin, name="fido2_begin_auth"),
    path(
        "fido2/complete_auth/", FIDO2.authenticate_complete, name="fido2_complete_auth"
    ),
    path("fido2/begin_reg/", FIDO2.begin_registeration, name="fido2_begin_reg"),
    path("fido2/complete_reg/", FIDO2.complete_reg, name="fido2_complete_reg"),
    path("fido2/recheck/", FIDO2.recheck, name="fido2_recheck"),
    path("td/", TrustedDevice.start, name="start_td"),
    path("td/add/", TrustedDevice.add, name="add_td"),
    path("td/send_link/", TrustedDevice.send_email, name="td_sendemail"),
    path("td/get-ua/", TrustedDevice.get_user_agent, name="td_get_useragent"),
    path("td/trust/", TrustedDevice.trust_device, name="td_trust_device"),
    path("u2f/checkTrusted/", TrustedDevice.check_trusted, name="td_checkTrusted"),
    path("u2f/secure_device", TrustedDevice.get_cookie, name="td_securedevice"),
    path("", views.index, name="mfa_home"),
    path("goto/<method>/", views.goto, name="mfa_goto"),
    path("selct_method/", views.show_methods, name="mfa_methods_list"),
    path("recheck/", helpers.recheck, name="mfa_recheck"),
    path("toggleKey/", views.toggle_key, name="toggle_key"),
    path("delete/", views.del_key, name="mfa_delKey"),
    path("reset/", views.reset_cookie, name="mfa_reset_cookie"),
]
