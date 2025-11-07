# Method Usage Analysis

Source file: `mfatestcase.py`

## test_common

- `get_redirect_url()` - Get Redirect Url (4 uses)
    - CommonTests.test_get_redirect_url_custom_both_settings
    - CommonTests.test_get_redirect_url_custom_redirect
    - CommonTests.test_get_redirect_url_custom_success_message
    - CommonTests.test_get_redirect_url_default_settings

## test_config

- `assertMfaKeyState()` - Assertmfakeystate (4 uses)
    - ConfigTestCase.test_disable_totp_interactive_elements_correct_case
    - ConfigTestCase.test_hide_disable_method_endpoints_still_work
    - ConfigTestCase.test_hide_disable_method_shows_no_delete_button
    - ConfigTestCase.test_hide_disable_method_shows_static_status

- `create_email_key()` - Create Email Key (2 uses)
    - ConfigTestCase.test_email_token_behavior
    - ConfigTestCase.test_method_disablement_behavior

- `create_recovery_key()` - Create Recovery Key (8 uses)
    - ConfigTestCase.test_enforced_recovery_behavior
    - ConfigTestCase.test_method_renaming_behavior
    - ConfigTestCase.test_methods_disallowed
    - ConfigTestCase.test_recovery_default_name
    - ConfigTestCase.test_recovery_enforcement_behavior
    - ConfigTestCase.test_recovery_key_table_visibility
    - ConfigTestCase.test_recovery_renamed
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `create_totp_key()` - Create Totp Key (14 uses)
    - ConfigTestCase.test_disable_totp_interactive_elements_correct_case
    - ConfigTestCase.test_enforced_recovery_behavior
    - ConfigTestCase.test_hide_disable_method_endpoints_still_work
    - ConfigTestCase.test_hide_disable_method_shows_no_delete_button
    - ConfigTestCase.test_hide_disable_method_shows_static_status
    - ConfigTestCase.test_login_callback_behavior
    - ConfigTestCase.test_method_renaming_behavior
    - ConfigTestCase.test_methods_disallowed
    - ConfigTestCase.test_recheck_behavior
    - ConfigTestCase.test_recovery_default_name
    - ConfigTestCase.test_recovery_enforcement_behavior
    - ConfigTestCase.test_recovery_key_table_visibility
    - ConfigTestCase.test_recovery_renamed
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `get_dropdown_menu_items()` - Get Dropdown Menu Items (11 uses)
    - ConfigTestCase.test_disable_totp_interactive_elements_correct_case
    - ConfigTestCase.test_disallowed_method_visibility
    - ConfigTestCase.test_hide_disable_does_not_affect_dropdown_visibility
    - ConfigTestCase.test_method_custom_names
    - ConfigTestCase.test_method_default_names
    - ConfigTestCase.test_method_hiding_wrong_case_email
    - ConfigTestCase.test_method_hiding_wrong_case_totp
    - ConfigTestCase.test_method_renaming_behavior
    - ConfigTestCase.test_methods_disallowed
    - ConfigTestCase.test_mfa_method_dropdown_visibility
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `get_key_row_content()` - Get Key Row Content (9 uses)
    - ConfigTestCase.test_disable_totp_interactive_elements_correct_case
    - ConfigTestCase.test_enforced_recovery_behavior
    - ConfigTestCase.test_hide_disable_method_shows_no_delete_button
    - ConfigTestCase.test_hide_disable_method_shows_static_status
    - ConfigTestCase.test_methods_disallowed
    - ConfigTestCase.test_recovery_default_name
    - ConfigTestCase.test_recovery_key_table_visibility
    - ConfigTestCase.test_recovery_renamed
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `get_mfa_url()` - Get Mfa Url (27 uses)
    - ConfigTestCase.test_disable_totp_interactive_elements_correct_case
    - ConfigTestCase.test_disallowed_method_visibility
    - ConfigTestCase.test_email_token_behavior
    - ConfigTestCase.test_enforced_recovery_behavior
    - ConfigTestCase.test_hide_disable_does_not_affect_dropdown_visibility
    - ConfigTestCase.test_hide_disable_method_endpoints_still_work
    - ConfigTestCase.test_hide_disable_method_shows_no_delete_button
    - ConfigTestCase.test_hide_disable_method_shows_static_status
    - ConfigTestCase.test_login_callback_behavior
    - ConfigTestCase.test_method_custom_names
    - ConfigTestCase.test_method_default_names
    - ConfigTestCase.test_method_disablement_behavior
    - ConfigTestCase.test_method_hiding_wrong_case_email
    - ConfigTestCase.test_method_hiding_wrong_case_totp
    - ConfigTestCase.test_method_name_case_sensitivity
    - ConfigTestCase.test_method_renaming_behavior
    - ConfigTestCase.test_methods_disallowed
    - ConfigTestCase.test_mfa_method_dropdown_visibility
    - ConfigTestCase.test_recheck_behavior
    - ConfigTestCase.test_recovery_codes_behavior
    - ConfigTestCase.test_recovery_default_name
    - ConfigTestCase.test_recovery_enforcement_behavior
    - ConfigTestCase.test_recovery_key_table_visibility
    - ConfigTestCase.test_recovery_renamed
    - ConfigTestCase.test_registration_message_behavior
    - ConfigTestCase.test_totp_configuration_behavior
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `get_recovery_key_row_content()` - Get Recovery Key Row Content (2 uses)
    - ConfigTestCase.test_method_renaming_behavior
    - ConfigTestCase.test_recovery_enforcement_behavior

- `get_redirect_url()` - Get Redirect Url (2 uses)
    - ConfigTestCase.test_redirect_behavior
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `get_user_keys()` - Get User Keys (1 uses)
    - ConfigTestCase.test_hide_disable_method_endpoints_still_work

- `get_valid_totp_token()` - Get Valid Totp Token (2 uses)
    - ConfigTestCase.test_recheck_behavior
    - ConfigTestCase.test_recovery_enforcement_behavior

- `login_user()` - Login User (26 uses)
    - ConfigTestCase.test_disable_totp_interactive_elements_correct_case
    - ConfigTestCase.test_disallowed_method_visibility
    - ConfigTestCase.test_email_token_behavior
    - ConfigTestCase.test_enforced_recovery_behavior
    - ConfigTestCase.test_hide_disable_does_not_affect_dropdown_visibility
    - ConfigTestCase.test_hide_disable_method_endpoints_still_work
    - ConfigTestCase.test_hide_disable_method_shows_no_delete_button
    - ConfigTestCase.test_hide_disable_method_shows_static_status
    - ConfigTestCase.test_login_callback_behavior
    - ConfigTestCase.test_method_custom_names
    - ConfigTestCase.test_method_default_names
    - ConfigTestCase.test_method_disablement_behavior
    - ConfigTestCase.test_method_hiding_wrong_case_email
    - ConfigTestCase.test_method_hiding_wrong_case_totp
    - ConfigTestCase.test_method_name_case_sensitivity
    - ConfigTestCase.test_method_renaming_behavior
    - ConfigTestCase.test_methods_disallowed
    - ConfigTestCase.test_mfa_method_dropdown_visibility
    - ConfigTestCase.test_recheck_behavior
    - ConfigTestCase.test_recovery_default_name
    - ConfigTestCase.test_recovery_enforcement_behavior
    - ConfigTestCase.test_recovery_key_table_visibility
    - ConfigTestCase.test_recovery_renamed
    - ConfigTestCase.test_redirect_behavior
    - ConfigTestCase.test_registration_message_behavior
    - MFAIntegrationTestCase.test_complete_mfa_flow

- `setUp()` - Setup (3 uses)
    - ConfigTestCase.setUp
    - MFAIntegrationTestCase.setUp
    - MFAIntegrationTestCase.test_disallowed_method_visibility

- `setup_mfa_session()` - Setup Mfa Session (2 uses)
    - ConfigTestCase.test_recheck_behavior
    - ConfigTestCase.test_recovery_enforcement_behavior

- `tearDown()` - Teardown (3 uses)
    - ConfigTestCase.tearDown
    - MFAIntegrationTestCase.tearDown
    - MFAIntegrationTestCase.test_disallowed_method_visibility

## test_email

- `assertMfaKeyState()` - Assertmfakeystate (2 uses)
    - EmailViewTests.test_auth_with_enforcement_creates_key
    - EmailViewTests.test_verify_login_success

- `assertMfaSessionUnverified()` - Assertmfasessionunverified (1 uses)
    - EmailViewTests.test_verify_login_failure

- `assertMfaSessionVerified()` - Assertmfasessionverified (2 uses)
    - EmailViewTests.test_auth_with_enforcement_creates_key
    - EmailViewTests.test_verify_login_success

- `create_email_key()` - Create Email Key (4 uses)
    - EmailModuleTests.test_auth_with_custom_method_names
    - EmailModuleTests.test_auth_with_existing_email_key
    - EmailModuleTests.test_auth_with_mfa_recheck_settings
    - EmailViewTests.setUp

- `create_recovery_key()` - Create Recovery Key (1 uses)
    - EmailViewTests.test_start_with_recovery_key_succeeds

- `get_mfa_url()` - Get Mfa Url (28 uses)
    - EmailModuleTests.test_auth_get_request
    - EmailModuleTests.test_auth_with_custom_method_names
    - EmailModuleTests.test_auth_with_enforce_email_token_enabled
    - EmailModuleTests.test_auth_with_existing_email_key
    - EmailModuleTests.test_auth_with_invalid_otp
    - EmailModuleTests.test_auth_with_mfa_recheck_settings
    - EmailModuleTests.test_start_with_custom_redirect_url
    - EmailModuleTests.test_start_without_recovery_method_enforcement
    - EmailViewTests.test_auth_get_generates_token
    - EmailViewTests.test_auth_raises_exception_when_no_email_key_and_enforcement_disabled
    - EmailViewTests.test_auth_with_empty_token_handles_gracefully
    - EmailViewTests.test_auth_with_enforcement_creates_key
    - EmailViewTests.test_auth_with_missing_otp_field_handles_gracefully
    - EmailViewTests.test_auth_with_proper_session_setup
    - EmailViewTests.test_auth_with_special_characters_handles_gracefully
    - EmailViewTests.test_auth_with_very_long_token_handles_gracefully
    - EmailViewTests.test_auth_with_whitespace_token_strips_whitespace
    - EmailViewTests.test_auth_with_wrong_otp_handles_error
    - EmailViewTests.test_auth_without_key_and_no_enforcement_raises_exception
    - EmailViewTests.test_email_subject_with_otp
    - EmailViewTests.test_start_email_get_generates_token
    - EmailViewTests.test_start_email_post_creates_key
    - EmailViewTests.test_start_email_setup_failure
    - EmailViewTests.test_start_with_recovery_key_succeeds
    - EmailViewTests.test_start_without_recovery_key_requires_recovery
    - EmailViewTests.test_token_format_validation
    - EmailViewTests.test_verify_login_failure
    - EmailViewTests.test_verify_login_success

- `get_user_keys()` - Get User Keys (13 uses)
    - EmailModuleTests.test_auth_with_custom_method_names
    - EmailModuleTests.test_auth_with_enforce_email_token_enabled
    - EmailModuleTests.test_auth_with_existing_email_key
    - EmailModuleTests.test_auth_with_invalid_otp
    - EmailModuleTests.test_start_with_custom_redirect_url
    - EmailModuleTests.test_start_with_invalid_otp
    - EmailModuleTests.test_start_without_recovery_method_enforcement
    - EmailViewTests.test_auth_raises_exception_when_no_email_key_and_enforcement_disabled
    - EmailViewTests.test_auth_with_enforcement_creates_key
    - EmailViewTests.test_auth_without_key_and_no_enforcement_raises_exception
    - EmailViewTests.test_start_email_post_creates_key
    - EmailViewTests.test_start_email_setup_failure
    - EmailViewTests.test_start_with_recovery_key_succeeds

- `login_user()` - Login User (22 uses)
    - EmailModuleTests.test_start_with_custom_redirect_url
    - EmailModuleTests.test_start_without_recovery_method_enforcement
    - EmailViewTests.test_auth_get_generates_token
    - EmailViewTests.test_auth_raises_exception_when_no_email_key_and_enforcement_disabled
    - EmailViewTests.test_auth_with_empty_token_handles_gracefully
    - EmailViewTests.test_auth_with_enforcement_creates_key
    - EmailViewTests.test_auth_with_missing_otp_field_handles_gracefully
    - EmailViewTests.test_auth_with_proper_session_setup
    - EmailViewTests.test_auth_with_special_characters_handles_gracefully
    - EmailViewTests.test_auth_with_very_long_token_handles_gracefully
    - EmailViewTests.test_auth_with_whitespace_token_strips_whitespace
    - EmailViewTests.test_auth_with_wrong_otp_handles_error
    - EmailViewTests.test_auth_without_key_and_no_enforcement_raises_exception
    - EmailViewTests.test_email_subject_with_otp
    - EmailViewTests.test_start_email_get_generates_token
    - EmailViewTests.test_start_email_post_creates_key
    - EmailViewTests.test_start_email_setup_failure
    - EmailViewTests.test_start_with_recovery_key_succeeds
    - EmailViewTests.test_start_without_recovery_key_requires_recovery
    - EmailViewTests.test_token_format_validation
    - EmailViewTests.test_verify_login_failure
    - EmailViewTests.test_verify_login_success

- `setUp()` - Setup (2 uses)
    - EmailModuleTests.setUp
    - EmailViewTests.setUp

- `setup_session_base_username()` - Setup Session Base Username (15 uses)
    - EmailViewTests.test_auth_get_generates_token
    - EmailViewTests.test_auth_raises_exception_when_no_email_key_and_enforcement_disabled
    - EmailViewTests.test_auth_with_empty_token_handles_gracefully
    - EmailViewTests.test_auth_with_enforcement_creates_key
    - EmailViewTests.test_auth_with_missing_otp_field_handles_gracefully
    - EmailViewTests.test_auth_with_proper_session_setup
    - EmailViewTests.test_auth_with_special_characters_handles_gracefully
    - EmailViewTests.test_auth_with_very_long_token_handles_gracefully
    - EmailViewTests.test_auth_with_whitespace_token_strips_whitespace
    - EmailViewTests.test_auth_with_wrong_otp_handles_error
    - EmailViewTests.test_auth_without_key_and_no_enforcement_raises_exception
    - EmailViewTests.test_email_subject_with_otp
    - EmailViewTests.test_token_format_validation
    - EmailViewTests.test_verify_login_failure
    - EmailViewTests.test_verify_login_success

## test_fido2

- `assertMfaSessionVerified()` - Assertmfasessionverified (1 uses)
    - FIDO2AuthenticationTests.test_authenticate_complete_success_authenticated_user

- `create_fido2_key()` - Create Fido2 Key (6 uses)
    - FIDO2AuthenticationTests.setUp
    - FIDO2AuthenticationTests.test_authenticate_complete_recheck_scenario
    - FIDO2EdgeCaseTests.test_authenticate_complete_credential_id_lookup
    - FIDO2EdgeCaseTests.test_authenticate_complete_userhandle_lookup
    - FIDO2RegistrationTests.test_begin_registration_with_existing_credentials
    - FIDO2UtilityTests.test_getUserCredentials_retrieves_credentials

- `create_http_request_mock()` - Create Http Request Mock (7 uses)
    - FIDO2AuthenticationTests.test_authenticate_complete_credential_matching_failure_authenticated_user
    - FIDO2AuthenticationTests.test_authenticate_complete_invalid_json
    - FIDO2AuthenticationTests.test_authenticate_complete_no_username
    - FIDO2AuthenticationTests.test_authenticate_complete_wrong_challenge
    - FIDO2EdgeCaseTests.test_authenticate_complete_credential_id_lookup
    - FIDO2EdgeCaseTests.test_authenticate_complete_no_matching_credentials
    - FIDO2EdgeCaseTests.test_authenticate_complete_userhandle_lookup

- `create_recovery_key()` - Create Recovery Key (3 uses)
    - FIDO2RegistrationTests.test_create_recovery_key_with_custom_properties
    - FIDO2RegistrationTests.test_create_recovery_key_with_real_format
    - FIDO2RegistrationTests.test_start_view_renders_template_with_recovery_codes

- `get_mfa_url()` - Get Mfa Url (17 uses)
    - FIDO2AuthenticationTests.test_authenticate_begin_success
    - FIDO2AuthenticationTests.test_authenticate_begin_with_base_username
    - FIDO2AuthenticationTests.test_authenticate_complete_credential_matching_failure
    - FIDO2AuthenticationTests.test_authenticate_complete_missing_session_state
    - FIDO2AuthenticationTests.test_authenticate_complete_success_authenticated_user
    - FIDO2RegistrationTests.test_auth_view_renders_template_with_csrf
    - FIDO2RegistrationTests.test_authenticate_complete_empty_request_body
    - FIDO2RegistrationTests.test_begin_registration_success
    - FIDO2RegistrationTests.test_begin_registration_with_existing_credentials
    - FIDO2RegistrationTests.test_complete_registration_cbor_parsing_error
    - FIDO2RegistrationTests.test_complete_registration_empty_request_body
    - FIDO2RegistrationTests.test_complete_registration_fido2_library_exception
    - FIDO2RegistrationTests.test_complete_registration_invalid_json
    - FIDO2RegistrationTests.test_complete_registration_missing_session_state
    - FIDO2RegistrationTests.test_complete_registration_recovery_enforcement
    - FIDO2RegistrationTests.test_complete_registration_success
    - FIDO2RegistrationTests.test_start_view_renders_template_with_recovery_codes

- `get_unauthenticated_user()` - Get Unauthenticated User (3 uses)
    - FIDO2AuthenticationTests.test_authenticate_complete_no_username
    - FIDO2EdgeCaseTests.test_authenticate_complete_credential_id_lookup
    - FIDO2EdgeCaseTests.test_authenticate_complete_userhandle_lookup

- `login_user()` - Login User (18 uses)
    - FIDO2AuthenticationTests.test_authenticate_begin_success
    - FIDO2AuthenticationTests.test_authenticate_complete_credential_matching_failure
    - FIDO2AuthenticationTests.test_authenticate_complete_credential_matching_failure_authenticated_user
    - FIDO2AuthenticationTests.test_authenticate_complete_success_authenticated_user
    - FIDO2RegistrationTests.test_auth_view_renders_template_with_csrf
    - FIDO2RegistrationTests.test_authenticate_complete_empty_request_body
    - FIDO2RegistrationTests.test_begin_registration_success
    - FIDO2RegistrationTests.test_begin_registration_with_existing_credentials
    - FIDO2RegistrationTests.test_complete_registration_cbor_parsing_error
    - FIDO2RegistrationTests.test_complete_registration_empty_request_body
    - FIDO2RegistrationTests.test_complete_registration_fido2_library_exception
    - FIDO2RegistrationTests.test_complete_registration_invalid_json
    - FIDO2RegistrationTests.test_complete_registration_missing_session_state
    - FIDO2RegistrationTests.test_complete_registration_recovery_enforcement
    - FIDO2RegistrationTests.test_complete_registration_success
    - FIDO2RegistrationTests.test_create_recovery_key_with_custom_properties
    - FIDO2RegistrationTests.test_create_recovery_key_with_real_format
    - FIDO2RegistrationTests.test_start_view_renders_template_with_recovery_codes

- `setUp()` - Setup (3 uses)
    - FIDO2AuthenticationTests.setUp
    - FIDO2EdgeCaseTests.setUp
    - FIDO2RegistrationTests.setUp

- `setup_session_base_username()` - Setup Session Base Username (5 uses)
    - FIDO2AuthenticationTests.setUp
    - FIDO2EdgeCaseTests.setUp
    - FIDO2RegistrationTests.setUp
    - FIDO2RegistrationTests.test_auth_view_renders_template_with_csrf
    - FIDO2RegistrationTests.test_authenticate_complete_empty_request_body

## test_helpers

- `create_email_key()` - Create Email Key (2 uses)
    - HelpersTests.test_has_mfa_with_multiple_key_types
    - HelpersTests.test_has_mfa_with_only_disabled_multiple_types

- `create_fido2_key()` - Create Fido2 Key (1 uses)
    - HelpersTests.test_recheck_fido2_method

- `create_recovery_key()` - Create Recovery Key (2 uses)
    - HelpersTests.test_has_mfa_with_multiple_key_types
    - HelpersTests.test_has_mfa_with_only_disabled_multiple_types

- `create_totp_key()` - Create Totp Key (16 uses)
    - HelpersTests.test_has_mfa_with_disabled_keys
    - HelpersTests.test_has_mfa_with_enabled_keys
    - HelpersTests.test_has_mfa_with_mixed_keys
    - HelpersTests.test_has_mfa_with_multiple_key_types
    - HelpersTests.test_has_mfa_with_only_disabled_multiple_types
    - HelpersTests.test_is_mfa_empty_ignore_methods
    - HelpersTests.test_is_mfa_ignores_methods
    - HelpersTests.test_is_mfa_ignores_specified_method
    - HelpersTests.test_is_mfa_verified_false
    - HelpersTests.test_is_mfa_verified_true
    - HelpersTests.test_is_mfa_with_custom_ignore_methods
    - HelpersTests.test_is_mfa_with_none_ignore_methods
    - HelpersTests.test_recheck_empty_method
    - HelpersTests.test_recheck_none_method
    - HelpersTests.test_recheck_totp_method
    - HelpersTests.test_recheck_unknown_method

- `create_trusted_device_key()` - Create Trusted Device Key (2 uses)
    - HelpersTests.test_recheck_trusted_device_method
    - HelpersTests.test_recheck_with_trusted_device_false

- `create_u2f_key()` - Create U2F Key (2 uses)
    - HelpersTests.test_recheck_u2f_method
    - HelpersTests.test_recheck_u2f_with_valid_config

## test_mfatestcase

- `assertMfaKeyState()` - Assertmfakeystate (5 uses)
    - MFATestCaseTests.test_assertMfaKeyState_disabled
    - MFATestCaseTests.test_assertMfaKeyState_enabled
    - MFATestCaseTests.test_assertMfaKeyState_enabled_and_last_used
    - MFATestCaseTests.test_assertMfaKeyState_last_used
    - MFATestCaseTests.test_assertMfaKeyState_last_used_none

- `assertMfaSessionState()` - Assertmfasessionstate (8 uses)
    - MFATestCaseTests.test_assertMfaSessionState_empty_session
    - MFATestCaseTests.test_assertMfaSessionState_invalid_structure
    - MFATestCaseTests.test_assertMfaSessionState_no_session
    - MFATestCaseTests.test_assertMfaSessionState_none_session
    - MFATestCaseTests.test_assertMfaSessionState_partial_verification
    - MFATestCaseTests.test_assertMfaSessionState_verified_false
    - MFATestCaseTests.test_assertMfaSessionState_verified_true
    - MFATestCaseTests.test_assertMfaSessionState_verified_without_method_id

- `assertMfaSessionUnverified()` - Assertmfasessionunverified (1 uses)
    - MFATestCaseTests.test_assert_mfa_session_unverified_when_verified

- `assertMfaSessionVerified()` - Assertmfasessionverified (3 uses)
    - MFATestCaseTests.test_mfa_session_verification_failure
    - MFATestCaseTests.test_mfa_session_verification_success
    - MFATestCaseTests.test_verify_session_saved_failure

- `assert_recovery_key_has_codes()` - Assert Recovery Key Has Codes (3 uses)
    - MFATestCaseTests.test_assert_recovery_key_has_codes_invalid_format_fails
    - MFATestCaseTests.test_assert_recovery_key_has_codes_utility
    - MFATestCaseTests.test_assert_recovery_key_has_codes_without_expected_count_codes

- `complete_trusted_device_registration()` - Complete Trusted Device Registration (2 uses)
    - MFATestCaseTests.test_complete_trusted_device_registration
    - MFATestCaseTests.test_complete_trusted_device_registration_custom_user_agent

- `create_email_key()` - Create Email Key (5 uses)
    - MFATestCaseTests.test_create_email_key_disabled
    - MFATestCaseTests.test_create_email_key_enabled
    - MFATestCaseTests.test_get_user_keys_all
    - MFATestCaseTests.test_get_user_keys_filtered
    - MFATestCaseTests.test_mfa_unallowed_methods_ui_behavior

- `create_fido2_credential_data()` - Create Fido2 Credential Data (1 uses)
    - MFATestCaseTests.test_create_fido2_credential_data

- `create_fido2_key()` - Create Fido2 Key (4 uses)
    - MFATestCaseTests.test_create_fido2_key_disabled
    - MFATestCaseTests.test_create_fido2_key_enabled
    - MFATestCaseTests.test_fido2_key_creation_format
    - MFATestCaseTests.test_fido2_key_disabled_state

- `create_http_request_mock()` - Create Http Request Mock (2 uses)
    - MFATestCaseTests.test_create_http_request_mock
    - MFATestCaseTests.test_create_http_request_mock_custom_username

- `create_mock_request()` - Create Mock Request (2 uses)
    - MFATestCaseTests.test_create_mock_request
    - MFATestCaseTests.test_create_mock_request_custom_username

- `create_recovery_key()` - Create Recovery Key (20 uses)
    - MFATestCaseTests.test_assert_recovery_key_has_codes_invalid_format_fails
    - MFATestCaseTests.test_assert_recovery_key_has_codes_utility
    - MFATestCaseTests.test_assert_recovery_key_has_codes_without_expected_count_codes
    - MFATestCaseTests.test_create_recovery_key_disabled
    - MFATestCaseTests.test_create_recovery_key_enabled
    - MFATestCaseTests.test_get_recovery_codes_count_finds_first_key_when_no_key_id
    - MFATestCaseTests.test_get_recovery_codes_count_returns_zero_for_invalid_format
    - MFATestCaseTests.test_get_recovery_codes_count_utility
    - MFATestCaseTests.test_get_recovery_key_row_content_finds_enabled_key
    - MFATestCaseTests.test_get_recovery_key_row_content_missing_elements_returns_empty
    - MFATestCaseTests.test_get_user_keys_all
    - MFATestCaseTests.test_get_user_keys_filtered
    - MFATestCaseTests.test_get_valid_recovery_code_finds_first_key_when_no_key_id
    - MFATestCaseTests.test_get_valid_recovery_code_raises_error_when_invalid_format
    - MFATestCaseTests.test_get_valid_recovery_code_raises_error_when_no_codes_available
    - MFATestCaseTests.test_get_valid_recovery_code_utility
    - MFATestCaseTests.test_get_valid_recovery_code_with_specific_key_id
    - MFATestCaseTests.test_recovery_key_code_generation
    - MFATestCaseTests.test_simulate_recovery_code_usage_code_not_found_raises_error
    - MFATestCaseTests.test_simulate_recovery_code_usage_utility

- `create_recovery_key_with_real_codes()` - Create Recovery Key With Real Codes (8 uses)
    - MFATestCaseTests.test_assert_recovery_key_has_codes_utility
    - MFATestCaseTests.test_assert_recovery_key_has_codes_without_expected_count_codes
    - MFATestCaseTests.test_create_recovery_key_with_real_codes
    - MFATestCaseTests.test_create_recovery_key_with_real_codes_custom_count
    - MFATestCaseTests.test_create_recovery_key_with_real_codes_disabled
    - MFATestCaseTests.test_get_recovery_codes_count_utility
    - MFATestCaseTests.test_get_valid_recovery_code_utility
    - MFATestCaseTests.test_simulate_recovery_code_usage_real_format_raises_error

- `create_totp_key()` - Create Totp Key (24 uses)
    - MFATestCaseTests.test_assertMfaKeyState_disabled
    - MFATestCaseTests.test_assertMfaKeyState_enabled
    - MFATestCaseTests.test_assertMfaKeyState_enabled_and_last_used
    - MFATestCaseTests.test_assertMfaKeyState_last_used
    - MFATestCaseTests.test_assertMfaKeyState_last_used_none
    - MFATestCaseTests.test_assertMfaSessionState_partial_verification
    - MFATestCaseTests.test_assertMfaSessionState_verified_true
    - MFATestCaseTests.test_create_totp_key_disabled
    - MFATestCaseTests.test_create_totp_key_enabled
    - MFATestCaseTests.test_get_key_row_content_finds_disabled_key
    - MFATestCaseTests.test_get_key_row_content_finds_enabled_key
    - MFATestCaseTests.test_get_key_row_content_handles_dynamic_content
    - MFATestCaseTests.test_get_key_row_content_handles_html_attributes
    - MFATestCaseTests.test_get_key_row_content_handles_nested_elements
    - MFATestCaseTests.test_get_key_row_content_handles_whitespace_variations
    - MFATestCaseTests.test_get_key_row_content_isolates_correct_row
    - MFATestCaseTests.test_get_recovery_key_row_content_returns_empty_for_non_recovery_key
    - MFATestCaseTests.test_get_user_keys_all
    - MFATestCaseTests.test_get_user_keys_filtered
    - MFATestCaseTests.test_get_valid_totp_token_generates_valid_code
    - MFATestCaseTests.test_get_valid_totp_token_with_different_keys
    - MFATestCaseTests.test_mfa_unallowed_methods_ui_behavior
    - MFATestCaseTests.test_reset_session
    - MFATestCaseTests.test_totp_token_generation

- `create_trusted_device_jwt_token()` - Create Trusted Device Jwt Token (2 uses)
    - MFATestCaseTests.test_create_trusted_device_jwt_token
    - MFATestCaseTests.test_verify_trusted_device_success

- `create_trusted_device_key()` - Create Trusted Device Key (15 uses)
    - MFATestCaseTests.test_create_trusted_device_jwt_token
    - MFATestCaseTests.test_create_trusted_device_key_custom_properties
    - MFATestCaseTests.test_create_trusted_device_key_disabled
    - MFATestCaseTests.test_create_trusted_device_key_enabled
    - MFATestCaseTests.test_get_trusted_device_key_custom_user
    - MFATestCaseTests.test_get_trusted_device_key_default_user
    - MFATestCaseTests.test_trusted_device_ip_address_storage
    - MFATestCaseTests.test_trusted_device_key_creation_format
    - MFATestCaseTests.test_trusted_device_key_disabled_state
    - MFATestCaseTests.test_trusted_device_key_generation
    - MFATestCaseTests.test_trusted_device_user_agent_parsing
    - MFATestCaseTests.test_verify_trusted_device_exception_handling
    - MFATestCaseTests.test_verify_trusted_device_exception_handling_covers_lines_1442_1445
    - MFATestCaseTests.test_verify_trusted_device_failure
    - MFATestCaseTests.test_verify_trusted_device_success

- `create_u2f_device_mock()` - Create U2F Device Mock (3 uses)
    - MFATestCaseTests.test_u2f_complete_flow_integration
    - MFATestCaseTests.test_u2f_device_mock_custom_values_integration
    - MFATestCaseTests.test_u2f_device_mock_integration

- `create_u2f_enrollment_mock()` - Create U2F Enrollment Mock (3 uses)
    - MFATestCaseTests.test_u2f_complete_flow_integration
    - MFATestCaseTests.test_u2f_enrollment_mock_custom_appid_integration
    - MFATestCaseTests.test_u2f_enrollment_mock_integration

- `create_u2f_key()` - Create U2F Key (3 uses)
    - MFATestCaseTests.test_create_u2f_key_disabled
    - MFATestCaseTests.test_create_u2f_key_enabled
    - MFATestCaseTests.test_u2f_complete_flow_integration

- `create_u2f_response_data()` - Create U2F Response Data (3 uses)
    - MFATestCaseTests.test_u2f_complete_flow_integration
    - MFATestCaseTests.test_u2f_response_data_custom_values_integration
    - MFATestCaseTests.test_u2f_response_data_integration

- `dummy_logout()` - Dummy Logout (1 uses)
    - MFATestCaseTests.test_dummy_logout_function

- `get_authenticated_user()` - Get Authenticated User (1 uses)
    - MFATestCaseTests.test_get_authenticated_user

- `get_dropdown_menu_items()` - Get Dropdown Menu Items (8 uses)
    - MFATestCaseTests.test_get_dropdown_menu_items_basic
    - MFATestCaseTests.test_get_dropdown_menu_items_custom_class
    - MFATestCaseTests.test_get_dropdown_menu_items_empty_input
    - MFATestCaseTests.test_get_dropdown_menu_items_empty_menu_custom_class_raises_error
    - MFATestCaseTests.test_get_dropdown_menu_items_empty_menu_raises_error
    - MFATestCaseTests.test_get_dropdown_menu_items_malformed_html
    - MFATestCaseTests.test_get_dropdown_menu_items_multiple_menus
    - MFATestCaseTests.test_get_dropdown_menu_items_with_html_content

- `get_invalid_recovery_code()` - Get Invalid Recovery Code (1 uses)
    - MFATestCaseTests.test_get_invalid_recovery_code_utility

- `get_invalid_totp_token()` - Get Invalid Totp Token (3 uses)
    - MFATestCaseTests.test_get_invalid_totp_token_consistency
    - MFATestCaseTests.test_get_invalid_totp_token_returns_consistent_value
    - MFATestCaseTests.test_totp_token_generation

- `get_key_row_content()` - Get Key Row Content (9 uses)
    - MFATestCaseTests.test_get_key_row_content_finds_disabled_key
    - MFATestCaseTests.test_get_key_row_content_finds_enabled_key
    - MFATestCaseTests.test_get_key_row_content_handles_dynamic_content
    - MFATestCaseTests.test_get_key_row_content_handles_html_attributes
    - MFATestCaseTests.test_get_key_row_content_handles_malformed_html
    - MFATestCaseTests.test_get_key_row_content_handles_nested_elements
    - MFATestCaseTests.test_get_key_row_content_handles_whitespace_variations
    - MFATestCaseTests.test_get_key_row_content_isolates_correct_row
    - MFATestCaseTests.test_get_key_row_content_returns_empty_for_nonexistent

- `get_mfa_url()` - Get Mfa Url (4 uses)
    - MFATestCaseTests.test_get_mfa_url
    - MFATestCaseTests.test_get_mfa_url_invalid
    - MFATestCaseTests.test_get_mfa_url_namespace_handling
    - MFATestCaseTests.test_verify_session_saved_helper

- `get_recovery_codes_count()` - Get Recovery Codes Count (5 uses)
    - MFATestCaseTests.test_get_recovery_codes_count_finds_first_key_when_no_key_id
    - MFATestCaseTests.test_get_recovery_codes_count_raises_error_when_no_key_found
    - MFATestCaseTests.test_get_recovery_codes_count_returns_zero_for_invalid_format
    - MFATestCaseTests.test_get_recovery_codes_count_utility
    - MFATestCaseTests.test_simulate_recovery_code_usage_utility

- `get_recovery_key_row_content()` - Get Recovery Key Row Content (4 uses)
    - MFATestCaseTests.test_get_recovery_key_row_content_finds_enabled_key
    - MFATestCaseTests.test_get_recovery_key_row_content_missing_elements_returns_empty
    - MFATestCaseTests.test_get_recovery_key_row_content_returns_empty_for_non_recovery_key
    - MFATestCaseTests.test_get_recovery_key_row_content_returns_empty_for_nonexistent_key

- `get_redirect_url()` - Get Redirect Url (3 uses)
    - MFATestCaseTests.test_get_redirect_url_custom
    - MFATestCaseTests.test_get_redirect_url_default
    - MFATestCaseTests.test_get_redirect_url_fallback_to_default_when_invalid_url_name

- `get_trusted_device_key()` - Get Trusted Device Key (3 uses)
    - MFATestCaseTests.test_get_trusted_device_key_custom_user
    - MFATestCaseTests.test_get_trusted_device_key_default_user
    - MFATestCaseTests.test_get_trusted_device_key_nonexistent_user

- `get_unauthenticated_user()` - Get Unauthenticated User (1 uses)
    - MFATestCaseTests.test_get_unauthenticated_user

- `get_user_keys()` - Get User Keys (8 uses)
    - MFATestCaseTests.test_complete_trusted_device_registration
    - MFATestCaseTests.test_complete_trusted_device_registration_custom_user_agent
    - MFATestCaseTests.test_get_trusted_device_key_nonexistent_user
    - MFATestCaseTests.test_get_user_keys_all
    - MFATestCaseTests.test_get_user_keys_filtered
    - MFATestCaseTests.test_get_user_keys_nonexistent_type
    - MFATestCaseTests.test_mfa_unallowed_methods_ui_behavior
    - MFATestCaseTests.test_setup_trusted_device_test

- `get_valid_recovery_code()` - Get Valid Recovery Code (7 uses)
    - MFATestCaseTests.test_get_valid_recovery_code_finds_first_key_when_no_key_id
    - MFATestCaseTests.test_get_valid_recovery_code_raises_error_when_invalid_format
    - MFATestCaseTests.test_get_valid_recovery_code_raises_error_when_no_codes_available
    - MFATestCaseTests.test_get_valid_recovery_code_raises_error_when_no_key_found
    - MFATestCaseTests.test_get_valid_recovery_code_utility
    - MFATestCaseTests.test_get_valid_recovery_code_with_specific_key_id
    - MFATestCaseTests.test_simulate_recovery_code_usage_utility

- `get_valid_totp_token()` - Get Valid Totp Token (4 uses)
    - MFATestCaseTests.test_get_valid_totp_token_generates_valid_code
    - MFATestCaseTests.test_get_valid_totp_token_raises_value_error_when_no_totp_key_exists
    - MFATestCaseTests.test_get_valid_totp_token_with_different_keys
    - MFATestCaseTests.test_totp_token_generation

- `login_user()` - Login User (2 uses)
    - MFATestCaseTests.setUp
    - MFATestCaseTests.test_login_user_method

- `setUp()` - Setup (1 uses)
    - MFATestCaseTests.setUp

- `setup_mfa_session()` - Setup Mfa Session (10 uses)
    - MFATestCaseTests.test_assert_mfa_session_unverified_when_verified
    - MFATestCaseTests.test_mfa_session_verification_failure
    - MFATestCaseTests.test_mfa_session_verification_success
    - MFATestCaseTests.test_setup_mfa_session_custom_values
    - MFATestCaseTests.test_setup_mfa_session_default_values
    - MFATestCaseTests.test_tearDown_cleanup
    - MFATestCaseTests.test_validate_session_structure_valid
    - MFATestCaseTests.test_verify_mfa_session_accessible
    - MFATestCaseTests.test_verify_mfa_session_accessible_unallowed_method
    - MFATestCaseTests.test_verify_session_saved_helper

- `setup_session_base_username()` - Setup Session Base Username (1 uses)
    - MFATestCaseTests.test_setup_session_base_username

- `setup_trusted_device_test()` - Setup Trusted Device Test (1 uses)
    - MFATestCaseTests.test_setup_trusted_device_test

- `simulate_recovery_code_usage()` - Simulate Recovery Code Usage (3 uses)
    - MFATestCaseTests.test_simulate_recovery_code_usage_code_not_found_raises_error
    - MFATestCaseTests.test_simulate_recovery_code_usage_real_format_raises_error
    - MFATestCaseTests.test_simulate_recovery_code_usage_utility

- `tearDown()` - Teardown (2 uses)
    - MFATestCaseTests.tearDown
    - MFATestCaseTests.test_tearDown_cleanup

- `verify_trusted_device()` - Verify Trusted Device (4 uses)
    - MFATestCaseTests.test_verify_trusted_device_exception_handling
    - MFATestCaseTests.test_verify_trusted_device_exception_handling_covers_lines_1442_1445
    - MFATestCaseTests.test_verify_trusted_device_failure
    - MFATestCaseTests.test_verify_trusted_device_success

## test_recovery

- `assertMfaKeyState()` - Assertmfakeystate (1 uses)
    - RecoveryViewTests.test_recovery_auth_success

- `assertMfaSessionUnverified()` - Assertmfasessionunverified (1 uses)
    - RecoveryViewTests.test_recovery_auth_failure_invalid_code

- `assertMfaSessionVerified()` - Assertmfasessionverified (2 uses)
    - RecoveryViewTests.test_recovery_auth_success
    - RecoveryViewTests.test_recovery_session_integration

- `assert_recovery_key_has_codes()` - Assert Recovery Key Has Codes (1 uses)
    - RecoveryViewTests.test_recovery_key_with_real_format

- `create_http_request_mock()` - Create Http Request Mock (2 uses)
    - RecoveryViewTests.test_recovery_code_regeneration
    - RecoveryViewTests.test_recovery_salt_uniqueness

- `create_mock_request()` - Create Mock Request (2 uses)
    - RecoveryViewTests.test_recovery_code_deletion
    - RecoveryViewTests.test_recovery_get_token_left

- `create_recovery_key()` - Create Recovery Key (1 uses)
    - RecoveryViewTests.test_recovery_key_creation_structure

- `create_recovery_key_with_real_codes()` - Create Recovery Key With Real Codes (12 uses)
    - RecoveryViewTests.setUp
    - RecoveryViewTests.test_recovery_code_consumption_removal
    - RecoveryViewTests.test_recovery_code_deletion
    - RecoveryViewTests.test_recovery_code_regeneration
    - RecoveryViewTests.test_recovery_get_token_left
    - RecoveryViewTests.test_recovery_key_creation_structure
    - RecoveryViewTests.test_recovery_key_with_real_format
    - RecoveryViewTests.test_recovery_last_used_timestamp_update
    - RecoveryViewTests.test_recovery_multiple_keys_handling
    - RecoveryViewTests.test_recovery_salt_uniqueness
    - RecoveryViewTests.test_verify_login_function_failure
    - RecoveryViewTests.test_verify_login_function_last_code

- `get_invalid_recovery_code()` - Get Invalid Recovery Code (2 uses)
    - RecoveryViewTests.test_recovery_auth_failure_invalid_code
    - RecoveryViewTests.test_recovery_recheck_failure

- `get_mfa_url()` - Get Mfa Url (14 uses)
    - RecoveryViewTests.test_recovery_auth_empty_code
    - RecoveryViewTests.test_recovery_auth_failure_invalid_code
    - RecoveryViewTests.test_recovery_auth_failure_wrong_format
    - RecoveryViewTests.test_recovery_auth_get_after_last_backup
    - RecoveryViewTests.test_recovery_auth_last_backup_code
    - RecoveryViewTests.test_recovery_auth_success
    - RecoveryViewTests.test_recovery_recheck_failure
    - RecoveryViewTests.test_recovery_recheck_get
    - RecoveryViewTests.test_recovery_recheck_success
    - RecoveryViewTests.test_recovery_session_integration
    - RecoveryViewTests.test_recovery_start_get
    - RecoveryViewTests.test_recovery_start_with_mfa_registration_redirect
    - RecoveryViewTests.test_recovery_start_with_redirect
    - RecoveryViewTests.test_recovery_template_context

- `get_recovery_codes_count()` - Get Recovery Codes Count (1 uses)
    - RecoveryViewTests.test_recovery_key_with_real_format

- `get_user_keys()` - Get User Keys (4 uses)
    - RecoveryViewTests.cleanup_recovery_keys
    - RecoveryViewTests.test_recovery_code_deletion
    - RecoveryViewTests.test_recovery_code_regeneration
    - RecoveryViewTests.test_recovery_salt_uniqueness

- `login_user()` - Login User (13 uses)
    - RecoveryViewTests.test_recovery_auth_empty_code
    - RecoveryViewTests.test_recovery_auth_failure_invalid_code
    - RecoveryViewTests.test_recovery_auth_failure_wrong_format
    - RecoveryViewTests.test_recovery_auth_last_backup_code
    - RecoveryViewTests.test_recovery_auth_success
    - RecoveryViewTests.test_recovery_code_deletion
    - RecoveryViewTests.test_recovery_code_regeneration
    - RecoveryViewTests.test_recovery_get_token_left
    - RecoveryViewTests.test_recovery_salt_uniqueness
    - RecoveryViewTests.test_recovery_session_integration
    - RecoveryViewTests.test_recovery_start_get
    - RecoveryViewTests.test_recovery_start_with_mfa_registration_redirect
    - RecoveryViewTests.test_recovery_start_with_redirect

- `setUp()` - Setup (1 uses)
    - RecoveryViewTests.setUp

- `setup_mfa_session()` - Setup Mfa Session (5 uses)
    - RecoveryViewTests.test_recovery_auth_get_after_last_backup
    - RecoveryViewTests.test_recovery_recheck_failure
    - RecoveryViewTests.test_recovery_recheck_get
    - RecoveryViewTests.test_recovery_recheck_success
    - RecoveryViewTests.test_recovery_template_context

- `setup_session_base_username()` - Setup Session Base Username (7 uses)
    - RecoveryViewTests.setUp
    - RecoveryViewTests.test_recovery_auth_empty_code
    - RecoveryViewTests.test_recovery_auth_failure_invalid_code
    - RecoveryViewTests.test_recovery_auth_failure_wrong_format
    - RecoveryViewTests.test_recovery_auth_last_backup_code
    - RecoveryViewTests.test_recovery_auth_success
    - RecoveryViewTests.test_recovery_session_integration

## test_totp

- `assertMfaKeyState()` - Assertmfakeystate (2 uses)
    - TOTPViewTests.test_auth_with_valid_token_success
    - TOTPViewTests.test_verify_token_with_valid_structure_but_unverified

- `assertMfaSessionUnverified()` - Assertmfasessionunverified (1 uses)
    - TOTPViewTests.test_auth_with_invalid_token_failure

- `assertMfaSessionVerified()` - Assertmfasessionverified (2 uses)
    - TOTPViewTests.test_auth_with_valid_token_success
    - TOTPViewTests.test_verify_token_with_valid_structure_but_unverified

- `create_http_request_mock()` - Create Http Request Mock (6 uses)
    - TOTPModuleTests.test_getToken_with_custom_issuer_name
    - TOTPModuleTests.test_recheck_with_invalid_token
    - TOTPModuleTests.test_recheck_with_mfa_recheck_settings
    - TOTPModuleTests.test_recheck_with_valid_token
    - TOTPModuleTests.test_verify_login_with_pyotp_exception
    - TOTPModuleTests.test_verify_with_custom_method_names

- `create_recovery_key()` - Create Recovery Key (1 uses)
    - TOTPViewTests.test_verify_with_recovery_enforcement

- `create_totp_key()` - Create Totp Key (13 uses)
    - TOTPModuleTests.test_auth_with_custom_method_names
    - TOTPModuleTests.test_auth_with_invalid_token_verification
    - TOTPModuleTests.test_auth_with_mfa_recheck_settings
    - TOTPModuleTests.test_auth_with_valid_token_length
    - TOTPModuleTests.test_recheck_with_invalid_token
    - TOTPModuleTests.test_recheck_with_mfa_recheck_settings
    - TOTPModuleTests.test_recheck_with_valid_token
    - TOTPModuleTests.test_verify_login_with_disabled_key
    - TOTPModuleTests.test_verify_login_with_invalid_token
    - TOTPModuleTests.test_verify_login_with_multiple_keys
    - TOTPModuleTests.test_verify_login_with_pyotp_exception
    - TOTPModuleTests.test_verify_login_with_valid_token
    - TOTPViewTests.setUp

- `get_invalid_totp_token()` - Get Invalid Totp Token (3 uses)
    - TOTPViewTests.test_auth_with_invalid_token_failure
    - TOTPViewTests.test_recheck_failure
    - TOTPViewTests.test_recheck_get_failure

- `get_mfa_url()` - Get Mfa Url (22 uses)
    - TOTPModuleTests.test_auth_with_custom_method_names
    - TOTPModuleTests.test_auth_with_invalid_token_length
    - TOTPModuleTests.test_auth_with_invalid_token_verification
    - TOTPModuleTests.test_auth_with_mfa_recheck_settings
    - TOTPModuleTests.test_auth_with_valid_token_length
    - TOTPModuleTests.test_recheck_get_request
    - TOTPModuleTests.test_start_function_direct
    - TOTPModuleTests.test_verify_with_invalid_token_direct
    - TOTPModuleTests.test_verify_with_recovery_method_enforcement_direct
    - TOTPModuleTests.test_verify_with_valid_token_direct
    - TOTPViewTests.test_auth_with_invalid_token_failure
    - TOTPViewTests.test_auth_with_valid_token_success
    - TOTPViewTests.test_getToken
    - TOTPViewTests.test_recheck_failure
    - TOTPViewTests.test_recheck_get
    - TOTPViewTests.test_recheck_get_failure
    - TOTPViewTests.test_recheck_success
    - TOTPViewTests.test_start
    - TOTPViewTests.test_verify_token_with_valid_structure_but_unverified
    - TOTPViewTests.test_verify_with_invalid_token_failure
    - TOTPViewTests.test_verify_with_recovery_enforcement
    - TOTPViewTests.test_verify_with_valid_token_success

- `get_user_keys()` - Get User Keys (4 uses)
    - TOTPViewTests.test_auth_with_invalid_token_failure
    - TOTPViewTests.test_verify_with_invalid_token_failure
    - TOTPViewTests.test_verify_with_recovery_enforcement
    - TOTPViewTests.test_verify_with_valid_token_success

- `get_valid_totp_token()` - Get Valid Totp Token (4 uses)
    - TOTPViewTests.test_auth_with_valid_token_success
    - TOTPViewTests.test_recheck_get
    - TOTPViewTests.test_recheck_success
    - TOTPViewTests.test_verify_token_with_valid_structure_but_unverified

- `login_user()` - Login User (7 uses)
    - TOTPViewTests.test_auth_with_invalid_token_failure
    - TOTPViewTests.test_auth_with_valid_token_success
    - TOTPViewTests.test_recheck_get
    - TOTPViewTests.test_recheck_success
    - TOTPViewTests.test_start
    - TOTPViewTests.test_verify_with_recovery_enforcement
    - TOTPViewTests.test_verify_with_valid_token_success

- `setUp()` - Setup (2 uses)
    - TOTPModuleTests.setUp
    - TOTPViewTests.setUp

- `setup_mfa_session()` - Setup Mfa Session (5 uses)
    - TOTPViewTests.test_recheck_failure
    - TOTPViewTests.test_recheck_get
    - TOTPViewTests.test_recheck_get_failure
    - TOTPViewTests.test_recheck_success
    - TOTPViewTests.test_verify_token_with_valid_structure_but_unverified

- `setup_session_base_username()` - Setup Session Base Username (3 uses)
    - TOTPViewTests.setUp
    - TOTPViewTests.test_auth_with_invalid_token_failure
    - TOTPViewTests.test_auth_with_valid_token_success

- `tearDown()` - Teardown (1 uses)
    - TOTPModuleTests.tearDown

## test_trusteddevice

- `assertMfaKeyState()` - Assertmfakeystate (1 uses)
    - TrustedDeviceViewTests.test_verify_login_success

- `assertMfaSessionUnverified()` - Assertmfasessionunverified (3 uses)
    - TrustedDeviceViewTests.test_trusted_device_session_integration
    - TrustedDeviceViewTests.test_verify_handles_missing_user_keys
    - TrustedDeviceViewTests.test_verify_login_failure

- `assertMfaSessionVerified()` - Assertmfasessionverified (1 uses)
    - TrustedDeviceViewTests.test_trusted_device_session_integration

- `complete_trusted_device_registration()` - Complete Trusted Device Registration (2 uses)
    - TrustedDeviceViewTests.test_add_trusted_device_post
    - TrustedDeviceViewTests.test_trusted_device_verification_process

- `create_trusted_device_key()` - Create Trusted Device Key (16 uses)
    - TestTrustedDeviceModule.test_add_function_post_request_pc_device
    - TestTrustedDeviceModule.test_add_function_post_request_success
    - TestTrustedDeviceModule.test_checkTrusted_with_non_trusted_status
    - TestTrustedDeviceModule.test_checkTrusted_with_valid_id
    - TestTrustedDeviceModule.test_getCookie_with_trusted_device
    - TestTrustedDeviceModule.test_getUserAgent_with_device_id
    - TestTrustedDeviceModule.test_getUserAgent_with_empty_user_agent
    - TestTrustedDeviceModule.test_id_generator_with_existing_key
    - TestTrustedDeviceModule.test_start_function_with_existing_td_id
    - TestTrustedDeviceModule.test_start_function_with_max_devices
    - TestTrustedDeviceModule.test_trust_device_function
    - TestTrustedDeviceModule.test_verify_function_with_disabled_key
    - TestTrustedDeviceModule.test_verify_function_with_non_trusted_status
    - TestTrustedDeviceModule.test_verify_function_with_valid_cookie
    - TrustedDeviceViewTests.setUp
    - TrustedDeviceViewTests.test_verify_login_failure

- `get_mfa_url()` - Get Mfa Url (7 uses)
    - TestTrustedDeviceModule.test_add_function_get_request
    - TestTrustedDeviceModule.test_add_function_post_request_invalid_key
    - TestTrustedDeviceModule.test_add_function_post_request_pc_device
    - TestTrustedDeviceModule.test_add_function_post_request_success
    - TestTrustedDeviceModule.test_start_function_with_max_devices
    - TrustedDeviceViewTests.test_send_email_link_post
    - TrustedDeviceViewTests.test_start_trusted_device_get

- `get_trusted_device_key()` - Get Trusted Device Key (1 uses)
    - TrustedDeviceViewTests.test_add_trusted_device_post

- `get_user_keys()` - Get User Keys (1 uses)
    - TrustedDeviceViewTests.test_verify_handles_missing_user_keys

- `login_user()` - Login User (3 uses)
    - TrustedDeviceViewTests.test_send_email_link_post
    - TrustedDeviceViewTests.test_verify_handles_missing_user_keys
    - TrustedDeviceViewTests.test_verify_login_failure

- `setUp()` - Setup (1 uses)
    - TrustedDeviceViewTests.setUp

- `setup_mfa_session()` - Setup Mfa Session (1 uses)
    - TrustedDeviceViewTests.test_trusted_device_session_integration

- `setup_session_base_username()` - Setup Session Base Username (10 uses)
    - TestTrustedDeviceModule.test_verify_function_with_disabled_key
    - TestTrustedDeviceModule.test_verify_function_with_exception
    - TestTrustedDeviceModule.test_verify_function_with_invalid_username
    - TestTrustedDeviceModule.test_verify_function_with_non_trusted_status
    - TestTrustedDeviceModule.test_verify_function_with_valid_cookie
    - TestTrustedDeviceModule.test_verify_function_without_cookie
    - TrustedDeviceViewTests.setUp
    - TrustedDeviceViewTests.test_trusted_device_session_integration
    - TrustedDeviceViewTests.test_verify_handles_missing_user_keys
    - TrustedDeviceViewTests.test_verify_login_failure

- `setup_trusted_device_test()` - Setup Trusted Device Test (3 uses)
    - TrustedDeviceViewTests.test_add_trusted_device_post
    - TrustedDeviceViewTests.test_start_trusted_device_get
    - TrustedDeviceViewTests.test_trusted_device_verification_process

- `verify_trusted_device()` - Verify Trusted Device (1 uses)
    - TrustedDeviceViewTests.test_verify_login_success

## test_u2f

- `assertMfaSessionUnverified()` - Assertmfasessionunverified (1 uses)
    - MockChallenge.test_verify_failure_with_invalid_response

- `assertMfaSessionVerified()` - Assertmfasessionverified (1 uses)
    - MockChallenge.__init__

- `create_u2f_device_mock()` - Create U2F Device Mock (3 uses)
    - U2FRegistrationTests.test_bind_device_duplicate_prevention
    - U2FRegistrationTests.test_bind_device_success_with_valid_response
    - U2FRegistrationTests.test_registration_requires_recovery_when_enforced

- `create_u2f_enrollment_mock()` - Create U2F Enrollment Mock (5 uses)
    - U2FRegistrationTests.test_bind_device_duplicate_prevention
    - U2FRegistrationTests.test_bind_device_invalid_response_handling
    - U2FRegistrationTests.test_bind_device_success_with_valid_response
    - U2FRegistrationTests.test_registration_requires_recovery_when_enforced
    - U2FRegistrationTests.test_start_registration_initiates_enrollment

- `create_u2f_key()` - Create U2F Key (12 uses)
    - U2FAuthenticationTests.setUp
    - U2FModuleTests.test_auth_function
    - U2FModuleTests.test_auth_function_with_rename_methods
    - U2FModuleTests.test_bind_function_with_existing_certificate
    - U2FModuleTests.test_check_errors_error_code_1
    - U2FModuleTests.test_process_recheck_success
    - U2FModuleTests.test_recheck_function
    - U2FModuleTests.test_sign_function
    - U2FModuleTests.test_validate_success
    - U2FModuleTests.test_validate_with_recheck_settings
    - U2FModuleTests.test_verify_function_success
    - U2FRegistrationTests.test_bind_device_duplicate_prevention

- `create_u2f_response_data()` - Create U2F Response Data (3 uses)
    - U2FRegistrationTests.test_bind_device_duplicate_prevention
    - U2FRegistrationTests.test_bind_device_success_with_valid_response
    - U2FRegistrationTests.test_registration_requires_recovery_when_enforced

- `get_mfa_url()` - Get Mfa Url (8 uses)
    - MockChallenge.__init__
    - MockChallenge.test_verify_failure_with_invalid_response
    - U2FAuthenticationTests.test_auth_get_request_renders_template
    - U2FRegistrationTests.test_bind_device_duplicate_prevention
    - U2FRegistrationTests.test_bind_device_invalid_response_handling
    - U2FRegistrationTests.test_bind_device_success_with_valid_response
    - U2FRegistrationTests.test_registration_requires_recovery_when_enforced
    - U2FRegistrationTests.test_start_registration_initiates_enrollment

- `login_user()` - Login User (2 uses)
    - U2FAuthenticationTests.setUp
    - U2FRegistrationTests.setUp

- `setUp()` - Setup (2 uses)
    - U2FAuthenticationTests.setUp
    - U2FRegistrationTests.setUp

- `setup_session_base_username()` - Setup Session Base Username (6 uses)
    - U2FAuthenticationTests.setUp
    - U2FModuleTests.test_auth_function
    - U2FModuleTests.test_auth_function_with_rename_methods
    - U2FModuleTests.test_verify_function_failure
    - U2FModuleTests.test_verify_function_success
    - U2FRegistrationTests.setUp

## test_views

- `create_fido2_key()` - Create Fido2 Key (1 uses)
    - TestViewsModule.test_verify_function_always_go_to_last_method

- `create_totp_key()` - Create Totp Key (4 uses)
    - TestViewsModule.test_delkey_function_success
    - TestViewsModule.test_togglekey_function_hidden_method
    - TestViewsModule.test_togglekey_function_success
    - TestViewsModule.test_verify_function_always_go_to_last_method

- `create_trusted_device_key()` - Create Trusted Device Key (1 uses)
    - TestViewsModule.test_verify_function_trusted_device_success

- `verify_trusted_device()` - Verify Trusted Device (1 uses)
    - TestViewsModule.test_verify_function_trusted_device_success
