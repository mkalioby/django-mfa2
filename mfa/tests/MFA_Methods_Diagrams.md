# MFA Methods - Flow Diagrams

**Note**: These diagrams show Django view functions that are called via AJAX from JavaScript on the frontend. The "API" references are actually Django view functions that return `JsonResponse` or `HttpResponse` objects, not separate REST API services.

## 1. Email MFA (Email.py)

```mermaid
flowchart TD
    EM_A["Email MFA Start"] --> EM_B{"Request Method?"}

    EM_B -->|GET| EM_C["Generate 6-digit OTP"]
    EM_C --> EM_D["Store in session['email_secret']"]
    EM_D --> EM_E["Call sendEmail function"]
    EM_E --> EM_F{"Email sent successfully?"}
    EM_F -->|Yes| EM_G["Set context['sent'] = True"]
    EM_F -->|No| EM_H["Continue without sent flag"]
    EM_G --> EM_I["Render Email/Add.html"]
    EM_H --> EM_I

    EM_B -->|POST| EM_J["Get OTP from POST data"]
    EM_J --> EM_K{"OTP matches session?"}
    EM_K -->|No| EM_L["Set context['invalid'] = True"]
    EM_K -->|Yes| EM_M["Create User_Keys object"]
    EM_M --> EM_N["Set username = USERNAME_FIELD (field name)"]
    EM_N --> EM_O["Set key_type = 'Email'"]
    EM_O --> EM_P["Set enabled = 1"]
    EM_P --> EM_Q["Save to database"]
    EM_Q --> EM_R{"Recovery method required?"}
    EM_R -->|Yes| EM_S["Set session['mfa_reg']"]
    EM_R -->|No| EM_T["Redirect to MFA_REDIRECT_AFTER_REGISTRATION"]
    EM_L --> EM_I
    EM_S --> EM_I
    EM_T --> EM_U["End"]
```

```mermaid
flowchart TD
    EM_V["Email MFA Auth"] --> EM_W{"Request Method?"}
    EM_W -->|GET| EM_X["Generate 6-digit OTP"]
    EM_X --> EM_Y["Store in session['email_secret']"]
    EM_Y --> EM_Z["Call sendEmail with base_username"]
    EM_Z --> EM_AA{"Email sent successfully?"}
    EM_AA -->|Yes| EM_BB["Set context['sent'] = True"]
    EM_AA -->|No| EM_CC["Continue without sent flag"]
    EM_BB --> EM_DD["Render Email/Auth.html"]
    EM_CC --> EM_DD

    EM_W -->|POST| EM_EE["Get username from session"]
    EM_EE --> EM_FF["Get OTP from POST data"]
    EM_FF --> EM_GG{"OTP matches session?"}
    EM_GG -->|No| EM_HH["Set context['invalid'] = True"]
    EM_GG -->|Yes| EM_II["Query existing Email keys"]
    EM_II --> EM_JJ{"Keys exist?"}
    EM_JJ -->|Yes| EM_KK["Use first existing key"]
    EM_JJ -->|No| EM_LL{"MFA_ENFORCE_EMAIL_TOKEN?"}
    EM_LL -->|Yes| EM_MM["Create new User_Keys"]
    EM_LL -->|No| EM_NN["RAISE Exception: Email not valid method"]
    EM_MM --> EM_OO["Set MFA session data"]
    EM_KK --> EM_OO
    EM_OO --> EM_PP["Update last_used timestamp"]
    EM_PP --> EM_QQ["Call login function"]
    EM_HH --> EM_DD
    EM_NN --> EM_RR["Exception Handler"]
```

```mermaid
flowchart TD

    EM_SS["sendEmail Function"] --> EM_TT["Get User model and username field"]
    EM_TT --> EM_UU["Create kwargs for user lookup"]
    EM_UU --> EM_VV["user = User.objects.get(**kwargs)"]
    EM_VV --> EM_WW["Render email template with OTP"]
    EM_WW --> EM_XX["Get email subject from settings"]
    EM_XX --> EM_YY{"MFA_SHOW_OTP_IN_EMAIL_SUBJECT?"}
    EM_YY -->|Yes| EM_ZZ["Replace %s in subject with OTP"]
    EM_YY -->|No| EM_AAA["Use subject as-is"]
    EM_ZZ --> EM_BBB["Send email via send function"]
    EM_AAA --> EM_BBB
    EM_BBB --> EM_CCC["Return send result"]
```
<br>
<br>
<br>

## 2. TOTP MFA (totp.py)

```mermaid
flowchart TD
    TOTP_A["TOTP MFA Start"] --> TOTP_B["Render TOTP/Add.html"]
    TOTP_B --> TOTP_C["JavaScript calls getToken() view"]
    TOTP_C --> TOTP_D["Generate random secret key"]
    TOTP_D --> TOTP_E["Create TOTP object"]
    TOTP_E --> TOTP_F["Generate provisioning URI"]
    TOTP_F --> TOTP_G["Return JsonResponse with QR and secret"]
    TOTP_G --> TOTP_H["Display QR code to user"]

    TOTP_H --> TOTP_I["User enters OTP"]
    TOTP_I --> TOTP_J["JavaScript calls verify() view"]
    TOTP_J --> TOTP_K["Get answer and key from GET"]
    TOTP_K --> TOTP_L["Create TOTP object with key"]
    TOTP_L --> TOTP_M["Verify answer with 60s window"]
    TOTP_M --> TOTP_N{"Verification valid?"}
    TOTP_N -->|No| TOTP_O["Return JsonResponse: 'Error'"]
    TOTP_N -->|Yes| TOTP_P["Create User_Keys object"]
    TOTP_P --> TOTP_Q["Set username = request.user.username"]
    TOTP_Q --> TOTP_R["Set key_type = 'TOTP'"]
    TOTP_R --> TOTP_S["Set properties with secret key"]
    TOTP_S --> TOTP_T["Set enabled = 1"]
    TOTP_T --> TOTP_U["Save to database"]
    TOTP_U --> TOTP_V{"Recovery method required?"}
    TOTP_V -->|Yes| TOTP_W["Return JsonResponse: 'RECOVERY'"]
    TOTP_V -->|No| TOTP_X["Return JsonResponse: 'Success'"]
    TOTP_O --> TOTP_Y["Show error to user"]
    TOTP_W --> TOTP_Z["Redirect to recovery setup"]
    TOTP_X --> TOTP_AA["Redirect to MFA_REDIRECT_AFTER_REGISTRATION"]
```

```mermaid
flowchart TD

    TOTP_V["TOTP MFA Auth"] --> TOTP_W{"Request Method?"}
    TOTP_W -->|GET| TOTP_X["Render TOTP/Auth.html"]
    TOTP_W -->|POST| TOTP_Y["Get OTP from POST data"]
    TOTP_Y --> TOTP_Z["Call verify_login function"]
    TOTP_Z --> TOTP_AA["Query TOTP keys for username"]
    TOTP_AA --> TOTP_BB["For each key: verify OTP"]
    TOTP_BB --> TOTP_CC{"Any key valid?"}
    TOTP_CC -->|No| TOTP_DD["Set context['invalid'] = True"]
    TOTP_CC -->|Yes| TOTP_EE["Update last_used timestamp"]
    TOTP_EE --> TOTP_FF["Set MFA session data"]
    TOTP_FF --> TOTP_GG["Call login function"]
    TOTP_DD --> TOTP_HH["Render TOTP/Auth.html"]
```

```mermaid
flowchart TD

    TOTP_II["TOTP Recheck"] --> TOTP_JJ{"Request Method?"}
    TOTP_JJ -->|GET| TOTP_KK["Render TOTP/recheck.html"]
    TOTP_JJ -->|POST| TOTP_LL["Call verify_login function"]
    TOTP_LL --> TOTP_MM{"OTP valid?"}
    TOTP_MM -->|Yes| TOTP_NN["Update recheck timestamp"]
    TOTP_NN --> TOTP_OO["Return JsonResponse recheck: true"]
    TOTP_MM -->|No| TOTP_PP["Return JsonResponse recheck: false"]
```
<br>
<br>
<br>

## 3. FIDO2 MFA (FIDO2.py)

```mermaid
flowchart TD
    F2_A["FIDO2 MFA Start"] --> F2_B["Render FIDO2/Add.html"]
    F2_B --> F2_C["JavaScript calls begin_registeration() view"]
    F2_C --> F2_D["Get FIDO2 server configuration"]
    F2_D --> F2_E["Create registration options"]
    F2_E --> F2_F["Store state in session"]
    F2_F --> F2_G["Return JsonResponse with registration data"]

    F2_G --> F2_H["JavaScript calls complete_reg() view"]
    F2_H --> F2_I{"Session state exists?"}
    F2_I -->|No| F2_J["Return JsonResponse: error='Status not found'"]
    F2_I -->|Yes| F2_K{"Request body valid?"}
    F2_K -->|No| F2_L["Return JsonResponse: error='Invalid JSON'"]
    F2_K -->|Yes| F2_M["Parse registration response"]
    F2_M --> F2_N["Verify registration with server"]
    F2_N --> F2_O{"Registration valid?"}
    F2_O -->|No| F2_P["Return JsonResponse: error='Server error'"]
    F2_O -->|Yes| F2_Q["Create User_Keys object"]
    F2_Q --> F2_R["Set username = request.user.username"]
    F2_R --> F2_S["Set key_type = 'FIDO2'"]
    F2_S --> F2_T["Set properties with credential data"]
    F2_T --> F2_U["Set enabled = 1"]
    F2_U --> F2_V["Save to database"]
    F2_V --> F2_W{"Recovery method required?"}
    F2_W -->|Yes| F2_X["Return JsonResponse: status='RECOVERY'"]
    F2_W -->|No| F2_Y["Return JsonResponse: status='OK'"]
```

```mermaid
flowchart TD
    F2_Z["FIDO2 MFA Auth"] --> F2_AA["Render FIDO2/Auth.html"]
    F2_AA --> F2_BB["JavaScript calls authenticate_begin() view"]
    F2_BB --> F2_CC["Get FIDO2 server configuration"]
    F2_CC --> F2_DD["Get user credentials"]
    F2_DD --> F2_EE["Create authentication options"]
    F2_EE --> F2_FF["Store state in session"]
    F2_FF --> F2_GG["Return JsonResponse with authentication data"]

    F2_GG --> F2_HH["JavaScript calls authenticate_complete() view"]
    F2_HH --> F2_II{"Request body valid?"}
    F2_II -->|No| F2_JJ["Return JsonResponse: error='Invalid JSON'"]
    F2_II -->|Yes| F2_KK["Parse authentication response"]
    F2_KK --> F2_LL["Get user handle from response"]
    F2_LL --> F2_MM["Query credentials by user handle"]
    F2_MM --> F2_NN["Verify authentication with server"]
    F2_NN --> F2_OO{"Authentication valid?"}
    F2_OO -->|No| F2_PP["Return JsonResponse: error='Wrong challenge'"]
    F2_OO -->|Yes| F2_QQ{"Recheck mode?"}
    F2_QQ -->|Yes| F2_RR["Update recheck timestamp"]
    F2_RR --> F2_SS["Return JsonResponse: status='OK'"]
    F2_QQ -->|No| F2_TT["Find matching key"]
    F2_TT --> F2_UU["Update last_used timestamp"]
    F2_UU --> F2_VV["Set MFA session data"]
    F2_VV --> F2_WW{"User authenticated?"}
    F2_WW -->|Yes| F2_XX["Return JsonResponse: status='OK'"]
    F2_WW -->|No| F2_YY["Call login function"]
    F2_YY --> F2_ZZ["Return JsonResponse with redirect"]
```

```mermaid
flowchart TD
    F2_AAA["FIDO2 Recheck"] --> F2_BBB["Set mfa_recheck = True"]
    F2_BBB --> F2_CCC["Render FIDO2/recheck.html"]
```
<br>
<br>
<br>

## 4. U2F MFA (U2F.py)

```mermaid
flowchart TD
    U2F_A["U2F MFA Start"] --> U2F_B["Call begin_registration"]
    U2F_B --> U2F_C["Store enrollment data in session"]
    U2F_C --> U2F_D["Render U2F/Add.html with token"]

    U2F_D --> U2F_E["JavaScript calls bind() view"]
    U2F_E --> U2F_F["Get enrollment from session"]
    U2F_F --> U2F_G["Parse registration response"]
    U2F_G --> U2F_H["Complete registration"]
    U2F_H --> U2F_I["Parse certificate"]
    U2F_I --> U2F_J["Check for duplicate certificate"]
    U2F_J --> U2F_K{"Certificate exists?"}
    U2F_K -->|Yes| U2F_L["Return HttpResponse: error='Key already registered'"]
    U2F_K -->|No| U2F_M["Delete old U2F keys"]
    U2F_M --> U2F_N["Create User_Keys object"]
    U2F_N --> U2F_O["Set username = request.user.username"]
    U2F_O --> U2F_P["Set key_type = 'U2F'"]
    U2F_P --> U2F_Q["Set properties with device and cert"]
    U2F_Q --> U2F_R["Save to database"]
    U2F_R --> U2F_S{"Recovery method required?"}
    U2F_S -->|Yes| U2F_T["Return HttpResponse: 'RECOVERY'"]
    U2F_S -->|No| U2F_U["Return HttpResponse: 'OK'"]
```

```mermaid
flowchart TD
    U2F_V["U2F MFA Auth"] --> U2F_W["Call sign function"]
    U2F_W --> U2F_X["Get U2F devices for username"]
    U2F_X --> U2F_Y["Begin authentication"]
    U2F_Y --> U2F_Z["Store challenge in session"]
    U2F_Z --> U2F_AA["Render U2F/Auth.html with token"]

    U2F_AA --> U2F_BB["JavaScript calls verify() view"]
    U2F_BB --> U2F_CC["Call validate function"]
    U2F_CC --> U2F_DD["Parse response data"]
    U2F_DD --> U2F_EE["Check for errors"]
    U2F_EE --> U2F_FF{"Error code 0?"}
    U2F_FF -->|No| U2F_GG["Handle specific errors"]
    U2F_FF -->|Yes| U2F_HH["Complete authentication"]
    U2F_HH --> U2F_II["Find matching key by public key"]
    U2F_II --> U2F_JJ{"Key found?"}
    U2F_JJ -->|No| U2F_KK["Return HttpResponse: False"]
    U2F_JJ -->|Yes| U2F_LL["Update last_used timestamp"]
    U2F_LL --> U2F_MM["Set MFA session data"]
    U2F_MM --> U2F_NN["Call login function"]
```

```mermaid
flowchart TD
    U2F_OO["U2F Recheck"] --> U2F_PP["Call sign function"]
    U2F_PP --> U2F_QQ["Store challenge in session"]
    U2F_QQ --> U2F_RR["Set mfa_recheck = True"]
    U2F_RR --> U2F_SS["Render U2F/recheck.html"]

    U2F_TT["U2F Process Recheck"] --> U2F_UU["Call validate function"]
    U2F_UU --> U2F_VV{"Validation successful?"}
    U2F_VV -->|Yes| U2F_WW["Update recheck timestamp"]
    U2F_WW --> U2F_XX["Return JsonResponse recheck: true"]
    U2F_VV -->|No| U2F_YY["Return error response"]
```
<br>
<br>
<br>

## 5. Recovery Codes MFA (recovery.py)

```mermaid
flowchart TD
    RC_A["Recovery MFA Start"] --> RC_B["Render RECOVERY/Add.html"]
    RC_B --> RC_C["JavaScript calls genTokens() view"]
    RC_C --> RC_D["Call delTokens function"]
    RC_D --> RC_E["Delete old recovery codes"]
    RC_E --> RC_F["Generate 5 new recovery codes"]
    RC_F --> RC_G["Hash codes with PBKDF2"]
    RC_G --> RC_H["Store hashed codes in User_Keys"]
    RC_H --> RC_I["Return JsonResponse with clear codes"]
```

```mermaid
flowchart TD
    RC_J["Recovery MFA Auth"] --> RC_K{"Request Method?"}
    RC_K -->|GET| RC_L["Check for last backup flag"]
    RC_L --> RC_M{"Last backup used?"}
    RC_M -->|Yes| RC_N["Call login function"]
    RC_M -->|No| RC_O["Render RECOVERY/Auth.html"]
    
    RC_K -->|POST| RC_P["Get recovery code from POST"]
    RC_P --> RC_Q{"Code length = 11?"}
    RC_Q -->|No| RC_R["Set context['invalid'] = True"]
    RC_Q -->|Yes| RC_S["Call verify_login function"]
    RC_S --> RC_T["Query RECOVERY keys for username"]
    RC_T --> RC_U["For each key: verify code"]
    RC_U --> RC_V{"Any code valid?"}
    RC_V -->|No| RC_W["Set context['invalid'] = True"]
    RC_V -->|Yes| RC_X["Mark code as used"]
    RC_X --> RC_Y["Update last_used timestamp"]
    RC_Y --> RC_Z["Set MFA session data"]
    RC_Z --> RC_AA{"Last backup code?"}
    RC_AA -->|Yes| RC_BB["Set lastBackup flag"]
    RC_BB --> RC_CC["Render RECOVERY/Auth.html"]
    RC_AA -->|No| RC_DD["Call login function"]
    RC_R --> RC_EE["Render RECOVERY/Auth.html"]
    RC_W --> RC_EE
```

```mermaid
flowchart TD
    RC_FF["Recovery Recheck"] --> RC_GG{"Request Method?"}
    RC_GG -->|GET| RC_HH["Render RECOVERY/recheck.html"]
    RC_GG -->|POST| RC_II["Call verify_login function"]
    RC_II --> RC_JJ{"Code valid?"}
    RC_JJ -->|Yes| RC_KK["Update recheck timestamp"]
    RC_KK --> RC_LL["Return JsonResponse recheck: true"]
    RC_JJ -->|No| RC_MM["Return JsonResponse recheck: false"]

    RC_NN["getTokenLeft() view"] --> RC_OO["Query RECOVERY keys for user"]
    RC_OO --> RC_PP["Count remaining codes"]
    RC_PP --> RC_QQ["Return JsonResponse with count"]
```
<br>
<br>
<br>

## 6. Trusted Device MFA (TrustedDevice.py)

```mermaid
flowchart TD
    TD_A["Trusted Device MFA Start"] --> TD_B{"Device count >= 2?"}
    TD_B -->|Yes| TD_C["Render start.html with not_allowed"]
    TD_B -->|No| TD_D{"Session has td_id?"}
    TD_D -->|No| TD_E["Create User_Keys object"]
    TD_E --> TD_F["Generate unique device key"]
    TD_F --> TD_G["Set status = 'adding'"]
    TD_G --> TD_H["Set key_type = 'Trusted Device'"]
    TD_H --> TD_I["Save to database"]
    TD_I --> TD_J["Store td_id in session"]
    TD_D -->|Yes| TD_K["Get device from database"]
    TD_K --> TD_L["Render start.html with key and URL"]
```

```mermaid
flowchart TD
    TD_M["Trusted Device Add"] --> TD_N{"Request Method?"}
    TD_N -->|GET| TD_O["Get username and key from GET"]
    TD_O --> TD_P["Render TrustedDevices/Add.html"]
    
    TD_N -->|POST| TD_Q["Get key and username from POST"]
    TD_Q --> TD_R["Clean and normalize key"]
    TD_R --> TD_S["Query trusted keys by key"]
    TD_S --> TD_T{"Key exists?"}
    TD_T -->|No| TD_U["Set context['invalid'] = True"]
    TD_T -->|Yes| TD_V["Store td_id in session"]
    TD_V --> TD_W["Parse user agent"]
    TD_W --> TD_X{"Is PC?"}
    TD_X -->|Yes| TD_Y["Set invalid: PC not allowed"]
    TD_X -->|No| TD_Z["Store user agent"]
    TD_Z --> TD_AA["Set context['success'] = True"]
    TD_U --> TD_BB["Render TrustedDevices/Add.html"]
    TD_Y --> TD_BB
    TD_AA --> TD_BB
```

```mermaid
flowchart TD
    TD_CC["Trust Device"] --> TD_DD["Get device from session"]
    TD_DD --> TD_EE["Set status = 'trusted'"]
    TD_EE --> TD_FF["Save device"]
    TD_FF --> TD_GG["Clear session td_id"]
    TD_GG --> TD_HH["Return OK response"]

    TD_II["Get Cookie"] --> TD_JJ["Get device from session"]
    TD_JJ --> TD_KK{"Device status trusted?"}
    TD_KK -->|Yes| TD_LL["Set cookie expiration"]
    TD_LL --> TD_MM["Set deviceid cookie"]
    TD_MM --> TD_NN["Render Done.html"]
    TD_KK -->|No| TD_OO["Return error"]

    TD_PP["Check Trusted"] --> TD_QQ["Get td_id from session"]
    TD_QQ --> TD_RR{"td_id exists?"}
    TD_RR -->|No| TD_SS["Return empty response"]
    TD_RR -->|Yes| TD_TT["Get device from database"]
    TD_TT --> TD_UU{"Device status trusted?"}
    TD_UU -->|Yes| TD_VV["Return OK response"]
    TD_UU -->|No| TD_WW["Return empty response"]
```

```mermaid
flowchart TD
    TD_XX["Trusted Device Verify"] --> TD_YY{"Cookie exists?"}
    TD_YY -->|No| TD_ZZ["Return False"]
    TD_YY -->|Yes| TD_AAA["Decode JWT token"]
    TD_AAA --> TD_BBB{"Username matches?"}
    TD_BBB -->|No| TD_CCC["Return False"]
    TD_BBB -->|Yes| TD_DDD["Query device by key"]
    TD_DDD --> TD_EEE{"Device found and enabled?"}
    TD_EEE -->|No| TD_FFF["Return False"]
    TD_EEE -->|Yes| TD_GGG{"Status trusted?"}
    TD_GGG -->|No| TD_HHH["Return False"]
    TD_GGG -->|Yes| TD_III["Update last_used timestamp"]
    TD_III --> TD_JJJ["Set MFA session data"]
    TD_JJJ --> TD_KKK["Return True"]

    TD_LLL["Send Email"] --> TD_MMM["Render email template"]
    TD_MMM --> TD_NNN["Get user email"]
    TD_NNN --> TD_OOO{"Email exists?"}
    TD_OOO -->|No| TD_PPP["Return error message"]
    TD_OOO -->|Yes| TD_QQQ["Send email via send function"]
    TD_QQQ --> TD_RRR{"Email sent?"}
    TD_RRR -->|Yes| TD_SSS["Return success message"]
    TD_RRR -->|No| TD_TTT["Return error message"]
```
<br>
<br>
<br>

## 7. Overall MFA Flow (views.py)

```mermaid
flowchart TD
    MFA_A["User Login"] --> MFA_B["Call verify function"]
    MFA_B --> MFA_C["Set base_username in session"]
    MFA_C --> MFA_D["Query enabled keys for user"]
    MFA_D --> MFA_E["Get available methods"]
    MFA_E --> MFA_F{"Trusted Device in methods?"}
    MFA_F -->|Yes| MFA_G["Check trusted device"]
    MFA_G --> MFA_H{"Device trusted?"}
    MFA_H -->|Yes| MFA_I["Call login function"]
    MFA_H -->|No| MFA_J["Remove from methods"]
    MFA_F -->|No| MFA_K["Continue to method selection"]
    MFA_J --> MFA_K
    MFA_K --> MFA_L{"Methods available?"}
    MFA_L -->|No| MFA_M{"Email enforcement enabled?"}
    MFA_M -->|Yes| MFA_N["Set methods = ['email']"]
    MFA_M -->|No| MFA_O["Show error - no methods"]
    MFA_N --> MFA_P["Continue to method selection"]
    MFA_L -->|Yes| MFA_P
    MFA_P --> MFA_Q{"Only one method?"}
    MFA_Q -->|Yes| MFA_R["Redirect to method auth"]
    MFA_Q -->|No| MFA_S{"Always go to last method?"}
    MFA_S -->|Yes| MFA_T["Get most recently used method"]
    MFA_T --> MFA_U["Redirect to that method"]
    MFA_S -->|No| MFA_V["Call show_methods function"]
```

```mermaid
flowchart TD
    MFA_W["show_methods Function"] --> MFA_X["Render select_mfa_method.html"]
    MFA_X --> MFA_Y["Display available methods with rename"]
    MFA_Y --> MFA_Z["User selects method"]
    MFA_Z --> MFA_AA["Call goto function"]
    MFA_AA --> MFA_BB["Redirect to selected method auth"]

    MFA_CC["Method Authentication"] --> MFA_DD{"Method type?"}
    MFA_DD -->|TOTP| MFA_EE["Call TOTP auth"]
    MFA_DD -->|Email| MFA_FF["Call Email auth"]
    MFA_DD -->|FIDO2| MFA_GG["Call FIDO2 auth"]
    MFA_DD -->|U2F| MFA_HH["Call U2F auth"]
    MFA_DD -->|Recovery| MFA_II["Call Recovery auth"]
    MFA_DD -->|Trusted Device| MFA_JJ["Call Trusted Device auth"]

    MFA_EE --> MFA_KK["Verify authentication"]
    MFA_FF --> MFA_KK
    MFA_GG --> MFA_KK
    MFA_HH --> MFA_KK
    MFA_II --> MFA_KK
    MFA_JJ --> MFA_KK

    MFA_KK --> MFA_LL{"Authentication successful?"}
    MFA_LL -->|Yes| MFA_MM["Set MFA session data"]
    MFA_MM --> MFA_NN["Call login function"]
    MFA_LL -->|No| MFA_OO["Show error message"]
    MFA_OO --> MFA_PP["Return to method auth page"]
```

```mermaid
flowchart TD
    MFA_QQ["Login Function"] --> MFA_RR["Get MFA_LOGIN_CALLBACK setting"]
    MFA_RR --> MFA_SS["Call __get_callable_function__"]
    MFA_SS --> MFA_TT["Import callback module"]
    MFA_TT --> MFA_UU["Get callback function"]
    MFA_UU --> MFA_VV["Call callback with request and username"]
    MFA_VV --> MFA_WW["Return callback response"]

    MFA_XX["Key Management"] --> MFA_YY{"Action?"}
    MFA_YY -->|Delete| MFA_ZZ["Call delKey function"]
    MFA_YY -->|Toggle| MFA_AAA["Call toggleKey function"]
    MFA_ZZ --> MFA_BBB["Verify key ownership"]
    MFA_BBB --> MFA_CCC["Delete key"]
    MFA_CCC --> MFA_DDD["Return success message"]
    MFA_AAA --> MFA_EEE["Verify key ownership"]
    MFA_EEE --> MFA_FFF{"Key in HIDE_DISABLE?"}
    MFA_FFF -->|Yes| MFA_GGG["Return error: Can't change method"]
    MFA_FFF -->|No| MFA_HHH["Toggle enabled status"]
    MFA_HHH --> MFA_III["Return OK"]

    MFA_JJJ["reset_cookie Function"] --> MFA_KKK["Create redirect to LOGIN_URL"]
    MFA_KKK --> MFA_LLL["Delete base_username cookie"]
    MFA_LLL --> MFA_MMM["Return redirect response"]
```
