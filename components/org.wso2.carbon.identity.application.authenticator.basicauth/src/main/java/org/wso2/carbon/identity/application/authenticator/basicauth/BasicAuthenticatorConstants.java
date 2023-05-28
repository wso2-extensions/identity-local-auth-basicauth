/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.basicauth;

/**
 * Constants used by the BasicAuthenticator
 */
public abstract class BasicAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "BasicAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "Username & Password";
    public static final String USER_NAME = "username";
    public static final String PASSWORD = "password";
    public static final String FAILED_USERNAME = "&failedUsername=";
    public static final String ERROR_CODE = "&errorCode=";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";
    public static final String UTF_8 = "UTF-8";
    public static final String USER_NAME_PARAM = "username=";
    public static final String TENANT_DOMAIN_PARAM = "&tenantdomain=";
    public static final String CONFIRMATION_PARAM = "&confirmation=";
    public static final String REMAINING_ATTEMPTS = "&remainingAttempts=";
    public static final String LOCKED_REASON = "&lockedReason=";
    public static final String CONF_SHOW_AUTH_FAILURE_REASON = "showAuthFailureReason";
    public static final String CONF_SHOW_AUTH_FAILURE_REASON_ON_LOGIN_PAGE = "showAuthFailureReasonOnLoginPage";
    public static final String CONF_MASK_USER_NOT_EXISTS_ERROR_CODE = "maskUserNotExistsErrorCode";
    public static final String CONF_MASK_ADMIN_FORCED_PASSWORD_RESET_ERROR_CODE =
            "maskAdminForcedPasswordResetErrorCode";
    public static final String CONF_ERROR_PARAMS_TO_OMIT = "errorParamsToOmit";
    public static final String AUTH_FAILURE_PARAM = "&authFailure=";
    public static final String AUTH_FAILURE_MSG_PARAM = "&authFailureMsg=";
    public static final String RECAPTCHA_PARAM = "&reCaptcha=";
    public static final String RECAPTCHA_TYPE_PARAM = "&reCaptchaType=";
    public static final String RECAPTCHA_RESEND_CONFIRMATION_PARAM = "&reCaptchaResend=";
    public static final String RECAPTCHA_KEY_PARAM = "&reCaptchaKey=";
    public static final String RECAPTCHA_API_PARAM = "&reCaptchaAPI=";
    public static final String CALLBACK_PARAM = "&callback=";
    public static final String REASON_PARAM = "&reason=";

    public static final String AUTHENTICATION_POLICY_CONFIG = "AuthenticationPolicy.CheckAccountExist";

    public static final String RESOURCE_TYPE_NAME_CONFIG = "basic-authenticator-config";
    public static final String RESOURCE_NAME_CONFIG = "user-information";
    public static final String PENDING_USER_INFORMATION_ATTRIBUTE_NAME_CONFIG = "ShowPendingUserInformation.enable";
    public static final String SHOW_PENDING_USER_INFORMATION_CONFIG = "ShowPendingUserInformation";
    public static final String IS_INVALID_USERNAME = "isInvalidUsername";
    public static final String USERNAME_USER_INPUT = "usernameUserInput";
    public static final boolean SHOW_PENDING_USER_INFORMATION_DEFAULT_VALUE = true;

    private BasicAuthenticatorConstants() {
    }
}
