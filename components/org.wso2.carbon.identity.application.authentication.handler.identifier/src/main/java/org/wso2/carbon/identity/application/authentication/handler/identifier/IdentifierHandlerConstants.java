/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.application.authentication.handler.identifier;

import org.apache.commons.lang.StringUtils;

/**
 * Constants used by the IdentifierHandler
 */
public abstract class IdentifierHandlerConstants {

    public static final String HANDLER_NAME = "IdentifierExecutor";
    public static final String HANDLER_FRIENDLY_NAME = "Identifier First";
    public static final String USER_NAME = "username";
    public static final String FAILED_USERNAME = "&failedUsername=";
    public static final String ERROR_CODE = "&errorCode=";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";
    public static final String UTF_8 = "UTF-8";
    public static final String IS_INVALID_USERNAME = "isInvalidUsername";
    public static final String USERNAME_USER_INPUT = "usernameUserInput";
    public static final String IS_USER_RESOLVED = "isUserResolved";

    public static final String ACCOUNT_DISABLED = "The account is disabled.";
    public static final String ACCOUNT_DISABLED_I18N_KEY = "{{account.disabled}}";
    public static final String USER_NOT_FOUND = "The user does not exist.";
    public static final String USER_NOT_FOUND_I18N_KEY = "{{user.not.found}}";

    private IdentifierHandlerConstants() {
    }

    /**
     * Known account lock reasons with their associated i18n key and error message.
     */
    public enum AccountLockedReason {

        DEFAULT("{{account.locked}}",
                "The account is locked."),
        MAX_ATTEMPTS_EXCEEDED("{{account.locked.max.attempts}}",
                "The account is locked due to maximum failed login attempts."),
        IDLE_ACCOUNT("{{account.locked.idle}}",
                "The account is locked due to inactivity."),
        PENDING_SELF_REGISTRATION("{{account.locked.pending.self.registration}}",
                "The account is pending self-registration."),
        PENDING_EMAIL_VERIFICATION("{{account.locked.pending.email.verification}}",
                "The account is pending email verification."),
        PENDING_ASK_PASSWORD("{{account.locked.pending.ask.password}}",
                "The account is pending password setup."),
        PENDING_ADMIN_FORCED_USER_PASSWORD_RESET("{{account.locked.pending.admin.forced.password.reset}}",
                "The account is pending admin-forced password reset."),
        ADMIN_INITIATED("{{account.locked.admin.initiated}}",
                "The account has been locked by an administrator.");

        private final String i18nKey;
        private final String message;

        AccountLockedReason(String i18nKey, String message) {

            this.i18nKey = i18nKey;
            this.message = message;
        }

        public String getI18nKey() {

            return i18nKey;
        }

        public String getMessage() {

            return message;
        }

        /**
         * Returns the AccountLockedReason for the given reason string,
         * or DEFAULT if the reason is null, blank, or unrecognized.
         *
         * @param reason Account locked reason string stored in the user's identity claims.
         * @return Matching AccountLockedReason, or DEFAULT.
         */
        public static AccountLockedReason fromReason(String reason) {

            if (reason == null || StringUtils.isBlank(reason)) {
                return DEFAULT;
            }
            for (AccountLockedReason r : values()) {
                if (r.name().equals(reason)) {
                    return r;
                }
            }
            return DEFAULT;
        }
    }

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String IDENTIFIER_AUTH_SERVICE = "local-auth-identifier-first";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-identifier-authentication-response";
            public static final String INITIATE_IDENTIFIER_AUTH_REQUEST = "initiate-identifier-authentication-request";
            public static final String AUTHENTICATOR_IDENTIFIER = "authenticator.identifier";
        }
    }
}
