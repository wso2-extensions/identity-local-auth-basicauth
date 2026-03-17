/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier;

/**
 * Constants used by the SharedUserIdentifierHandler.
 */
public abstract class SharedUserIdentifierHandlerConstants {

    public static final String HANDLER_NAME = "SharedUserIdentifierExecutor";
    public static final String HANDLER_FRIENDLY_NAME = "Shared User Identifier First";
    public static final String USER_NAME = "username";
    public static final String FAILED_USERNAME = "&failedUsername=";
    public static final String ERROR_CODE = "&errorCode=";
    public static final String AUTHENTICATORS = "&authenticators=";
    public static final String LOCAL = "LOCAL";
    public static final String UTF_8 = "UTF-8";
    public static final String IS_USER_RESOLVED = "isUserResolved";
    public static final String USERNAME_USER_INPUT = "usernameUserInput";

    private SharedUserIdentifierHandlerConstants() {
    }

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String SHARED_USER_IDENTIFIER_AUTH_SERVICE = "local-auth-shared-user-identifier-first";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String PROCESS_AUTHENTICATION_RESPONSE =
                    "process-shared-user-identifier-authentication-response";
            public static final String INITIATE_SHARED_USER_IDENTIFIER_AUTH_REQUEST =
                    "initiate-shared-user-identifier-authentication-request";
            public static final String AUTHENTICATOR_SHARED_USER_IDENTIFIER =
                    "authenticator.shared-user-identifier";
        }
    }

    /**
     * Error messages used by the SharedUserIdentifierHandler.
     */
    public enum ErrorMessages {

        SYSTEM_ERROR_WHILE_AUTHENTICATING("SHUID-65001", "System error while authenticating."),
        CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT("SHUID-65012",
                "Cannot find the user realm for the given tenant: %s"),
        USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE("SHUID-65021",
                "UserStoreException while trying to authenticate."),
        USER_SHARING_SERVICE_EXCEPTION("SHUID-65023",
                "Error while checking shared user status."),
        USER_NOT_A_SHARED_USER("SHUID-17003", "User is not a shared user in this tenant."),
        USER_DOES_NOT_EXIST("SHUID-17001", "User does not exist."),
        EMPTY_USERNAME("SHUID-60002", "Username is empty."),
        INVALID_TENANT_ID_OF_THE_USER("SHUID-65011",
                "Failed while trying to get the tenant ID of the user %s"),
        ORGANIZATION_MGT_EXCEPTION("SHUID-65022",
                "Organization management exception while resolving shared user.");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {
            this.code = code;
            this.message = message;
        }

        public String getCode() {
            return code;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString() {
            return code + " - " + message;
        }
    }
}

