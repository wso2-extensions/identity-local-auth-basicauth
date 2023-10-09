/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.basicauth.util;

public class BasicAuthErrorConstants {

    /**
     * Relevant error messages and error codes.
     * This error codes are commented as a group not because of the convention
     * because to maintain the togetherness of the errors.
     */
    public enum ErrorMessages {

        // Credential related Exceptions
        CREDENTIAL_MISMATCH("BAS-60001", "Credential mismatch."),
        EMPTY_USERNAME("BAS-60002", "Username is empty."),
        EMPTY_PASSWORD("BAS-60003", "Password is empty."),

        // IO related Error codes
        SYSTEM_ERROR_WHILE_AUTHENTICATING("BAS-65001", "System error while authenticating"),
        // Tenant related Error codes
        INVALID_TENANT_ID_OF_THE_USER("BAS-65011",
                "Failed while trying to get the tenant ID of the user %s"),
        CANNOT_FIND_THE_USER_REALM_FOR_THE_GIVEN_TENANT("BAS-65012",
                "Cannot find the user realm for the given tenant: %s"),
        // UserStore related Exceptions
        USER_STORE_EXCEPTION_WHILE_TRYING_TO_AUTHENTICATE("BAS-65021",
                "UserStoreException while trying to authenticate"),
        // Organization management exception while resolving user's resident org.
        ORGANIZATION_MGT_EXCEPTION_WHILE_TRYING_TO_RESOLVE_RESIDENT_ORG("BAS-65022",
                "Organization mgt exception while authenticating"),
        MULTIPLE_USER_STORE_BINDING_FOR_SP_NOT_ALLOWED("BAS-65023",
                "Multiple user store binding for SP is not allowed with multi attribute login."),
        // UserStore Error codes
        USER_DOES_NOT_EXISTS("17001", "User does not exists"),
        INVALID_CREDENTIALS("17002",
                "User authentication failed due to invalid credentials"),
        // user identification failure in organization hierarchy.
        USER_NOT_IDENTIFIED_IN_HIERARCHY("17003", "User is not identified");
        private final String code;
        private final String message;

        /**
         * Create an Error Message.
         *
         * @param code    Relevant error code.
         * @param message Relevant error message.
         */
        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        /**
         * To get the code of specific error.
         *
         * @return Error code.
         */
        public String getCode() {

            return code;
        }

        /**
         * To get the message of specific error.
         *
         * @return Error message.
         */
        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return String.format("%s - %s", code, message);
        }
    }
}
