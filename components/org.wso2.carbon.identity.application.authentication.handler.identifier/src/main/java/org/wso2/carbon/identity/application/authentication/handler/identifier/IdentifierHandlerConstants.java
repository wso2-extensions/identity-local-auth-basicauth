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

    private IdentifierHandlerConstants() {
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
        }
    }
}
