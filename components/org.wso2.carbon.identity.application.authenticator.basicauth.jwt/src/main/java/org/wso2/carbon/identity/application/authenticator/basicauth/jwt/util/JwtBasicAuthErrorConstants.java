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

package org.wso2.carbon.identity.application.authenticator.basicauth.jwt.util;

public class JwtBasicAuthErrorConstants {

    /**
     * Relevant error messages and error codes.
     * This error codes are commented as a group not because of the convention
     * because to maintain the togetherness of the errors.
     */
    public enum ErrorMessages {

        // Signature related error codes
        INVALID_SIGNATURE("JBA-60001",
                "User authentication failed : Invalid signature."),
        SIGNATURE_VALIDATION_ALGORITHM_NOT_FOUND_IN_JWT_HEADER("JBA-60002",
                "Signature validation failed. No algorithm is found in JWT header."),
        SIGNATURE_VALIDATION_PUBLIC_KEY_NOT_AN_RSA_PUBLIC_KEY("JBA-60003",
                "Signature validation failed. Public key is not an RSA public key."),
        SIGNATURE_ALGORITHM_NOT_SUPPORTED("JBA-60004",
                "Signature Algorithm not supported : %s"),
        SIGNATURE_VERIFICATION_FAILED_FOR_JWT("JBA-60005",
                "Signature verification failed for the JWT."),

        // Token related error codes
        INVALID_TOKEN("JBA-60011", "Invalid token"),
        MISSING_REQUIRED_FIELDS_IN_JWT("JBA-60012",
                "Invalid token : Required fields are not present in JWT."),
        INVALID_TOKEN_POSSIBLE_REPLAY_ATTACK("JBA-60013", "Invalid token : Possible replay attack."),
        TOKEN_EXPIRED("JBA-60014", "Invalid token : Token is expired."),
        UNABLE_TO_LOCATE_CERTIFICATE_FOR_JWT("JBA-60015",
                "Unable to locate certificate for JWT %s"),
        CLAIM_VALUES_ARE_EMPTY_IN_GIVEN_JWT("JBA-60016",
                "Claim values are empty in the given JWT."),
        RETRIEVING_CLAIMS_SET_FROM_JWT_FAILED("JBA-60017",
                "Error when trying to retrieve claimsSet from the JWT."),
        KEY_STORE_EXCEPTION_WHILE_INSTANTIATING_X_509_CERTIFICATE_OBJECT("JBA-60018",
                "Key store exception while instantiating x 509 certificate object"),

        // Tenant related Error codes
        GETTING_THE_TENANT_ID_FROM_TENANT_DOMAIN_FAILED("JBA-65031",
                "Error while getting the tenant ID from the tenant domain : %s"),
        UNABLE_TO_LOAD_KEY_STORE_MANAGER_FOR_TENANT_DOMAIN("JBA-65032",
                "Unable to load key store manager for the tenant domain: %s");

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
