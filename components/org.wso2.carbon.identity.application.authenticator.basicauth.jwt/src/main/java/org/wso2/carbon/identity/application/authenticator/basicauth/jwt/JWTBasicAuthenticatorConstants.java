/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.basicauth.jwt;

import org.wso2.carbon.utils.security.KeystoreUtils;

public class JWTBasicAuthenticatorConstants {

    public static final String FULLSTOP_DELIMITER = ".";
    public static final String DASH_DELIMITER = "-";
    @Deprecated
    public static final String KEYSTORE_FILE_EXTENSION = KeystoreUtils.StoreFileType.defaultFileType();

    // Authenticator Name
    public static final String AUTHENTICATOR_NAME = "JWTBasicAuthenticator";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "JWT Basic";

    public static final String PARAM_TOKEN = "token";
    public static final String AUTH_TOKEN = "AuthToken";

    public static final String TIMESTAMP_SKEW = "TimestampSkew";

    private JWTBasicAuthenticatorConstants() {
    }
}
