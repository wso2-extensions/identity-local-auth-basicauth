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

package org.wso2.carbon.identity.application.authenticator.basicauth.jwt.cache;

import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationBaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Implements a cache to store JWT references
 */
public class AuthJwtCache extends AuthenticationBaseCache<String,String> {
    public static final String AUTH_JWT_CACHE = "AuthJWT";
    private static volatile AuthJwtCache instance;

    private AuthJwtCache() {
        super(AUTH_JWT_CACHE);
    }

    public static AuthJwtCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (AuthJwtCache.class) {
                if (instance == null) {
                    instance = new AuthJwtCache();
                }
            }
        }
        return instance;
    }
}
