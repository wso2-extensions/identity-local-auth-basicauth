/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

/**
 * Utility class for Basic Authentication related operations.
 */
public class BasicAuthUtil {

    public static final String RESOLVE_TENANT_DOMAIN_FROM_USERNAME_CONFIG = "ResolveTenantDomainFromUsername";

    /**
     * Get the tenant aware username based on configuration and context.
     *
     * @param context  Authentication context
     * @param username Username to process
     * @return Tenant aware username
     */
    public static String getTenantAwareUsername(AuthenticationContext context, String username) {

        if (!Boolean.parseBoolean(IdentityUtil.getProperty(RESOLVE_TENANT_DOMAIN_FROM_USERNAME_CONFIG)) &&
                IdentityTenantUtil.isTenantQualifiedUrlsEnabled() &&
                !context.getSequenceConfig().getApplicationConfig().isSaaSApp()) {
            return username;
        }
        return MultitenantUtils.getTenantAwareUsername(username);
    }

    /**
     * Check if preprocessed username should be used based on configuration and context.
     *
     * @param context Authentication context
     * @return true if preprocessed username should be used, false otherwise
     */
    public static boolean usePreprocessedUsername(AuthenticationContext context) {

        if (Boolean.parseBoolean(IdentityUtil.getProperty(RESOLVE_TENANT_DOMAIN_FROM_USERNAME_CONFIG))) {
            return true;
        }

        return context.getSequenceConfig().getApplicationConfig().isSaaSApp() ||
                !IdentityTenantUtil.isTenantQualifiedUrlsEnabled();
    }

    private BasicAuthUtil() {
        // Private constructor to prevent instantiation.
    }
}
