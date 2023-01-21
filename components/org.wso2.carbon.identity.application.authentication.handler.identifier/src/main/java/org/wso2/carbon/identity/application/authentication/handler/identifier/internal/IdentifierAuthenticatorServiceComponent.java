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

package org.wso2.carbon.identity.application.authentication.handler.identifier.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.handler.identifier.IdentifierHandler;
import org.wso2.carbon.identity.login.resolver.mgt.LoginResolverService;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.organization.management.service.OrganizationUserResidentResolverService;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "identity.application.handler.identifier.component",
        immediate = true
)
public class IdentifierAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(IdentifierAuthenticatorServiceComponent.class);

    private static RealmService realmService;
    private static LoginResolverService loginResolverService;
    private static MultiAttributeLoginService multiAttributeLogin;
    private static OrganizationUserResidentResolverService organizationUserResidentResolverService;

    public static RealmService getRealmService() {

        return realmService;
    }

    /**
     * Retrieves the login resolver service.
     *
     * @return The login resolver service.
     */
    public static LoginResolverService getLoginResolverService() {

        return loginResolverService;
    }

    /**
     * Retrieves the multi attribute login service.
     *
     * @return The multi attribute login service.
     * @deprecated To generalize the resolver concept and make it extensible.
     * Use the {@link #getLoginResolverService()} method instead.
     */
    @Deprecated
    public static MultiAttributeLoginService getMultiAttributeLogin() {

        return multiAttributeLogin;
    }

    public static OrganizationUserResidentResolverService getOrganizationUserResidentResolverService() {

        return organizationUserResidentResolverService;
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        log.debug("Setting the Realm Service");
        IdentifierAuthenticatorServiceComponent.realmService = realmService;
    }

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            IdentifierHandler identifierHandler = new IdentifierHandler();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), identifierHandler, null);
            if (log.isDebugEnabled()) {
                log.info("IdentifierHandler bundle is activated");
            }
        } catch (Throwable e) {
            log.error("IdentifierHandler Authenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("IdentifierHandler bundle is deactivated");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        IdentifierAuthenticatorServiceComponent.realmService = null;
    }

    /**
     * Sets the login resolver service.
     *
     * @param loginResolverService The login resolver service to be set.
     */
    @Reference(
            name = "LoginResolverService",
            service = LoginResolverService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetLoginResolverService")
    protected void setLoginResolverService(LoginResolverService loginResolverService) {

        IdentifierAuthenticatorServiceComponent.loginResolverService = loginResolverService;
    }

    /**
     * Unsets the login resolver service.
     *
     * @param loginResolverService The login resolver service to be unset.
     */
    protected void unsetLoginResolverService(LoginResolverService loginResolverService) {

        IdentifierAuthenticatorServiceComponent.loginResolverService = null;
    }

    /**
     * Sets the multi attribute login service.
     *
     * @param multiAttributeLogin The multi attribute login service to be set.
     * @deprecated To generalize the resolver concept and make it extensible.
     * Use the {@link #setLoginResolverService(LoginResolverService)} method instead.
     */
    @Deprecated
    @Reference(
            name = "MultiAttributeLoginService",
            service = MultiAttributeLoginService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetMultiAttributeLoginService")
    protected void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLogin) {

        IdentifierAuthenticatorServiceComponent.multiAttributeLogin = multiAttributeLogin;
    }

    /**
     * Unsets the multi attribute login service.
     *
     * @param multiAttributeLogin The multi attribute login service to be unset.
     * @deprecated To generalize the resolver concept and make it extensible.
     * Use the {@link #unsetLoginResolverService(LoginResolverService)} method instead.
     */
    @Deprecated
    protected void unsetMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLogin) {

        IdentifierAuthenticatorServiceComponent.multiAttributeLogin = null;

    }

    @Reference(
            name = "organization.user.resident.resolver.service",
            service = OrganizationUserResidentResolverService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserResidentResolverService"
    )
    protected void setOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the organization user resident resolver service.");
        }
        IdentifierAuthenticatorServiceComponent.organizationUserResidentResolverService =
                organizationUserResidentResolverService;
    }

    protected void unsetOrganizationUserResidentResolverService(
            OrganizationUserResidentResolverService organizationUserResidentResolverService) {

        if (log.isDebugEnabled()) {
            log.debug("Unset organization user resident resolver service.");
        }
        IdentifierAuthenticatorServiceComponent.organizationUserResidentResolverService = null;
    }
}
