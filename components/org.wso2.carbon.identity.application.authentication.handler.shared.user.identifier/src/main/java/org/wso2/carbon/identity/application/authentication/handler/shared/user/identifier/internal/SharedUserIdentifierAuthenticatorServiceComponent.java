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

package org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.internal;

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
import org.wso2.carbon.identity.application.authentication.handler.shared.user.identifier.SharedUserIdentifierHandler;
import org.wso2.carbon.identity.multi.attribute.login.mgt.MultiAttributeLoginService;
import org.wso2.carbon.identity.organization.management.organization.user.sharing.OrganizationUserSharingService;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and de-registration of
 * SharedUserIdentifierHandler.
 */
@Component(
        name = "identity.application.handler.shared.user.identifier.component",
        immediate = true
)
public class SharedUserIdentifierAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(SharedUserIdentifierAuthenticatorServiceComponent.class);

    private static RealmService realmService;
    private static MultiAttributeLoginService multiAttributeLogin;
    private static OrganizationUserSharingService organizationUserSharingService;
    private static OrganizationManager organizationManager;

    public static RealmService getRealmService() {

        return realmService;
    }

    public static MultiAttributeLoginService getMultiAttributeLogin() {

        return multiAttributeLogin;
    }

    public static OrganizationUserSharingService getOrganizationUserSharingService() {

        return organizationUserSharingService;
    }

    public static OrganizationManager getOrganizationManager() {

        return organizationManager;
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
        SharedUserIdentifierAuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("Unsetting the Realm Service");
        SharedUserIdentifierAuthenticatorServiceComponent.realmService = null;
    }

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            SharedUserIdentifierHandler sharedUserIdentifierHandler = new SharedUserIdentifierHandler();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    sharedUserIdentifierHandler, null);

            if (log.isDebugEnabled()) {
                log.info("SharedUserIdentifierHandler bundle is activated");
            }
        } catch (Throwable e) {
            log.error("SharedUserIdentifierHandler bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("SharedUserIdentifierHandler bundle is deactivated");
        }
    }

    @Reference(
            name = "MultiAttributeLoginService",
            service = MultiAttributeLoginService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetMultiAttributeLoginService"
    )
    protected void setMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLogin) {

        SharedUserIdentifierAuthenticatorServiceComponent.multiAttributeLogin = multiAttributeLogin;
    }

    protected void unsetMultiAttributeLoginService(MultiAttributeLoginService multiAttributeLogin) {

        SharedUserIdentifierAuthenticatorServiceComponent.multiAttributeLogin = null;
    }

    @Reference(
            name = "organization.user.sharing.service",
            service = OrganizationUserSharingService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationUserSharingService"
    )
    protected void setOrganizationUserSharingService(
            OrganizationUserSharingService organizationUserSharingService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the organization user sharing service.");
        }
        SharedUserIdentifierAuthenticatorServiceComponent.organizationUserSharingService =
                organizationUserSharingService;
    }

    protected void unsetOrganizationUserSharingService(
            OrganizationUserSharingService organizationUserSharingService) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the organization user sharing service.");
        }
        SharedUserIdentifierAuthenticatorServiceComponent.organizationUserSharingService = null;
    }

    @Reference(
            name = "organization.manager",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager"
    )
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the organization manager service.");
        }
        SharedUserIdentifierAuthenticatorServiceComponent.organizationManager = organizationManager;
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        if (log.isDebugEnabled()) {
            log.debug("Unsetting the organization manager service.");
        }
        SharedUserIdentifierAuthenticatorServiceComponent.organizationManager = null;
    }
}

