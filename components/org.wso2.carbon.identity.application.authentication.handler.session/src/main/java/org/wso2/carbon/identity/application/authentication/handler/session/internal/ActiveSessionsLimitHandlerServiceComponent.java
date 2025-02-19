/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authentication.handler.session.internal;

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
import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.identity.application.authentication.handler.session.ActiveSessionsLimitHandler;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi declarative services component which handles registration and de-registration of Session Handler.
 */
@Component(
        name = "identity.application.handler.session.component",
        immediate = true
)
public class ActiveSessionsLimitHandlerServiceComponent {

    private static final Log log = LogFactory.getLog(ActiveSessionsLimitHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            ActiveSessionsLimitHandler activeSessionsLimitHandler = new ActiveSessionsLimitHandler();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), activeSessionsLimitHandler
                    , null);
            if (log.isDebugEnabled()) {
                log.debug("ActiveSessionsLimitHandler bundle is activated");
            }
        } catch (Throwable e) {
            log.error("ActiveSessionsLimitHandler Authenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("ActiveSessionsLimitHandler bundle is deactivated");
        }
    }

    @Reference(
            name = "realm.service",
            service = RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService"
    )
    protected void setRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("Setting the Realm Service");
        }
        ActiveSessionsLimitHandlerServiceHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        if (log.isDebugEnabled()) {
            log.debug("UnSetting the Realm Service");
        }
        ActiveSessionsLimitHandlerServiceHolder.getInstance().setRealmService(null);
    }

    @Reference(
            name = "org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService",
            service = UserSessionManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetUserSessionManagementService"
    )
    protected void setUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("UserSessionManagementService is set in the conditional authentication user functions bundle");
        }
        ActiveSessionsLimitHandlerServiceHolder.getInstance()
                .setUserSessionManagementService(userSessionManagementService);
    }

    protected void unsetUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        if (log.isDebugEnabled()) {
            log.debug("UserSessionManagementService is unset in the conditional authentication user functions bundle");
        }
        ActiveSessionsLimitHandlerServiceHolder.getInstance().setUserSessionManagementService(null);
    }

    @Reference(name = "identity.organization.management.component",
            service = OrganizationManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetOrganizationManager")
    protected void setOrganizationManager(OrganizationManager organizationManager) {

        ActiveSessionsLimitHandlerServiceHolder.getInstance().setOrganizationManager(organizationManager);
        log.debug("Organization Manager is set in the ActiveSessionsLimitHandlerServiceComponent bundle.");
    }

    protected void unsetOrganizationManager(OrganizationManager organizationManager) {

        ActiveSessionsLimitHandlerServiceHolder.getInstance().setOrganizationManager(null);
        log.debug("Organization Manager is unset in the ActiveSessionsLimitHandlerServiceComponent bundle.");
    }
}
