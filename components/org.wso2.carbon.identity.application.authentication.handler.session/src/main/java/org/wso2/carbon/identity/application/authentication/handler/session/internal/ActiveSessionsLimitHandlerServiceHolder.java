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

import org.wso2.carbon.identity.application.authentication.framework.UserSessionManagementService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * OSGi service holder for the Session Handler.
 */
public class ActiveSessionsLimitHandlerServiceHolder {

    private static ActiveSessionsLimitHandlerServiceHolder instance = new ActiveSessionsLimitHandlerServiceHolder();
    private RealmService realmService;
    private UserSessionManagementService userSessionManagementService;

    private ActiveSessionsLimitHandlerServiceHolder() {

    }

    public static ActiveSessionsLimitHandlerServiceHolder getInstance() {

        return instance;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public UserSessionManagementService getUserSessionManagementService() {

        return userSessionManagementService;
    }

    public void setUserSessionManagementService(UserSessionManagementService userSessionManagementService) {

        this.userSessionManagementService = userSessionManagementService;
    }
}
