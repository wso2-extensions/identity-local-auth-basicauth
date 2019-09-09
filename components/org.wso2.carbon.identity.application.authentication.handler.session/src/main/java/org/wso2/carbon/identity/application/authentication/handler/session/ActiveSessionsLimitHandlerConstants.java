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

package org.wso2.carbon.identity.application.authentication.handler.session;

/**
 * Constants used by the Session Handler.
 */
public abstract class ActiveSessionsLimitHandlerConstants {

    public static final String HANDLER_NAME = "SessionExecutor";
    public static final String HANDLER_FRIENDLY_NAME = "active-sessions-limit-handler";
    public static final String TERMINATE_SESSIONS_ACTION = "terminateActiveSessionsAction";
    public static final String ACTIVE_SESSIONS_LIMIT_ACTION = "ActiveSessionsLimitAction";
    public static final String DENY_LOGIN_ACTION = "denyLimitActiveSessionsAction";
    public static final String REFRESH_ACTION = "refreshActiveSessionsAction";
    public static final String MAX_SESSION_COUNT = "MaxSessionCount";
    public static final String SESSIONS_TO_TERMINATE = "sessionsToTerminate";
    public static final String SESSIONS = "sessions";
    public static final String SESSION_DATA_KEY = "sessionDataKey";

    private ActiveSessionsLimitHandlerConstants() {

    }
}
