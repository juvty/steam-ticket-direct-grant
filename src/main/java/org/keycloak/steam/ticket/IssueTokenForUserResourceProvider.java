/*
 * Copyright 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.steam.ticket;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Mounts the issue-token-for-user endpoint under the realm.
 * With provider id "ext", the URL is: /realms/{realm}/ext/issue-token-for-user
 */
public class IssueTokenForUserResourceProvider implements RealmResourceProvider, RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "ext";

    private final KeycloakSession session;

    public IssueTokenForUserResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    /** No-arg constructor for SPI factory loading. */
    public IssueTokenForUserResourceProvider() {
        this.session = null;
    }

    @Override
    public Object getResource() {
        if (session == null) {
            throw new IllegalStateException("Provider not initialized with session");
        }
        return new IssueTokenForUserResource(session);
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new IssueTokenForUserResourceProvider(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
