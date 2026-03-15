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
import org.keycloak.protocol.oidc.grants.OAuth2GrantType;
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

/**
 * Factory for the steam_ticket grant type. Configures lookup URL and API secret from provider config or environment.
 */
public class SteamTicketGrantTypeFactory implements OAuth2GrantTypeFactory {

    public static final String PROVIDER_ID = "steam_ticket";

    private static final String CONFIG_LOOKUP_URL = "lookup_url";
    private static final String CONFIG_API_SECRET = "api_secret";
    private static final String ENV_LOOKUP_URL = "STEAM_TICKET_LOOKUP_URL";
    private static final String ENV_LOOKUP_SECRET = "STEAM_TICKET_LOOKUP_SECRET";

    private SteamTicketLookupService lookupService;

    @Override
    public OAuth2GrantType create(org.keycloak.models.KeycloakSession session) {
        return new SteamTicketGrantType(lookupService);
    }

    @Override
    public void init(Config.Scope config) {
        String lookupUrl = config.get(CONFIG_LOOKUP_URL);
        if (lookupUrl == null || lookupUrl.isBlank()) {
            lookupUrl = System.getenv(ENV_LOOKUP_URL);
        }
        String apiSecret = config.get(CONFIG_API_SECRET);
        if (apiSecret == null || apiSecret.isBlank()) {
            apiSecret = System.getenv(ENV_LOOKUP_SECRET);
        }
        this.lookupService = new SteamTicketLookupService(lookupUrl, apiSecret);
    }

    @Override
    public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getShortcut() {
        return "stm";
    }

    @Override
    public void close() {
    }

    @Override
    public List<ProviderConfigProperty> getConfigMetadata() {
        return List.of(
                new ProviderConfigProperty(
                        CONFIG_LOOKUP_URL,
                        "Lookup URL",
                        "URL of the external lookup endpoint (e.g. https://example.com/access/steam/lookup). Alternatively set " + ENV_LOOKUP_URL + ".",
                        ProviderConfigProperty.STRING_TYPE,
                        null),
                new ProviderConfigProperty(
                        CONFIG_API_SECRET,
                        "API Secret",
                        "Secret sent in X-API-Secret header to the lookup endpoint. Alternatively set " + ENV_LOOKUP_SECRET + ". Do not commit secrets.",
                        ProviderConfigProperty.PASSWORD,
                        null,
                        true));
    }
}
