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

package org.keycloak.steam.claim;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.Collections;
import java.util.List;

/**
 * Protocol mapper that adds {@code steam_id} to tokens from the user's Steam federated identity (broker link).
 * Works for both web-linked and ticket-linked users; no user attribute required.
 */
public class SteamIdFromBrokerLinkMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper, OIDCIDTokenMapper {

    public static final String PROVIDER_ID = "steam-id-from-broker-link";
    private static final String STEAM_IDP_ALIAS = "steam";
    private static final String STEAM_FEDERATED_USER_ID_PREFIX = "https://steamcommunity.com/openid/id/";
    private static final String CLAIM_STEAM_ID = "steam_id";

    @Override
    public String getDisplayCategory() {
        return "Federated identity";
    }

    @Override
    public String getDisplayType() {
        return "Steam ID (from broker link)";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "Adds the numeric Steam ID to the token from the user's Steam federated identity (Identity provider link). Works for web and ticket-linked users.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return Collections.emptyList();
    }

    @Override
    public AccessToken transformAccessToken(AccessToken token, ProtocolMapperModel mappingModel,
                                            KeycloakSession session, UserSessionModel userSession,
                                            ClientSessionContext clientSessionCtx) {
        String steamId = getSteamIdFromBrokerLink(session, userSession);
        if (steamId != null) {
            token.getOtherClaims().put(CLAIM_STEAM_ID, steamId);
        }
        return token;
    }

    @Override
    public IDToken transformIDToken(IDToken token, ProtocolMapperModel mappingModel,
                                    KeycloakSession session, UserSessionModel userSession,
                                    ClientSessionContext clientSessionCtx) {
        String steamId = getSteamIdFromBrokerLink(session, userSession);
        if (steamId != null) {
            token.getOtherClaims().put(CLAIM_STEAM_ID, steamId);
        }
        return token;
    }

    @Override
    public AccessToken transformUserInfoToken(AccessToken token, ProtocolMapperModel mappingModel,
                                              KeycloakSession session, UserSessionModel userSession,
                                              ClientSessionContext clientSessionCtx) {
        String steamId = getSteamIdFromBrokerLink(session, userSession);
        if (steamId != null) {
            token.getOtherClaims().put(CLAIM_STEAM_ID, steamId);
        }
        return token;
    }

    private String getSteamIdFromBrokerLink(KeycloakSession session, UserSessionModel userSession) {
        if (userSession == null || userSession.getUser() == null) {
            return null;
        }
        UserModel user = userSession.getUser();
        var realm = userSession.getRealm();
        var federatedIdentity = session.users().getFederatedIdentity(realm, user, STEAM_IDP_ALIAS);
        if (federatedIdentity == null) {
            return null;
        }
        String providerUserId = federatedIdentity.getUserId();
        if (providerUserId == null || providerUserId.isEmpty()) {
            return null;
        }
        if (providerUserId.startsWith(STEAM_FEDERATED_USER_ID_PREFIX)) {
            return providerUserId.substring(STEAM_FEDERATED_USER_ID_PREFIX.length());
        }
        if (providerUserId.matches("\\d+")) {
            return providerUserId;
        }
        return null;
    }
}
