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

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

import org.jboss.logging.Logger;

import java.util.Map;

/**
 * Helper that issues tokens for a resolved Keycloak user on behalf of an already-authenticated client.
 */
public class IssueTokenForUserResource {

    private static final Logger logger = Logger.getLogger(IssueTokenForUserResource.class);

    private final KeycloakSession session;

    public IssueTokenForUserResource(KeycloakSession session) {
        this.session = session;
    }

    public Response issueTokenForUser(Map<String, String> body, ClientModel client) {
        if (body == null || !body.containsKey("userId")) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "invalid_request", "error_description", "Missing userId"))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
        String userId = body.get("userId");
        if (userId == null || userId.isBlank()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "invalid_request", "error_description", "userId must be non-empty"))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        RealmModel realm = session.getContext().getRealm();
        if (client == null) {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of("error", "invalid_client", "error_description", "Caller must authenticate with client_credentials"))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null || !user.isEnabled()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(Map.of("error", "invalid_grant", "error_description", "User not found or disabled"))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        try {
            String scopeParam = "openid profile email offline_access";
            String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());

            // TokenManager and auth session helpers rely on realm/client being present on the request context.
            session.getContext().setRealm(realm);
            session.getContext().setClient(client);

            RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
            AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
            authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
            authSession.setRedirectUri(issuer);
            authSession.setClientNote(OIDCLoginProtocol.ISSUER, issuer);
            authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam);
            authSession.setAuthenticatedUser(user);

            UserSessionModel userSession = session.sessions().createUserSession(
                    null,
                    realm,
                    user,
                    user.getUsername(),
                    session.getContext().getConnection().getRemoteAddr(),
                    "issue-token-for-user",
                    false,
                    null,
                    null,
                    UserSessionModel.SessionPersistenceState.PERSISTENT);

            var clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);

            TokenManager tokenManager = new TokenManager();
            org.keycloak.events.EventBuilder event = new org.keycloak.events.EventBuilder(realm, session, session.getContext().getConnection());
            var responseBuilder = tokenManager.responseBuilder(realm, client, event, session, userSession, clientSessionCtx).generateAccessToken();
            if (OIDCAdvancedConfigWrapper.fromClientModel(client).isUseRefreshToken()) {
                responseBuilder.generateRefreshToken();
            }
            responseBuilder.generateIDToken().generateAccessTokenHash();

            AccessTokenResponse res = responseBuilder.build();
            return Response.ok(res).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (Exception e) {
            logger.warnf(e, "Failed to issue token for user %s", userId);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity(Map.of("error", "server_error", "error_description", e.getMessage()))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }
    }
}
