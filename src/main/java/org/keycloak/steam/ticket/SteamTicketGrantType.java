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

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.services.CorsErrorResponseException;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.TokenUtil;

import org.jboss.logging.Logger;

/**
 * OAuth 2.0 extension grant: steam_ticket.
 * Validates the ticket via an external lookup URL, resolves the Keycloak user id, creates a session and returns tokens.
 */
public class SteamTicketGrantType extends org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase {

    private static final Logger logger = Logger.getLogger(SteamTicketGrantType.class);

    public static final String GRANT_TYPE = "steam_ticket";
    public static final String PARAM_TICKET = "ticket";
    public static final String PARAM_STEAM_APP_ID = "steam_app_id";
    public static final String PARAM_GAME_KEY = "game_key";

    private final SteamTicketLookupService lookupService;

    public SteamTicketGrantType(SteamTicketLookupService lookupService) {
        this.lookupService = lookupService;
    }

    @Override
    public Response process(org.keycloak.protocol.oidc.grants.OAuth2GrantType.Context context) {
        setContext(context);

        event.detail(Details.AUTH_METHOD, GRANT_TYPE);

        checkClient();

        if (!client.isDirectAccessGrantsEnabled()) {
            String errorMessage = "Client not allowed for direct access grants";
            event.detail(Details.REASON, errorMessage);
            event.error(Errors.NOT_ALLOWED);
            throw new CorsErrorResponseException(cors, OAuthErrorException.UNAUTHORIZED_CLIENT, errorMessage, Response.Status.BAD_REQUEST);
        }

        String ticket = formParams.getFirst(PARAM_TICKET);
        String steamAppIdParam = formParams.getFirst(PARAM_STEAM_APP_ID);
        String gameKey = formParams.getFirst(PARAM_GAME_KEY);

        if (ticket == null || ticket.isBlank()) {
            event.detail(Details.REASON, "Missing ticket");
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Missing ticket", Response.Status.BAD_REQUEST);
        }
        if (steamAppIdParam == null || steamAppIdParam.isBlank()) {
            event.detail(Details.REASON, "Missing steam_app_id");
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Missing steam_app_id", Response.Status.BAD_REQUEST);
        }
        int steamAppId;
        try {
            steamAppId = Integer.parseInt(steamAppIdParam.trim());
        } catch (NumberFormatException e) {
            event.detail(Details.REASON, "Invalid steam_app_id");
            event.error(Errors.INVALID_REQUEST);
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_REQUEST, "Invalid steam_app_id", Response.Status.BAD_REQUEST);
        }

        java.util.Optional<String> userIdOpt = lookupService.lookupUserId(ticket, steamAppId, gameKey);
        if (userIdOpt.isEmpty()) {
            logger.debug("Lookup returned no user or failed");
            event.detail(Details.REASON, "User not found or ticket invalid");
            event.error("invalid_grant");
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "User not found or ticket invalid", Response.Status.BAD_REQUEST);
        }
        String userId = userIdOpt.get();

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null || !user.isEnabled()) {
            event.detail(Details.REASON, "User not found or disabled");
            event.error("invalid_grant");
            throw new CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, "User not found or ticket invalid", Response.Status.BAD_REQUEST);
        }

        String scopeParam = getRequestedScopes();

        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, false);
        AuthenticationSessionModel authSession = rootAuthSession.createAuthenticationSession(client);
        authSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authSession.setRedirectUri(Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));
        authSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, scopeParam != null ? scopeParam : "");
        authSession.setAuthenticatedUser(user);

        UserSessionModel userSession = session.sessions().createUserSession(
                null,
                realm,
                user,
                user.getUsername(),
                clientConnection.getRemoteAddr(),
                GRANT_TYPE,
                false,
                null,
                null,
                UserSessionModel.SessionPersistenceState.PERSISTENT);

        ClientSessionContext clientSessionCtx = TokenManager.attachAuthenticationSession(session, userSession, authSession);
        clientSessionCtx.setAttribute(OAuth2Constants.GRANT_TYPE, GRANT_TYPE);
        updateUserSessionFromClientAuth(userSession);

        TokenManager.AccessTokenResponseBuilder responseBuilder = tokenManager
                .responseBuilder(realm, client, event, session, userSession, clientSessionCtx).generateAccessToken();
        boolean useRefreshToken = clientConfig.isUseRefreshToken();
        if (useRefreshToken) {
            responseBuilder.generateRefreshToken();
            if (TokenUtil.TOKEN_TYPE_OFFLINE.equals(responseBuilder.getRefreshToken().getType())) {
                session.sessions().removeUserSession(realm, userSession);
            }
        }

        if (TokenUtil.isOIDCRequest(scopeParam)) {
            responseBuilder.generateIDToken().generateAccessTokenHash();
        }

        checkAndBindMtlsHoKToken(responseBuilder, useRefreshToken);

        org.keycloak.representations.AccessTokenResponse res = responseBuilder.build();

        event.success();
        event.user(user);

        return cors.add(Response.ok(res, MediaType.APPLICATION_JSON_TYPE));
    }

    @Override
    public EventType getEventType() {
        return EventType.LOGIN;
    }
}
