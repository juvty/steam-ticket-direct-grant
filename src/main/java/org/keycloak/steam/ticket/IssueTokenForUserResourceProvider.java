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

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.UserModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.util.Map;

/**
 * Quarkus-friendly realm resource provider with an inline stub endpoint.
 * Mounted by IssueTokenForUserResourceProviderFactory at:
 * /realms/{realm}/steam-token/issue-token-for-user
 */
@Path("")
public class IssueTokenForUserResourceProvider implements RealmResourceProvider {

    public static final String PROVIDER_ID = "steam-token";

    private static final Logger logger = Logger.getLogger(IssueTokenForUserResourceProvider.class);

    private final KeycloakSession session;

    public IssueTokenForUserResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {
    }

    /**
     * Issue tokens for the requested user, authenticated by a caller Bearer token obtained via client_credentials.
     */
    @POST
    @Path("issue-token-for-user")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response issueTokenForUser(Map<String, String> body) {
        RealmModel realm = session.getContext().getRealm();
        AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(realm)
                .setHeaders(session.getContext().getRequestHeaders())
                .setUriInfo(session.getContext().getUri())
                .setConnection(session.getContext().getConnection())
                .setRequest(session.getContext().getHttpRequest())
                .authenticate();

        if (auth == null || auth.client() == null) {
            logger.warn("issue-token-for-user denied: no authenticated client resolved from Bearer token");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            "error", "invalid_client",
                            "error_description", "Caller must authenticate with client_credentials"))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        ClientModel client = auth.client();
        UserModel authUser = auth.user();
        String serviceAccountClientLink = authUser == null ? null : authUser.getServiceAccountClientLink();
        if (serviceAccountClientLink == null || !serviceAccountClientLink.equals(client.getId())) {
            logger.warnf(
                    "issue-token-for-user denied: caller client=%s is not a service-account token",
                    client.getClientId());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(Map.of(
                            "error", "invalid_client",
                            "error_description", "Caller must authenticate with client_credentials"))
                    .type(MediaType.APPLICATION_JSON_TYPE)
                    .build();
        }

        logger.infof(
                "issue-token-for-user authenticated caller client=%s realm=%s",
                client.getClientId(),
                realm == null ? "<null>" : realm.getName());

        return new IssueTokenForUserResource(session).issueTokenForUser(body, client);
    }
}
