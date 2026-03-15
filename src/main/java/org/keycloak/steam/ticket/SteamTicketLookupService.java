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

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

import org.jboss.logging.Logger;

/**
 * HTTP client that calls the configured lookup URL to validate a Steam ticket and resolve the Keycloak user id.
 * No hardcoded URLs or secrets; all from configuration.
 */
public class SteamTicketLookupService {

    private static final Logger logger = Logger.getLogger(SteamTicketLookupService.class);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private final String lookupUrl;
    private final String apiSecret;
    private final HttpClient httpClient;

    public SteamTicketLookupService(String lookupUrl, String apiSecret) {
        this.lookupUrl = lookupUrl;
        this.apiSecret = apiSecret == null ? "" : apiSecret;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(REQUEST_TIMEOUT)
                .build();
    }

    /**
     * POST to the lookup URL with JSON body { ticket, steamAppId, gameKey? } and API secret header.
     * Expects 200 with JSON { userId: "..." } or { userId: null }.
     *
     * @return the Keycloak user id if found, empty if not found or on error
     */
    public Optional<String> lookupUserId(String ticket, int steamAppId, String gameKey) {
        if (lookupUrl == null || lookupUrl.isBlank()) {
            logger.warn("Lookup URL not configured");
            return Optional.empty();
        }

        String body = buildRequestBody(ticket, steamAppId, gameKey);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(lookupUrl))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .header("X-API-Secret", apiSecret)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) {
                logger.debugf("Lookup returned status %d", response.statusCode());
                return Optional.empty();
            }
            return parseUserId(response.body());
        } catch (Exception e) {
            logger.warnf(e, "Lookup request failed: %s", e.getMessage());
            return Optional.empty();
        }
    }

    private static String buildRequestBody(String ticket, int steamAppId, String gameKey) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"ticket\":\"").append(escapeJson(ticket)).append("\",\"steamAppId\":").append(steamAppId);
        if (gameKey != null && !gameKey.isBlank()) {
            sb.append(",\"gameKey\":\"").append(escapeJson(gameKey)).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static Optional<String> parseUserId(String json) {
        if (json == null || json.isBlank()) return Optional.empty();
        // Simple extraction: "userId":"<value>" or "userId": null
        int keyIdx = json.indexOf("\"userId\"");
        if (keyIdx < 0) return Optional.empty();
        int colonIdx = json.indexOf(':', keyIdx);
        if (colonIdx < 0) return Optional.empty();
        int start = colonIdx + 1;
        while (start < json.length() && (json.charAt(start) == ' ' || json.charAt(start) == '\t')) start++;
        if (start >= json.length()) return Optional.empty();
        if (json.startsWith("null", start)) return Optional.empty();
        if (json.charAt(start) == '"') {
            int end = json.indexOf('"', start + 1);
            if (end < 0) return Optional.empty();
            return Optional.of(json.substring(start + 1, end));
        }
        return Optional.empty();
    }
}
