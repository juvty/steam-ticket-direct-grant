# Steam Ticket Direct Grant – Keycloak Extension

Keycloak server extension that adds:

1. **Steam ticket OAuth2 grant type** (`grant_type=steam_ticket`) – Clients can exchange a Steam auth ticket for Keycloak access and refresh tokens. The extension calls an external lookup URL (configurable) to validate the ticket and resolve the Keycloak user id; no secrets in source.

2. **Optional: issue-token-for-user endpoint** – REST endpoint for the “everything through payments” flow: an authenticated backend (e.g. client_credentials) can request tokens for a given user id. Used when the backend has already resolved the user (e.g. from a Steam ticket via its own service) and needs Keycloak tokens for that user.

## Deployment checklist

| Step | Where | What |
|------|--------|------|
| 1. Build | This repo | `mvn clean package` → JAR in `target/`. |
| 2. Deploy JAR | Keycloak server | Copy JAR to Keycloak `providers/` (e.g. `/opt/keycloak/providers/`). Restart Keycloak. |
| 3. Configure extension | Keycloak host | Set **lookup URL** so the extension can call your backend: env `STEAM_TICKET_LOOKUP_URL=https://<payments-host>/access/steam/lookup`. Optionally set `STEAM_TICKET_LOOKUP_SECRET` if your lookup endpoint requires it; juvty-payments keeps `/access/steam/lookup` unguarded (Unity/client sends no secret during Steam login), so you can leave the secret unset unless you add your own auth later. |
| 4. Keycloak client | Keycloak Admin → Client | The client that will use `grant_type=steam_ticket` must have **Direct access grants** enabled. |
| 5. Steam Web API key | **juvty-payments** (not Keycloak) | Get a Steam Web API key (Steamworks). Set **`STEAM_WEB_API_KEY_ARN`** to the ARN of an AWS secret whose JSON has key **`Steam__ApplicationKey`** (e.g. `juvty/steam-proxy`), or set **`STEAM_WEB_API_KEY`** in env for local dev. Payments uses it to call Steam (AuthenticateUserTicket, GetOwnedGames). |
| 6. Payments URL | Keycloak / clients | juvty-payments must be reachable at the URL you put in `STEAM_TICKET_LOOKUP_URL`. With the current design, the lookup endpoint is unguarded so both Keycloak (server) and the Unity client (during Steam login, no token yet) can call it. |
| 7. (Optional) issue-token-for-user | juvty-payments | If you use the “everything through payments” flow (client calls payments `POST /access/steam/authenticate`), payments needs to call Keycloak to get tokens. Configure payments to use `https://<keycloak>/realms/<realm>/ext/issue-token-for-user` (this extension adds that endpoint). |

**Steam dev key:** The **Steam Web API key** (step 5) is the one you need. It is used by **juvty-payments** only. Keycloak does not talk to Steam; it only calls your payments lookup URL. Get the key from [Steamworks](https://partner.steamgames.com/) (Web API Key for your app / account).

---

## Build

- **Requirements:** Maven 3.8+, Java 17+
- **Keycloak:** Target Keycloak 26.x (Quarkus). Match your server version via `keycloak.version` in `pom.xml`.

```bash
mvn clean package
```

The JAR is produced in `target/steam-ticket-direct-grant-1.0.0-SNAPSHOT.jar` (or the current version).

## Deploy

1. Copy the JAR to Keycloak’s `providers/` directory (e.g. `keycloak_home/providers/` or in Docker: mount the JAR into `/opt/keycloak/providers/`).
2. Restart Keycloak.

Keycloak will load the extension and register the new grant type and the custom realm resource.

## Configuration

No hardcoded secrets or internal URLs. Configuration is per deployment.

### Steam ticket grant (lookup URL and secret)

- **Option A – Keycloak provider config**  
  In Keycloak Admin: **Realm** → **Client scopes** / or the provider config for the grant type (if exposed in the UI).  
  Alternatively, configure the provider via Keycloak CLI or a custom theme that exposes:
  - `lookup_url` – Full URL of the lookup endpoint (e.g. `https://your-backend.example.com/access/steam/lookup`).
  - `api_secret` – Secret sent in the `X-API-Secret` header to that endpoint. Do not commit; store in Keycloak’s config or vault.

- **Option B – Environment variables**
  - `STEAM_TICKET_LOOKUP_URL` – Same as `lookup_url`.
  - `STEAM_TICKET_LOOKUP_SECRET` – Same as `api_secret`.

The lookup endpoint must accept `POST` with JSON body `{ "ticket": "<hex-or-base64>", "steamAppId": <number>, "gameKey": "<optional>" }` and return 200 with JSON `{ "userId": "<keycloak-user-id>" }` or `{ "userId": null }` when the user is not found.

**Example (environment variables on Keycloak host):**

```bash
# Payments base URL (without /game-status); lookup path is /access/steam/lookup
export STEAM_TICKET_LOOKUP_URL="https://juvty.com/api/juvty-payments/access/steam/lookup"
# Optional: STEAM_TICKET_LOOKUP_SECRET if your lookup endpoint requires X-API-Secret (juvty-payments keeps lookup unguarded for Unity Steam login)
# Then start Keycloak (e.g. systemctl restart keycloak)
```

**Example (Keycloak provider config):** If your Keycloak version exposes OAuth2 grant type provider configuration in the admin UI, set `lookup_url` and `api_secret` there. Otherwise use the env vars above.

### issue-token-for-user endpoint

- **URL:** `https://<keycloak-host>/realms/<realm>/ext/issue-token-for-user`  
  (This extension mounts the realm resource with id `ext`, so the path is `/realms/{realm}/ext/issue-token-for-user`.)

- **Auth:** Caller must call with a Bearer token obtained via OAuth2 client_credentials (e.g. the backend’s `client_id` + `client_secret`). Keycloak will set the client in the request context.

- **Body:** `{ "userId": "<keycloak-user-id>" }`

- **Response:** Standard token response (`access_token`, `refresh_token`, `expires_in`, etc.).

If your backend expects a different path (e.g. `.../protocol/openid-connect/ext/issue-token-for-user`), configure the backend’s issue-token URL to `.../realms/<realm>/ext/issue-token-for-user`, or use a reverse proxy to rewrite the path.

## Steam ticket grant usage

Clients (confidential) that have **Direct access grants** enabled can call the token endpoint with:

- `grant_type=steam_ticket`
- `ticket` – Steam auth ticket (hex or base64)
- `steam_app_id` – Steam App ID (number)
- `game_key` – Optional game key string

Plus `client_id` and `client_secret` (or equivalent client auth). The extension will call the configured lookup URL; if it returns a user id, it creates a session and returns access and refresh tokens.

## Security

- Do not commit `lookup_url` or `api_secret` in the repo. Use provider config or environment variables where the server runs.
- The repo can be public; secrets live only in Keycloak configuration or environment.

## License

Apache License 2.0.
