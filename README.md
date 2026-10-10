# RelayId

RelayId is a device-enrollment identity service with three protocol boundaries:

- `oauth2/*` is the internal upstream identity boundary. RelayId authenticates an enrolling user with an upstream provider through `egauth`.
- `oidc/*` is the external downstream identity boundary. Cloudflare Access and other relying parties authenticate against RelayId as an OIDC provider.
- `api/*` is the signed Relay device/application API. It is not a third identity protocol.

The browser UI is served from `web/`. The device API keeps its existing public-key enrollment, QR approval, mobile-code, replay-prevention, and credential behavior.

The boundaries have separate configuration:

- An **upstream provider** is where RelayId authenticates the enrolling person. It is configured under `oauth2.providers`.
- A **downstream OIDC client** is an application that trusts RelayId, such as Cloudflare Access. It is configured under `oidc.clients`.

RelayId is the OIDC provider for the downstream application. The downstream application is not the same OAuth client as the upstream provider.

## Relay Device Protocol

Relay-client authentication uses hybrid classical and post-quantum-resistant authentication. Every enrolled client has a P-256 ECDSA device key and an ML-DSA-65 key. Relay requires both signatures for enrollment completion and every protected `/api` request. Clients should keep the P-256 private key non-exportable in the platform key store and use hardware-backed storage where the platform provides it.

P-256 is compatible with platform key stores, including hardware-backed implementations where available, and protects the protocol if ML-DSA is ever broken. ML-DSA-65 provides the post-quantum signature component if a future cryptographically relevant quantum attack threatens elliptic-curve signatures. This is not a claim that RelayId is unbreakable or quantum-proof.

The device credential is opaque `rdc.<base64url nonce>.<base64url ciphertext>` state authenticated with AES-256-GCM. It contains the enrolled identity and both public keys, but no private key or upstream token. Changing `device_credential_key_b64` invalidates existing device credentials and requires re-enrollment.

External OIDC remains ES256 with P-256 JWKS for interoperability with Cloudflare, Grafana, and other relying parties. Device authentication and OIDC token signing are separate cryptographic boundaries. ML-KEM is not part of the application protocol; transport/TLS post-quantum support depends on the complete TLS path, including any reverse proxy or Cloudflare edge.

## Quick start

```bash
cp .env.example /srv/relayid/.env
sudo install -d -m 0750 /srv/relayid/secrets
cp config.example.yaml /srv/relayid/config.yml
go run ./src keygen
# Put the generated values in /srv/relayid/config.yml, or reference files in /srv/relayid/secrets/.
go run ./src check-config /srv/relayid/config.yml
docker compose --env-file /srv/relayid/.env -f /srv/relayid/service/docker-compose.yml up -d --wait
curl --fail https://relay.example.com/api/status
```

For a production-like local deployment, set `issuer` to the public hostname you control, for example `https://relay.example.com`, and route that hostname to host port `3000` through your reverse proxy or tunnel. The container listens on port `3000`; it does not terminate public TLS.

### Local Docker deployment

Keep deployment configuration and secret material outside the source checkout. A typical host layout is:

```text
/srv/relayid/
├── .env
├── config.yml
├── secrets/
└── service/       # checked-out RelayId service repository
```

Create `/srv/relayid/.env` from `.env.example`:

```env
RELAY_CONFIG_FILE=/srv/relayid/config.yml
RELAY_SECRETS_DIR=/srv/relayid/secrets
```

Copy `config.example.yaml` to `/srv/relayid/config.yml`, replace its example values, and place referenced key files under `/srv/relayid/secrets/`. Register each configured upstream callback using the public issuer, for example:

```text
https://relay.example.com/oauth2/google/callback
```

Run Compose with the deployment environment file and the checked-out Compose file:

```bash
cp .env.example /srv/relayid/.env
# Edit /srv/relayid/.env if the deployment paths differ.
docker compose --env-file /srv/relayid/.env -f /srv/relayid/service/docker-compose.yml up -d --wait
docker compose --env-file /srv/relayid/.env -f /srv/relayid/service/docker-compose.yml exec -T relay /relay check-config /etc/relay/config.yaml
curl --fail https://relay.example.com/api/status
curl --fail https://relay.example.com/api/providers
```

The example paths and domains are placeholders. Do not commit `/srv/relayid/.env`, `/srv/relayid/config.yml`, or `/srv/relayid/secrets/`.

## Upstream OAuth2

Upstream providers are configured under `oauth2.providers`. There is no generated provider layer and no Relay-owned endpoint catalog. Relay uses the ready-made constructors in `egauth/oauth/providers` for known presets and one generic constructor for custom OAuth2.

RelayId exposes the providers from the pinned `egauth` dependency that can satisfy RelayId's simple configuration and identity requirements. The supported preset names are sorted by `relay providers`:

```text
custom
discord
github
gitlab
google
linkedin
oidc
```

The library contains additional constructors, but they are not all valid RelayId presets. Some require mandatory provider-specific values such as an Auth0/Okta domain, Microsoft tenant, Keycloak realm, or Cognito region and user-pool ID. Those providers are intentionally not represented by a fake default or an unsafe three-field adapter. Relay only advertises presets whose callback and identity-verification behavior satisfies its security contract.

For a provider not listed above, use `provider: oidc` when it supports standard OIDC discovery and provide its issuer. That is the universal path for compliant OIDC services; it still cannot turn an arbitrary OAuth2 service into OIDC. `provider: custom` remains available when explicit OAuth2 endpoints and scopes are genuinely required.

Preset examples only need a provider name and credentials:

```yaml
oauth2:
  providers:
    - id: google
      name: Google
      provider: google
      client_id: replace-me
      client_secret: replace-me

    - id: company
      name: Company SSO
      provider: oidc
      issuer: https://login.example.com
      client_id: replace-me
      client_secret: replace-me
```

Generic custom OAuth2 requires an explicit stable `namespace`, `authorization_url`, `token_url`, and `userinfo_url`. Its optional `scopes` are the only upstream scopes configured by Relay. The user-info response must include a stable subject, an email, and `email_verified: true`; otherwise enrollment is rejected. Never change a namespace after users have enrolled.

Every upstream callback is Relay-owned:

```text
https://relay.example.com/oauth2/{provider-id}/callback
```

`egauth` owns provider construction, token exchange, PKCE, OIDC discovery, signed-token/JWKS validation, and provider user parsing. Relay keeps state single-use, adds the PKCE S256 challenge, validates OIDC nonce, and never persists upstream access tokens.

### Headless enrollment

A device client does not need to know the browser provider route. After creating an enrollment and listing `/api/providers`, it starts upstream authentication with:

```http
POST /api/enrollments/{id}/oauth2
{"provider_id":"google"}
```

The response contains only `authorization_url` and `expires_at`. The client opens that URL in the system user-agent: Android Custom Tabs, iOS `ASWebAuthenticationSession`, the desktop system browser, or a CLI browser flow. Do not use an embedded WebView. Relay keeps the OAuth state, PKCE verifier, nonce, and provider credentials server-side.

Before approving an enrollment, a Relay client must pin and display the Relay origin it is configured to use. The QR payload is generated from that origin; scanning it does not authorize a different Relay server and does not approve the transaction by itself. The client must compare the QR scheme, hostname, and effective port exactly with the stored origin, reject a mismatch, send protected API requests only to the stored origin, and never learn or auto-add a new Relay server from a QR. Before approval, it should show the stored origin, device name, relying-party display name, and requested scopes, then require an explicit approval action. Only one Relay process should own a configured in-memory state store at a time; running multiple active replicas without shared state can make transactions appear missing and is not supported by this deployment mode.

The browser callback remains `/oauth2/{provider-id}/callback`. After it succeeds, RelayId redirects to the optional client `return_uri` as a completion signal; the URI receives only `enrollment_id` and `state=verified`. The device then reads `GET /api/enrollments/{id}`, signs the returned `signing_payload` with both local private keys, and posts `signatures.p256` and `signatures.mldsa65` to the completion endpoint. Without a return URI, it can poll. Provider access tokens, refresh tokens, ID tokens, and sessions are never returned to the device client or stored as its credential.

When browser pages are enabled, the home page offers a QR code at `/api/relay-qr` containing a `relayid://relay?origin=...` configuration deep link. The RelayId app can scan this code or receive it from the operating system to open Add Relay with the origin prefilled before it fetches providers. This QR code is a convenience for configuration only; it does not enroll a device, approve a login, or override the app's origin validation.

## Downstream OIDC

Relying parties are configured under `oidc.clients`. Relay advertises discovery at the standard root URL:

```text
https://relay.example.com/.well-known/openid-configuration
```

The protocol endpoints are:

```text
/oidc/authorize
/oidc/userinfo
/oidc/token
/oidc/jwks
```

Discovery advertises those paths. Client `redirect_uris` belong to the consuming application, not to Relay's upstream provider.

Cloudflare One configuration uses:

```text
Name:              RelayId
App ID:            the oidc.clients[].id value
Client secret:     the matching oidc.clients[].secret value
Auth URL:          https://relay.example.com/oidc/authorize
Token URL:         https://relay.example.com/oidc/token
Certificate URL:   https://relay.example.com/oidc/jwks
PKCE:              enabled
OIDC scopes:       openid email profile
```

Cloudflare One setup order:

1. In Cloudflare One, open the Add OpenID Connect identity-provider form and copy the displayed `Callback URL`.
2. Add an entry under `oidc.clients` with an ID you choose, a random secret of at least 32 characters, and that exact callback URL in `redirect_uris`:

   ```yaml
   oidc:
     clients:
       - id: cloudflare-access
         name: Cloudflare Access
         secret: replace-with-a-random-secret-of-at-least-32-chars
         redirect_uris:
           - https://client.example.com/cdn-cgi/access/callback
         require_pkce: true
   ```

3. In the Cloudflare form, enter the URLs and values above. `App ID` is `oidc.clients[].id`; `Client secret` is the matching `secret`.
4. Enable the form's `Proof Key for Code Exchange (PKCE)` switch. RelayId supports S256 for this downstream flow.
5. Leave `Email claim` blank unless your RelayId deployment intentionally changes the standard `email` claim, and leave custom `OIDC Claims` empty. The form requires the built-in `openid`, `email`, and `profile` scopes.
6. If Cloudflare offers an issuer/discovery field instead of individual endpoints, use `https://relay.example.com/.well-known/openid-configuration`.
7. Create or edit the Cloudflare Access application and allow the RelayId identity provider.

The callback URL in Cloudflare's form belongs in RelayId's downstream `redirect_uris`. It is not the upstream callback at `/oauth2/{provider-id}/callback`. The `Certificate URL` field is RelayId's JWKS endpoint; it is not a PEM certificate file. Cloudflare's form does not require a UserInfo URL; RelayId's discovery document advertises `/oidc/userinfo` for clients that use UserInfo. Use the public hostname in every Cloudflare URL, not `localhost` or the container address.

## Device API

The signed device/application surface remains under `/api`:

```text
/api/status
/api/providers
/api/enrollments...
/api/logins...
/api/codes
/api/qr...
```

Device requests use the RelayDevice signature scheme and enrolled device keys. `openapi.yaml` is the single API contract source; it is not served as a second runtime copy.

### Client completion flow

RelayId does not need a separate Android, desktop, or CLI authentication implementation. Every client uses the same signed device API and may open the user's normal system browser.

For enrollment:

1. The client creates a key pair and sends the public key to `POST /api/enrollments`. It may include an HTTPS app/universal link or custom-scheme `return_uri`.
2. The client starts `POST /api/enrollments/{id}/oauth2` with a configured provider ID and opens the returned authorization URL in the system browser.
3. RelayId handles the upstream provider redirect, validates the state, PKCE, nonce, subject, and verified email, then marks the enrollment `verified`.
4. After success, RelayId redirects the browser to the supplied `return_uri` with only `enrollment_id` and `state=verified`. The client then reads `GET /api/enrollments/{id}`, signs the enrollment payload, and sends `POST /api/enrollments/{id}/complete`. Without a return URI, the client can poll instead.
5. RelayId returns the opaque device credential in that response. The upstream provider access token is never returned to or stored by the client.

The return URI is a completion signal, not an OAuth callback owned by the client. The client must still read the enrollment resource and complete it with both device signatures. If no return URI is available, polling is the portable fallback. A mobile client can use an app/universal link, a desktop client can use a registered custom scheme or loopback receiver, and a CLI can use a loopback receiver or polling.

The same Relay device API can be used by mobile, desktop, and CLI clients. Platform-specific code is limited to secure-key handling, opening the system browser, and optional return-URI handling. The homepage Relay QR contains a `relayid://relay?origin=...` configuration deep link. A RelayId app can scan it inside its Add Relay flow or receive it from the operating system and open Add Relay with the origin prefilled; it does not begin enrollment or skip provider verification.

Typed browser approval codes are disabled by default. Set `mobile_code.enabled: true` in the YAML configuration to expose `POST /api/codes`, the code field on browser login pages, and the app's Generate code action. Set `mobile_code.groups` to choose the exact number of four-character groups; the valid range is 2 through 4. The `/api/providers` response publishes this capability as one `mobile_code` object containing `enabled` and `groups`, so clients do not need a duplicated format setting. Codes are single-use and expire with the configured code lifetime. A login is expired after five invalid code attempts. QR approval with both device signatures remains available regardless of this setting.

The group count is deliberately one fixed value for the deployment rather than a per-login range. Each group contains four characters from a 32-character alphabet, so two groups provide 40 bits of random code space and four groups provide 80 bits. The service enforces the 2–4 group boundary, generates every character with a cryptographically secure random source, rejects active-code collisions, applies both per-login and global rate limits, and expires the login after five failed attempts. This makes guessing infeasible in practice without treating rate limiting as the only protection. QR approval with the enrolled device's required signatures remains the stronger default path. Provider discovery is authoritative: every returned provider has an explicit `enabled` state, and clients refresh it before starting enrollment so a provider disabled after the screen opened cannot be used. The preview login can switch the display without restarting the service: use `/test/login?mobile_code=on` or `/test/login?mobile_code=off` when test pages are enabled. This query override is limited to preview pages and does not change production login behavior.

For downstream OIDC login:

1. The relying party redirects its browser to `/oidc/authorize`.
2. RelayId creates a short-lived login and displays a QR code and mobile code in the browser transaction page.
3. The client discovers the pending login through `GET /api/logins/{id}` and submits a signed `POST /api/logins/{id}/approve` or `/deny`.
4. RelayId completes the browser redirect with a one-time authorization code; the relying party exchanges it at `/oidc/token` using its PKCE verifier.

The login QR contains a `relayid://login` deep link carrying the Relay origin and pending login ID. With RelayId installed and that Relay already configured, a phone's native camera can open the app directly on the approval screen. If the Relay is not configured, the app opens Relay setup with the origin prefilled and preserves the pending login through enrollment before opening approval. The app still verifies the exact Relay origin and login ID; scanning the QR does not approve anything.

The client never receives the relying party's client secret, browser cookie, authorization code, ID token, or upstream provider token. It only signs device operations with its enrolled credential.

### Relay-client request signing contract

For every protected `/api` request, the Relay client sends:

```http
Authorization: RelayDevice <opaque-credential>
X-Relay-Timestamp: <base-10 Unix seconds>
X-Relay-Nonce: <32-character base64url-no-padding nonce>
X-Relay-P256-Signature: <base64url-no-padding ASN.1 DER signature>
X-Relay-MLDSA65-Signature: <base64url-no-padding raw signature>
```

The nonce decodes to exactly 24 random bytes. Padded, malformed, empty, or oversized nonces are rejected. Authenticated Relay-client requests must not have a query string. Both signatures are mandatory; a valid signature from only one key is rejected.

The exact canonical UTF-8 bytes are:

```text
relay-device-request\n<METHOD>\n<ESCAPED-PATH>\n<TIMESTAMP>\n<NONCE>\n<BASE64URL-SHA512-OF-RAW-BODY>
```

There are ASCII LF separators and no trailing LF after the final digest. `METHOD` is the uppercase method exactly as sent. `ESCAPED-PATH` is the escaped path only; the query string is not included and is forbidden for authenticated requests. `TIMESTAMP` is base-10 Unix seconds. The raw body bytes are hashed before JSON parsing with SHA-512, and the digest is RFC 4648 base64url without padding. The P-256 signature is ECDSA over SHA-256 of the canonical bytes, encoded as ASN.1 DER and then base64url without padding. The ML-DSA-65 signature signs the exact canonical bytes directly with an empty FIPS 204 context; the `relay-device-request` prefix provides domain separation.

For enrollment completion, the client treats `signing_payload` as an opaque UTF-8 string. Relay generates it with the `relay-enrollment` prefix. The client signs the exact received bytes with P-256 ECDSA/SHA-256 and ML-DSA-65 using an empty FIPS 204 context, then submits both signatures under `signatures.p256` and `signatures.mldsa65`. It must not reconstruct or parse the payload.

### Device-held data

A completed client stores the Relay base URL, a device-key alias/reference, its device private key, the opaque Relay device credential, credential expiry, and optional display metadata such as email. The private key should be non-exportable where the platform supports it.

The client does not retain OAuth tokens, upstream ID tokens, PKCE verifiers, OAuth state, completed enrollment signing payloads, or OIDC tokens issued to target applications. The Relay credential is opaque to the client and is not sufficient by itself: protected device requests also require a signature from the corresponding device private key.

### Cryptographic keys

- The device private keys are generated locally as P-256 and ML-DSA-65 keys, never leave the device, and both sign Relay API requests.
- The Relay device credential key is a server-held 32-byte AES-256-GCM key used to authenticate opaque credentials issued after enrollment.
- The Relay OIDC signing key is server-held and signs ID/access tokens for relying parties; its public key is exposed at `/oidc/jwks`.

The enrollment sequence is therefore: the device sends both public keys; Relay verifies the upstream identity; Relay binds a signing payload to the enrollment, identity, both public keys, and expiry; the device signs it locally with both keys; Relay verifies both proofs and returns the opaque credential.

Credential internals use `upstream_namespace`, because the value is not always a formal issuer URI. For generic OIDC it is the normalized configured issuer. For known OAuth presets it is the stable preset/provider namespace. The client must not parse this claim; it is an internal server identity boundary.

## Configuration

Relay has one application configuration source: a YAML file. There are no environment overrides, JSON configuration variants, or duplicate duration/key/provider settings. This keeps deployment reviewable and prevents an unnoticed environment value from changing a checked configuration file.

Start from `config.example.yaml`, copy it to the host path named by `RELAY_CONFIG_FILE`, and fill in every real issuer, signing key, client secret, provider endpoint, and provider credential. Development mode may generate temporary keys; production requires explicit keys. If key files are used, put them under the host directory named by `RELAY_SECRETS_DIR` and reference their container paths such as `/etc/relay/secrets/oidc.key` in the YAML file.

### Signing keys and secret files

RelayId needs an ECDSA P-256 private key for downstream OIDC tokens and a separate 32-byte AES-256-GCM key for opaque device credentials. Never reuse key material for both purposes. Keep the YAML file and secret material outside the Git checkout, readable by the container, and backed up securely.

The simplest option is base64 in the YAML file. Run `go run ./src keygen`; it prints `oidc_signing_key_b64` and `device_credential_key_b64`. Copy each complete value into the matching field in the deployment YAML. Do not commit that YAML file.

For separate key files, generate PKCS#8 PEM files with OpenSSL:

```bash
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out /srv/relayid/secrets/oidc-signing-key.pem
chmod 0600 /srv/relayid/secrets/*.pem
```

The production container runs as the unprivileged `nonroot` user (UID/GID `65532`). When these files are bind-mounted into Docker, make them readable by that user while keeping the directory private:

```bash
sudo chown 65532:65532 /srv/relayid/config.yml /srv/relayid/secrets/*.pem
sudo chmod 0400 /srv/relayid/config.yml /srv/relayid/secrets/*.pem
sudo chmod 0750 /srv/relayid/secrets
```

Recreate the container after changing ownership or modes. Leaving the PEM files owned by `root:root` with mode `0600` causes `permission denied` errors inside the container.

Then use container paths in the YAML, not host paths:

```yaml
oidc_signing_key_file: /etc/relay/secrets/oidc-signing-key.pem
```

Do not set a `_b64` field and its matching `_file` field together. With Docker bind mounts, ensure the container's non-root user can read the files; the image runs as UID `65532` by default, so a host installation may use `chown 65532:65532` on the two files and keep them mode `0600`.

### Configuration fields

| Field | Meaning |
|---|---|
| `issuer` | RelayId's public, permanent base URL. It must have no path, query, or fragment; production uses HTTPS. |
| `listen` | Local bind port/address. The normal value is `3000`, not `:3000`. |
| `development` | Allows localhost HTTP and development key behavior. Keep `false` in production. |
| `serve_test_pages` | Serves the public Home and How It Works preview pages. Keep `false` when the browser preview is not needed; transaction pages used by OAuth/OIDC flows remain available. |
| `expose_system_stats` | Adds optional Relay-process CPU percentage and used memory bytes to `/api/status`. It does not expose host totals or maximum memory. Keep `false` unless operators intentionally want this public status data. |
| `trust_cloudflare_ip` | Uses `CF-Connecting-IP` for rate limiting. Enable only when direct access to RelayId is impossible. |
| `oidc_signing_key_b64` / `oidc_signing_key_file` | Exactly one source for the downstream OIDC ES256 signing key. |
| `device_credential_key_b64` | Standard base64 encoding of exactly 32 random bytes for AES-256-GCM device credentials. Required in production. |
| `oidc.clients[].id` | Downstream application client ID. |
| `oidc.clients[].secret` | Downstream application secret; at least 32 characters. |
| `oidc.clients[].redirect_uris` | Exact callback URLs owned by the downstream application. Production URLs must use HTTPS. |
| `oidc.clients[].require_pkce` | Requires S256 PKCE on the downstream authorization request. |
| `oauth2.providers[].id` | RelayId's provider route identifier; it must be unique and URL-safe. |
| `oauth2.providers[].name` | Display name shown to the device/user. |
| `oauth2.providers[].provider` | Preset name such as `google`, `github`, `gitlab`, `discord`, `linkedin`, `oidc`, or `custom`. |
| `oauth2.providers[].client_id` / `client_secret` | Credentials registered with the upstream provider. |
| `oauth2.providers[].issuer` | Required only for generic upstream `oidc`; it is the discovery issuer. |
| `oauth2.providers[].namespace` | Required only for `custom`; keep it stable because it affects user subjects. |
| `authorization_url`, `token_url`, `userinfo_url`, `scopes` | Used only by `custom`; presets and generic `oidc` do not accept these fields. |
| `lifetimes.*` | Login, enrollment, mobile-code, and device-credential durations. |

There are no environment overrides for these values. `config.example.yaml` is only the template. Copy it to the host path configured by `RELAY_CONFIG_FILE`, edit that file, and validate that exact file. The `.env` file contains only Docker host paths; it does not override any RelayId setting.

When `serve_test_pages: true`, the service also exposes safe, non-functional browser previews using dummy data:

```text
/test/enroll
/test/enroll/preview-enrollment
/test/login
/test/error
```

The preview routes never create real enrollments, logins, provider transactions, credentials, or callback state. They are intended for checking the embedded HTML/CSS while building Android, desktop, and CLI clients. Transaction pages used by real OAuth/OIDC flows remain available independently of this preview switch.


Generate keys with:

```bash
go run ./src keygen
```

Validate the example or your local YAML with:

```bash
cp .env.example /srv/relayid/.env
cp config.example.yaml /srv/relayid/config.yml
# Replace every placeholder, then validate the real local file.
go run ./src check-config /srv/relayid/config.yml
go run ./src providers
```

The API contract is kept as `openapi.yaml` at the repository root because it describes the service API and is consumed by client/code-generation tooling. `web/static` is only for browser assets that are embedded and served at runtime; copying OpenAPI there would create a second, drift-prone contract. The service does not expose a runtime OpenAPI endpoint.

For `POST /api/codes`, the minimal example body is the exact bytes `{}`. Clients must hash and sign the exact raw bytes they actually transmit; whitespace or JSON serialization differences change the signature.

The example configuration uses neutral `relay.example.com` and `client.example.com` values and is valid YAML with strict field names. Its placeholder keys and credentials are intentionally not deployable; replace them before running `check-config`. Lifetime comments in `config.example.yaml` describe the actual product/security effect of each value.

## Server and Docker setup

The simplest production-like server setup is:

```bash
cp .env.example /srv/relayid/.env
sudo install -d -m 0750 /srv/relayid/secrets
cp config.example.yaml /srv/relayid/config.yml
# edit /srv/relayid/config.yml and replace every example value
docker compose --env-file /srv/relayid/.env -f /srv/relayid/service/docker-compose.yml up -d --wait
```

Create `/srv/relayid/.env` from `.env.example` and set the two host paths:

```bash
cp .env.example /srv/relayid/.env
# Edit /srv/relayid/.env if your config and secrets live elsewhere.
```

`RELAY_CONFIG_FILE` is the host YAML file mounted read-only at `/etc/relay/config.yaml`. `RELAY_SECRETS_DIR` is the host directory mounted read-only at `/etc/relay/secrets`. These variables have no defaults and are not RelayId application configuration. The image is fixed to `ghcr.io/relayid/service:latest`. The Compose file publishes port `3000` and the service listens on port `3000`.

For a non-Docker server, install the built `relay` binary, keep `config.yaml` and `secrets/` outside the binary directory, and run `relay /absolute/path/to/config.yaml` under a service manager. The process needs read access to the YAML and referenced key files, but no write access to them. Put TLS at the reverse proxy; the Relay container is intended to receive HTTP from that local proxy/network boundary.

Before exposing a new server, validate the exact file that will be mounted:

```bash
go run ./src check-config /srv/relayid/config.yml
docker compose --env-file /srv/relayid/.env -f /srv/relayid/service/docker-compose.yml config
docker compose --env-file /srv/relayid/.env -f /srv/relayid/service/docker-compose.yml up -d --wait
curl https://relay.example.com/api/status
```

`/api/status` is intentionally public aggregate status. It reports readiness, uptime, coarse process-local counts, and configured counts, but no names, emails, subjects, credentials, transaction IDs, runtime details, or OAuth state. If `expose_system_stats` is enabled, it additionally reports Relay-process CPU percentage and used memory bytes, without host totals or maximum memory. Counts reset on restart and can reveal only coarse activity levels. Keep the host firewall and reverse proxy restricted to the intended public routes and use HTTPS at the edge.

## License

RelayId is distributed under the GNU General Public License v3. The complete license text is in `LICENSE`.

## Normal OIDC login

The target application starts `/oidc/authorize`. Relay creates a browser login transaction and displays its QR/code. The device reads `/api/logins/{id}`, approves locally by signing with both private keys and sending its Relay credential, and Relay verifies both the credential and signatures. The browser receives an authorization code, and the target application's backend exchanges it at `/oidc/token`. Relay issues the signed OIDC tokens. The device authenticates to Relay; it does not authenticate directly to Cloudflare or another target service.

The current short mobile code is not TOTP and is not generated offline. A device signs `POST /api/codes`, Relay returns a short-lived single-use code, and the user enters it in the Relay browser login page. Relay-client approval and code generation require network access to Relay.

`egauth` is pinned in `go.mod`; Relay's provider and end-to-end tests cover the behavior relied upon by the service.

## Client loss, reset, and re-enrollment

RelayId has no long-lived user/device database in stateless mode. If a Relay client loses its private key or credential, it creates a new P-256 key and enrolls again through OAuth2. Re-enrollment with the same stable upstream namespace and subject produces the same downstream Relay user `sub`, but creates a new device public key, credential, and JTI. A credential without its matching private key cannot authenticate.

Deleting all Relay-client app data is recoverable: the client generates a new P-256 key, enrolls again, authenticates through the same upstream account, and receives a new credential. If the upstream namespace and subject are unchanged, the downstream Relay OIDC `sub` remains unchanged. The old credential cannot be used without its old private key.

Re-enrollment does not revoke an older still-usable Relay client. A stolen client that still has both a valid credential and its private key can authenticate until credential expiry. Immediate revocation would require a future persistent device registry or revocation backend and is intentionally not part of this stateless contract.

## Long-lived identity invariants

Treat the configured `issuer` as permanent after deployment. Changing it invalidates existing credential issuer expectations and changes downstream OIDC identity configuration. Back up the Relay device-credential signing key: replacing or losing it invalidates enrolled Relay-client credentials and requires re-enrollment. Back up the Relay OIDC signing key: replacing it changes the JWKS/signing identity and immediately affects existing short-lived OIDC tokens. Once users have enrolled, do not casually change a provider namespace because it determines downstream `sub` values.

Credential expiry is intentional. An expired credential requires OAuth2 enrollment again; Relay does not automatically refresh device credentials. Relay does not retain upstream OAuth tokens or continuously query upstream account state. Upstream account disablement does not invalidate an already-issued Relay credential by itself; the upstream identity is consulted again only during a new enrollment after expiry, loss, or reset.

The same downstream OIDC `sub` is recovered only when both the stable `upstream_namespace` and `upstream_subject` are unchanged. The same email through a different upstream provider is not automatically the same Relay identity. Durable global revocation is out of scope; an individual relying party can apply its own access policy.

If `trust_cloudflare_ip` is enabled, Relay uses `CF-Connecting-IP` for rate-limit identity. Enable it only when Relay is reachable solely through Cloudflare or another boundary that guarantees the header. If attackers can connect directly to Relay, they can spoof the header and evade per-IP rate limits. Relay never downloads Cloudflare IP ranges at runtime.

The operator-configurable timing policy is limited to `lifetimes.login`, `lifetimes.enrollment`, `lifetimes.code`, and `lifetimes.credential`. The remaining protocol safety timings -- authorization codes, OIDC tokens, device clock skew, replay nonces, and upstream OAuth state -- are fixed internal constants and are not configuration fields.

## Development

```text
go test ./...
go test -race ./...
go vet ./...
make check-config
make e2e
docker build -t relayid:local .
```
`make clean` clears Go test cache and local build/test output. It does not remove configuration or key material.

Docker smoke tests create their disposable configuration and secrets directory at runtime and remove them afterward. The repository does not generate source archives; deploy from the checked-out source or build the container image directly.
