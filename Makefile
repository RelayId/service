.PHONY: fmt format-check test test-race vet staticcheck vuln build clean smoke e2e docker-build docker-smoke check-config ci

ifeq ($(OS),Windows_NT)
FORMAT_CHECK = powershell -NoProfile -Command "$$files = Get-ChildItem -Path src,web -Filter *.go -Recurse | ForEach-Object FullName; $$formatted = gofmt -l $$files; if ($$formatted) { Write-Error ($$formatted -join [Environment]::NewLine); exit 1 }"
REMOVE_BUILD_OUTPUT = powershell -NoProfile -Command "$$targets = @('relay', 'relay.exe') + @(Get-ChildItem -File -Filter '*.test' -ErrorAction SilentlyContinue | ForEach-Object FullName); foreach ($$target in $$targets) { if (Test-Path -LiteralPath $$target) { Remove-Item -Force -LiteralPath $$target } }"
DOCKER_SMOKE = powershell -NoProfile -Command "$$config = Join-Path (Get-Location) 'docker-smoke.config.local.yaml'; $$secrets = Join-Path (Get-Location) 'docker-smoke.secrets'; if ((Test-Path -LiteralPath $$config) -or (Test-Path -LiteralPath $$secrets)) { throw 'docker-smoke requires no existing temporary config or secrets directory' }; @('issuer: https://relay.example.com', 'listen: 3000', 'development: true', 'oauth2:', '  providers: []', 'oidc:', '  clients: []') | Set-Content -LiteralPath $$config; New-Item -ItemType Directory -Force -Path $$secrets | Out-Null; $$env:RELAY_CONFIG_FILE = $$config; $$env:RELAY_SECRETS_DIR = $$secrets; if (-not $$env:RELAY_IMAGE) { $$env:RELAY_IMAGE = 'relayid:local' }; docker tag $$env:RELAY_IMAGE ghcr.io/relayid/relayid:latest; try { go run ./src check-config $$config; docker compose -f docker-compose.yml up -d --force-recreate --wait; if ($$LASTEXITCODE -ne 0) { exit $$LASTEXITCODE }; Invoke-WebRequest -UseBasicParsing http://127.0.0.1:3000/api/status | Out-Null; Invoke-WebRequest -UseBasicParsing http://127.0.0.1:3000/.well-known/openid-configuration | Out-Null } finally { docker compose -f docker-compose.yml down -v; Remove-Item -Force -LiteralPath $$config -ErrorAction SilentlyContinue; Remove-Item -Recurse -Force -LiteralPath $$secrets -ErrorAction SilentlyContinue }"
CHECK_CONFIG = powershell -NoProfile -Command "$$config = 'check-config.local.yaml'; @('issuer: https://relay.example.com', 'listen: 3000', 'development: true', 'oauth2:', '  providers: []', 'oidc:', '  clients: []') | Set-Content -LiteralPath $$config; try { go run ./src check-config $$config } finally { Remove-Item -Force -LiteralPath $$config -ErrorAction SilentlyContinue }"
else
FORMAT_CHECK = test -z "$$(gofmt -l $$(find src web -name '*.go' -type f))"
REMOVE_BUILD_OUTPUT = rm -f relay relay.exe *.test
DOCKER_SMOKE = if test -e docker-smoke.config.local.yaml || test -e docker-smoke.secrets; then echo 'docker-smoke requires no existing temporary config or secrets directory' >&2; exit 1; fi; config="$$(pwd)/docker-smoke.config.local.yaml"; secrets="$$(pwd)/docker-smoke.secrets"; printf '%s\n' 'issuer: https://relay.example.com' 'listen: 3000' 'development: true' 'oauth2:' '  providers: []' 'oidc:' '  clients: []' > "$$config"; mkdir -p "$$secrets"; trap 'docker compose -f docker-compose.yml down -v; rm -rf "$$config" "$$secrets"' EXIT; export RELAY_CONFIG_FILE="$$config" RELAY_SECRETS_DIR="$$secrets"; image="$${RELAY_IMAGE:-relayid:local}"; docker tag "$$image" ghcr.io/relayid/relayid:latest; go run ./src check-config "$$config"; docker compose -f docker-compose.yml up -d --force-recreate --wait; curl --fail http://127.0.0.1:3000/api/status; curl --fail http://127.0.0.1:3000/.well-known/openid-configuration
CHECK_CONFIG = config=check-config.local.yaml; printf '%s\n' 'issuer: https://relay.example.com' 'listen: 3000' 'development: true' 'oauth2:' '  providers: []' 'oidc:' '  clients: []' > "$$config"; trap 'rm -f "$$config"' EXIT; go run ./src check-config "$$config"
endif

fmt:
	go fmt ./...

format-check:
	$(FORMAT_CHECK)

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

staticcheck:
	staticcheck ./...

vuln:
	govulncheck ./...

build:
	go build -trimpath -o relay ./src

clean:
	go clean -testcache
	$(REMOVE_BUILD_OUTPUT)

smoke:
	go test -run 'TestBrowserPagesAndQRRoute|TestPublicHTTP' ./src

e2e:
	go test -run 'TestEndToEnd|TestRestartAcceptsPreviouslyEnrolledCredential' ./src

docker-build:
	docker build -t relayid:local .

docker-smoke:
	$(DOCKER_SMOKE)

check-config:
	$(CHECK_CONFIG)

ci: format-check test e2e test-race vet staticcheck vuln build docker-build docker-smoke
