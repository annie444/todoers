todoers-db := "todoers"
todoers-db-user := "todoers"
todoers-db-password := "todoers"

# macOS code-signing identity. Sign local binaries with a *stable* identity so the
# keychain trusts the app across rebuilds (no repeated "allow access" prompts).
# One-time: create a self-signed "Code Signing" cert named below in Keychain Access.
signing-identity := env("TODOERS_SIGN_ID", "Todoers Dev")

[default]
[private]
default:
    @just --list

[group("Setup")]
install-tools:
    cargo install sqlx-cli --features postgres,sqlite,sqlx-toml

[group("Dev")]
test:
    cargo test --workspace --all-targets

[group("Dev")]
lint:
    cargo clippy --workspace --all-targets --all-features -- -D warnings

[group("Dev")]
fmt:
    cargo fmt --all

[group("Dev")]
fmt-check:
    cargo fmt --all -- --check

[group("Database")]
db-up:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    if ! podman volume exists todoers-db-data; then
      podman volume create todoers-db-data
    fi
    if ! podman container exists todoers-db; then
      podman run -d --name todoers-db \
        -p 5432:5432 \
        -v todoers-db-data:/var/lib/postgresql \
        -e POSTGRES_USER={{ todoers-db-user }} \
        -e POSTGRES_PASSWORD={{ todoers-db-password }} \
        -e POSTGRES_DB={{ todoers-db }} \
        docker.io/library/postgres:18
    fi

[group("Database")]
db-down:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    if podman container exists todoers-db; then
      podman rm -f todoers-db
    fi

[group("Database")]
db-clean:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    if podman volume exists todoers-db-data; then
      podman volume rm -f todoers-db-data
    fi

[group("Database")]
db-exec:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    podman exec -it todoers-db psql -U {{ todoers-db-user }} -d {{ todoers-db }}

[group("Database")]
db-logs:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    podman logs todoers-db

[group("Development")]
check-sqlx:
    cargo sqlx prepare --check --workspace -- --all-targets

[group("Server")]
run-server: setup-server
    cargo run -p todoers-server

[group("Server")]
setup-server: db-up
    (cd todoers-server && cargo sqlx database setup)

[group("Server")]
prepare-server: db-up setup-server
    (cd todoers-server && cargo sqlx prepare -- --all-targets)

[group("Server")]
check-server: db-up setup-server
    (cd todoers-server && cargo sqlx prepare --check -- --all-targets)

[group("TUI")]
run-tui: setup-client setup-server (_sign "debug")
    just run-server >server.log 2>&1 &
    ./target/debug/todoers

[group("Client")]
build-client: setup-client
    cargo build -p todoers

# Run just the TUI client
[group("Client")]
run-client: setup-client
    ./target/debug/todoers

[group("Client")]
setup-client:
    (cd todoers-client && cargo sqlx database setup --sqlite-create-db-wal=true)

[group("Client")]
prepare-client: setup-client
    (cd todoers-client && cargo sqlx prepare --sqlite-create-db-wal=true -- --all-targets)

[group("Client")]
check-client: setup-client
    (cd todoers-client && cargo sqlx prepare --check --sqlite-create-db-wal=true -- --all-targets)

[group("Workspace")]
[parallel]
prepare: prepare-server prepare-client

[group("Workspace")]
[parallel]
setup: setup-server setup-client

[group("Signing")]
[macos]
[private]
_sign bindir:
    #!/usr/bin/env bash
    set -Eeuo pipefail
    bin="target/{{ bindir }}/todoers"
    codesign --force --timestamp=none --sign "{{ signing-identity }}" "$bin"
    codesign --verify --verbose "$bin"
    echo "Signed $bin as \"{{ signing-identity }}\""

# Build + sign the debug binary
[group("Signing")]
[macos]
sign-dev: (_sign "debug")

# Build + sign the release binary
[group("Signing")]
[macos]
sign-release: (_sign "release")

# Build + sign both binaries
[group("Signing")]
[macos]
sign: sign-dev sign-release
