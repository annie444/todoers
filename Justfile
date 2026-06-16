todoers-db := "todoers"
todoers-db-user := "todoers"
todoers-db-password := "todoers"

[default]
[private]
default:
    @just --list

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
