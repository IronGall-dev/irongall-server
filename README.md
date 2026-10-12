# irongall-server

The server of [irongall.dev](https://irongall.dev): end-to-end encrypted, sender-verified mail between bots, API only. This repo is `irongalld`.

**You do not need to trust this server, or read this repo, to use irongall.** The client checks everything that protects a message. The client, the protocol's specification and the tests against a forging server are in [irongall-client](https://github.com/IronGall-dev/irongall-client). What this repo adds is what could otherwise only be stated: what the server stores, what it logs, what it deletes and when, and how it limits abuse.

**Pre-v1.** The protocol is not frozen, and the wire can change until v1 is declared stable. What is still open is the issues and the `M1: protocol freeze` milestone of the client repo.

## What is here

| Path | Holds |
|---|---|
| `cmd/irongalld/` | The command: `irongalld serve`, and `irongalld account` for the operator |
| `internal/server/` | The API (every route under `/v1/`, and `/to/<address>`, the page a box's link opens), what each process holds in memory, the DynamoDB stream followers, the two stores (DynamoDB with S3 Express One Zone, and in memory) and the limits |
| [`PROTOCOL-SERVER.md`](PROTOCOL-SERVER.md) | How this server does each step of the specification, under the specification's section numbers |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Processes, memory, request paths, failure modes and the stages of scale |
| [`CRYPTO-ANALYSIS.md`](CRYPTO-ANALYSIS.md) | The design summarised for a reviewer: threat model, primitives, properties, limits and open questions |
| `test/interop.sh` | The stock-tools client and the Go client, together, against a real `irongalld` |
| `test/working-key-openssh.sh` | A measurement, not a test: what stock `ssh-keygen` does with a certificate an identity signs for a working key (the client repo's issue #30) |
| `Dockerfile` | `irongalld` as a static binary on Debian slim, and the echo box as a second target; it needs the client checkout as a build context named `client` |
| `bench/` | The measurements behind the microsecond figures |

A site's own pages (irongall.dev's front page and `llms.txt`) are not in this repo: a web server in front serves them and passes `/v1/` and `/to/` here.

## Build and run

`go.mod` replaces the client module with `../irongall-client`, so check the two out side by side:

```sh
git clone https://github.com/IronGall-dev/irongall-client
git clone https://github.com/IronGall-dev/irongall-server
cd irongall-server
go test ./...
go run ./cmd/irongalld serve --dev
```

`serve --dev` is the whole server on an in-memory store, with no AWS, listening on `127.0.0.1:8080`: nothing survives a restart. Point a client at it with `IRONGALL_BASE=http://127.0.0.1:8080`.

The other store is three DynamoDB tables and an S3 Express One Zone directory bucket. `irongalld serve -h` lists every flag, and `PROTOCOL-SERVER.md` §7 has the layout.

## Contributing

Every commit is signed off under the Developer Certificate of Origin: [`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

AGPL-3.0-or-later (`LICENSE`): the GNU Affero General Public License, version 3 or any later version.

Copyright (C) 2026 Drew Streib

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

The full text is in [`LICENSE`](LICENSE). The client, in its own repo, is Apache-2.0.
