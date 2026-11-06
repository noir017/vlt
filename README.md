# vlt

`vlt` is a command-line client for a self-hosted [Vaultwarden](https://github.com/dani-garcia/vaultwarden)
account, built for automation. It reads, writes and searches secrets without
putting them on a command line, in a log, or on your terminal unless you
explicitly ask for it.

Single static binary, no runtime dependencies. Talks to the Bitwarden-compatible
API directly — no official CLI, no Node, no Python.

## Install

Download the archive for your platform from
[Releases](https://github.com/noir017/vlt/releases), unpack, and put `vlt`
somewhere on `PATH`.

Or build from source:

```sh
go build -trimpath -ldflags "-s -w" -o vlt ./cmd/vlt
```

## Configure

Create `~/.secrets/vlt.env` (mode `0600`, directory `0700`):

```sh
BW_SERVER=https://vault.example.com
BW_EMAIL=agent@example.com
BW_PASSWORD=...
```

`BW_PASSWORD_FILE` may point at a separate file instead of `BW_PASSWORD`.
The tool refuses to run if the file is readable by group or others.
`VLT_CONFIG` overrides the path; `VLT_CACHE` overrides the token cache
location.

## Use

```sh
# write: the value comes from stdin, never from the argument list
printf '%s' "$NEW_PASSWORD" | vlt set svc/gitea --username root \
    --uri https://gitea.example.com --password-stdin

# read metadata, then one field
vlt get svc/gitea
vlt get --id 5f0c... --field password --stdout
vlt get svc/gitea --field password --stdout | sshpass -e ...
vlt get svc/gitea --field totp --stdout          # current 6-digit code
vlt get svc/gitea --field totp-secret --stdout   # the raw seed

# search
vlt ls gitea
vlt find example.com --json          # includes each item id

# update, rename, delete
printf '%s' "$NEW" | vlt set svc/gitea --password-stdin   # upsert, keeps other fields
vlt mv svc/gitea svc/gitea-old
vlt rm svc/gitea-old svc/retired --yes                    # several at once, to the trash
vlt rm --id 5f0c... --yes

# trash (vlt never deletes permanently)
vlt trash                       # list what is in it
vlt restore svc/gitea-old       # put it back

# inject into a child process environment (not argv)
vlt run --env TOKEN=api/newapi.password -- curl -H "Authorization: Bearer $TOKEN" ...
vlt run --env TOKEN=api/newapi -- ...            # field defaults to password

# housekeeping
vlt rm svc/gitea --yes
vlt doctor
vlt lock
```

`vlt set` is an upsert: an existing name is updated, a missing one is created.
Items live in folder `agent` unless `--folder` says otherwise.

Long values (recovery codes, private keys) go in notes:

```sh
vlt set id/aws --type note --note-file ~/aws-recovery.txt
vlt get id/aws --field notes --stdout > ~/aws-recovery.txt
```

TOTP secrets may be an `otpauth://` URI or bare base32:

```sh
printf '%s' 'JBSWY3DPEHPK3PXP' | vlt set svc/x --totp-stdin
```

## Security model

- Secret values are accepted from stdin, a `0600` file, or `--generate`. There
  is no password flag, so nothing sensitive appears in `ps` or shell history.
- Secret fields are masked in the default output. Printing one to a terminal
  requires `--stdout` or `--reveal`; `--stdout` is the pipe-friendly path.
- No plaintext cache: the only thing on disk is a short-lived access token
  (`~/.cache/vlt/session.json`, `0600`, at most 15 minutes). `vlt lock` removes
  it immediately.
- `vlt run` passes values through the child's environment, never its argv.
  Same-uid processes can still read a process environment; that boundary is the
  operating system's, not the tool's.
- The master password file is the real secret. Anyone who can read it owns the
  account.
- Prefer HTTPS. Plain HTTP is acceptable only on a trusted network.

## Exit codes

| code | meaning |
|---|---|
| 0 | success |
| 1 | general error |
| 2 | usage error |
| 3 | item not found |
| 4 | authentication failed |
| 5 | network or server unreachable |

## Development

```sh
make check   # gofmt, vet, test
make build
```

Releases are cut by pushing a `v*` tag; `.github/workflows/release.yml` runs
GoReleaser for every supported GOOS/GOARCH pair.

## License

MIT
