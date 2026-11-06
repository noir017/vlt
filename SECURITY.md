# Security policy

## Reporting

Open a private security advisory on this repository, or email the address in
the git commit metadata. Please do not open a public issue for a vulnerability.

## Threat model

`vlt` protects secrets from four places they usually leak:

1. **Process arguments.** No command accepts a secret on the command line.
   Values enter through stdin, a `0600` file, or `--generate`.
2. **Terminal output.** Secret fields are masked by default and refuse to print
   to a TTY unless `--stdout` or `--reveal` is given.
3. **Logs and error messages.** The tool writes no log file. Every error string
   is passed through a redactor that removes values already handled.
4. **Child processes.** `vlt run` injects values into the environment, not the
   command line.

It does **not** protect against:

- Anyone who can read the master password file. That file is the account.
- Same-uid processes that inspect another process's environment or memory.
- A compromised server: the server sees the password hash and all ciphertext,
  and can serve malicious code to any client.
- Traffic interception on plain HTTP. Use HTTPS outside a trusted network.

## Token cache

The access token is a bearer credential. It is stored with mode `0600` under
`$XDG_CACHE_HOME/vlt/session.json`, expires after at most 15 minutes, and is
scoped to the server and account that created it. `vlt lock` deletes it.
Set `VLT_CACHE` to a path on an ephemeral filesystem if you do not want it on
disk at all.
