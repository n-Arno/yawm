Yet Another Wireguard Mesh
==========================

Using any generated `uuid` to identify a single mesh (max 100 at the same time), nodes can:
- `register` themselves (they will be identified by their source IP)
- `get` their own config (including all other registered nodes as peers)

All data (registered nodes and keys) expire after 5 minutes.

`X-Auth-Token` header for authentification is sourced from environment variable `APP_TOKEN`

**Use-case**

This tool can be used in a Cloud-Init script during a Terraform execution to:
- register nodes once they are up
- wait a minute or two for everyone
- get the config and install/start Wireguard
