# AWG runtime hardening v2

## Scope

This change is based on the current production source of truth and hardens
runtime discovery without replacing the existing AWG 3.1 implementation,
AWG Agent backend, AWG4 front door, server pool, AmneziaVPN artifacts or
XHTTP profiles.

It does not update the AWG Docker image and does not introduce a database
migration.

## Docker AWG runtime metadata

A successful runtime sync records:

- `interface` / `interface_ready`;
- discovered `command_bin` (`awg` or `wg`);
- `config_mtu` when the config explicitly contains MTU;
- `runtime_mtu` from `/sys/class/net/<iface>/mtu`;
- `mtu_mismatch`;
- `awg_generation` (`2.x`, `3.x`, `3.1`, or `unknown`);
- `awg_capabilities`;
- `awg_unknown_interface_keys`;
- `awg_export_compatible`.

Existing AWG 3.1 secret handling remains unchanged: HeaderProtectionKey is
stored in encrypted runtime metadata and decrypted only when an export needs
it.

## Fail-closed behavior

For Docker-backed AWG2, create/reissue must not mutate the current peer when:

- the new compatibility metadata has not been populated by runtime sync;
- an unknown active `[Interface]` key is present;
- required AWG metadata is missing;
- a protected AWG secret cannot be restored;
- config MTU and live interface MTU are both known and do not match.

These checks protect new config generation. They do not disconnect existing
peers.

The AWG Agent backend keeps its existing native artifact validation and
rollback workflow. Its compatibility metadata is informational and is not
used to replace those safeguards.

## Production rollout

1. Back up the application database/config and preserve the current
   production git SHA.
2. Deploy only the central `amnezia-control` code. Do not update or restart
   the `amnezia-awg2` image as part of this change.
3. Rebuild/restart the application services that load Python code
   (`web`, `worker`, `beat`) using the existing production procedure.
4. Run runtime sync before creating or reissuing any Docker-backed AWG2
   client.
5. Verify on the production AWG 3.1 server:
   - container remains running;
   - interface is `awg0`;
   - generation is `3.1`;
   - discovered CLI is valid (`awg` is expected on the current image);
   - runtime MTU is the expected value (currently 1376);
   - config/runtime MTU do not conflict;
   - no unknown active interface keys are reported;
   - export compatibility is enabled;
   - no private key, preshared key or HeaderProtectionKey appears in Jobs.
6. Create/reissue one disposable test connection and verify import,
   handshake and traffic.
7. Only after the smoke test, promote the candidate branch.

## Rollback

Rollback the central application to the preserved production SHA and rebuild
the application services. No AWG runtime/image rollback should be required
because this change does not modify the AWG image or existing peers during
runtime sync.

## Known limitation

The current AWG Agent bridge returns a curated set of runtime metadata.
Unknown-key visibility and live MTU discovery are therefore complete for the
Docker backend but limited for the agent backend until the bridge contract is
extended. The agent path continues to rely on its existing config/artifact
validation and runtime rollback safeguards.
