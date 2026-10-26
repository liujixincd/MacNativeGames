# TOTK static cheats on macOS

The build can import **static main-module writes** from an Atmosphere-format
cheat file, including code-patch cheats commonly used by Ryujinx, Yuzu and Eden.
Keep the original `<16-digit build ID>.txt` filename. No cheats are bundled or
enabled automatically.

List the file's named cheats and which ones this importer supports:

```sh
python3 games/totk/scripts/cheat_mod.py "/path/to/BUILD_ID.txt" --list
```

Select each desired `[Name]` explicitly when building your Mac app:

```sh
python3 build_app.py "/path/to/TOTK.xci" -k "/path/to/prod.keys" \
  --cheats "/path/to/BUILD_ID.txt" --enable-cheat "Exact cheat name"
```

Repeat `--enable-cheat` to select more. With `--update`, the file must match the
updated game's build ID. Empty title sections are not selectable. `{Master}`
sections are included only when an ordinary cheat is explicitly selected; an
unsupported master rejects the selection too.

Supported instructions are `0T0000AA AAAAAAAA VALUE` (two value words for an
8-byte write), where T is 1, 2, 4 or 8 and the address is relative to main.
Values are converted to little-endian bytes. **These are applied once, before
the game starts.** Pointer chains, heap-relative writes, conditions, register
programs, loops and button activators require a runtime VM and are rejected.
There is no in-game cheat menu or periodic memory writer in this feature.

Selected writes become a `.pchtxt` mod before the original NSO is rewritten.
The normal build checks the retail file's hash, the exact NSO build ID, segment
bounds, conflicts and the runtime's reserved patch sites. The rewritten output
is then bound by hash as usual. Conflicting selections fail rather than silently
overriding each other. `--mod` can be combined with `--cheats`: its ExeFS patches
are copied into the generated code-mod folder, while its RomFS follows the normal
mod workflow. The original mod folder and cheat file are unchanged.

The work folder keeps a `cheats-selection.json` with the source SHA-256, full
build ID, selected names and generated patch SHA-256. The existing validation
report also records that selection under `cheats`, alongside `mod_exefs`.
The Mac app carries the selection record; its runtime makes a complete
`profile-before-cheats-<selection fingerprint>` backup before the first start
with that selection. The copy runs after acquiring the game-slot lock and before
loading guest code, so it cannot snapshot a save while the game or migration tool
is using that slot. A failed backup prevents startup. Direct launches of the
internal native binary receive the same protection.

To disable or change cheats, rebuild the app with a different selection, or omit
`--cheats` entirely. Rebuilding removes the code patches; it does not undo changes
the game already wrote to a save. Restore a profile backup to undo saved effects.
This importer currently rejects iOS and visionOS builds.
