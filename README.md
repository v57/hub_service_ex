# hub_service_ex

Elixir port of the [hub-service](https://github.com/v57/hub-service) library: connect to a hub
(hub-lite/hub-pro), host post/stream API endpoints, and call API through the hub.

Hub-pro auth is supported: every (re)connect sends `auth` + `v` headers signed by the ed25519
keychain (`auth` key file in the cwd, or `$HUBKEY`), bound to the hub's key once it is pinned
(`v: "1"`). hub-lite ignores the headers. Wire parity with the TS reference:
`hub/profile/update` and `hub/service/update` payloads are built as ordered jiffy objects so the
JSON bytes match the TS/Go ports exactly.

## Usage

```elixir
alias HubServiceEx, as: Service
alias HubServiceEx.App

service =
  Service.new(name: "Echo", icon: %{symbol: "speaker.wave.2", text: "E"})
  |> Service.post("echo", fn body -> body end)
  |> Service.post("echo/upper", fn body -> String.upcase(body) end)
  |> Service.app(
    App.new("Echo", "echo/ui", [
      App.text("Echo"),
      App.text_field("", placeholder: "Type something…"),
      App.cell(title: "Echo service"),
      App.button("Upper", App.action("echo/upper", body: "hello"))
    ])
  )
  |> Service.start()
```

Run the example: `mix run example/echo.exs`

## API

- `new(options \\ [])` — options: `:address` (port int or `ws://` string; default `1997` or `$HUB`),
  `:name`, `:icon` (string or `%{symbol: ..., text: ...}`), `:sign`, `:hub_key`.
- Hub-bound auth: the first connect uses `v: "0"`, asks `hub/info` for the hub key, pins it in
  `hubs.json` beside the key file and reconnects with `v: "1"` (`:hub_key` supplies it up front,
  `forget_hub_key/1` clears the pin, `last_error/1` reports a refused connect).
  `Keychain.sign/0` / `Keychain.sign_hub/1` make the tokens.
- `post(path, handler, settings \\ nil)` — request/response endpoint; handler receives the request
  body and returns the response. `settings` (wire parity, hub-lite ignores): `permissions:
  [group:, name:, allows:]` and `limit:`. If `permissions` is set and `group` is missing, group is
  auto-filled with the first path segment.
- `stream(path, handler, settings \\ nil)` — streaming endpoint; handler receives the body and
  returns an enumerable of values.
- `app(App)` — append the app header to the hub apps list and serve the AppInterface (all 5 keys:
  `header`/`body`/`top`/`bottom`/`data`) as a stream at the app path. The app path also appears in
  the services list.
- `send(path, body \\ nil)` — call an API through the hub; `{:ok, response} | {:error, reason}`.
  Raises `Service not started` when the service has not been started.
- `values(path, body \\ nil)` — stream call through the hub; returns a lazy `Stream`.
- `start()` — connect; on every (re)connect sends `hub/profile/update` (if name/icon set) then
  `hub/service/update`. Reconnects automatically (channel_ex's client does not auto-reconnect, so
  the service owns a reconnect loop; hub-lite drops a sender's services on disconnect).

Register paths before `start()` — the update payload is snapshotted at connect time (TS parity).

## Element helpers

`text/2`, `progress/2`, `text_field/2`, `button/2`, `slider/2`, `list/2`, `picker/2`, `cell/1`,
`files/3`, `file_operation/2`, `hstack/2`, `vstack/2`, `zstack/1`, `spacer/0` (plain strings are
shorthand text), `action/2` (`:body`, `:output`). Optional fields are keyword-list options.

## Development

- Unit tests: `mix test` (or `scripts/test`)
- Live verification against a hub on 1997:

```sh
mix run example/echo.exs &
bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
bun ../hub-service/tests/appcheck.ts echo/ui Echo
```

## License

MIT — see [LICENSE](LICENSE).
