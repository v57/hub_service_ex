defmodule HubServiceEx do
  @moduledoc """
  HubServiceEx — Elixir port of the hub-service library (TS reference).

  Lets an Elixir process connect to a hub (hub-lite/hub-pro), host post/stream
  API endpoints, and call API through the hub. Every connection carries
  hub-pro auth headers (a freshly signed keychain token + `v`); hub-lite
  ignores them (regression-safe).

  Hub-bound auth (`Docs/Devices/protocol.md` section 2): with no pinned key
  for the address, the service connects with `v: "0"`, calls `hub/info`, pins
  the returned key in `hubs.json` beside the key file and reconnects at once
  with `v: "1"` tokens signed over `hub1:<hub key>:<expiry>`. A hub that
  doesn't answer `hub/info` (hub-lite) keeps getting v0. A refused v1 connect
  is reported (`last_error/1`), never silently downgraded; call
  `forget_hub_key/1` when the hub key really changed.

  Device mode (protocol.md section 3, on by default): every connect also
  carries a `device` header, a certificate for the service key signed by the
  device key (`HubServiceEx.Device`). It is created at connect when missing
  or with less than 24 hours left (7-day lifetime). A device key that can't
  be read or created turns device mode off for this service.

  Wire parity: `hub/profile/update` and `hub/service/update` payloads are built
  as ordered jiffy objects (tuple-wrapped proplists) so the JSON bytes match the
  TS reference exactly.
  """

  alias HubServiceEx.Connection

  defstruct channel: nil,
            address: 1997,
            profile: nil,
            apps: [],
            paths: MapSet.new(),
            path_order: [],
            settings: %{},
            sign: nil,
            hub_key: nil,
            pins: nil,
            device: true,
            device_key: nil,
            device_key_path: nil,
            instance: nil,
            device_name: nil,
            platform: nil,
            parent: nil,
            conn: nil,
            sender: nil

  @type t :: %__MODULE__{}

  @doc """
  Creates a Service.

  Options:
    * `:address` — port integer or `ws://` URL (default: `1997` or `$HUB`)
    * `:name` — profile name shown in the hub
    * `:icon` — profile icon: a string or `%{symbol: ..., text: ...}`
    * `:sign` — 0-arity fun returning a fresh hub-pro auth token (default:
      the keychain — the `auth` key file in the cwd — signing v1 tokens once
      the hub key is pinned). A custom fun always connects with `v: "0"`.
    * `:hub_key` — the hub's SPKI if known up front (invitation or config);
      default: learn and pin it via `hub/info`
    * `:device` — device mode: send a device certificate with every connect
      (default `true`)
    * `:device_key` — a caller-provided `HubServiceEx.KeyFile` (e.g. kept in
      an app's own keychain); default: the device key file
    * `:device_key_path` — the device key file; default
      `HubServiceEx.Device.default_key_path/0`
    * `:instance` — the instance name on this device (`s3-local/Backup Disk`);
      default: the profile name, else the first segment of the first
      registered path, else `service`
    * `:device_name` — the suggested device name; default: the computer name
    * `:platform` — the certificate platform; default: this OS
    * `:parent` — the declared parent device name (containers and VMs)
  """
  def new(options \\ []) do
    address = normalize_address(options[:address] || System.get_env("HUB") || 1997)
    name = options[:name]
    icon = options[:icon]
    sign = options[:sign]
    pins = if sign, do: nil, else: HubServiceEx.HubPins.beside(HubServiceEx.Keychain.key_path())
    hub_key = options[:hub_key] || (pins && HubServiceEx.HubPins.get(pins, normalize_hub_address(address)))

    profile = if name || icon, do: build_profile(name, icon), else: nil

    %__MODULE__{
      channel: ChannelEx.new(),
      address: address,
      profile: profile,
      sign: sign,
      hub_key: hub_key,
      pins: pins,
      device: Keyword.get(options, :device, true),
      device_key: options[:device_key],
      device_key_path: options[:device_key_path],
      instance: options[:instance],
      device_name: options[:device_name],
      platform: options[:platform],
      parent: options[:parent]
    }
  end

  @doc """
  The instance name the certificate carries: the `:instance` option, else
  the profile name, else the first segment of the first registered path,
  else `service`.
  """
  def instance(%__MODULE__{} = service) do
    profile_name =
      case service.profile do
        {fields} -> List.keyfind(fields, "name", 0) |> then(&(&1 && elem(&1, 1)))
        _ -> nil
      end

    cond do
      service.instance not in [nil, ""] -> service.instance
      profile_name not in [nil, ""] -> profile_name
      service.path_order != [] -> service.path_order |> List.last() |> String.split("/") |> hd()
      true -> "service"
    end
  end

  @doc """
  The headers for one connect, as the connection sends them: `auth_headers/2`
  plus the `device` header (a fresh certificate; the connection reuses its
  certificate across reconnects until renewal).
  """
  def connect_headers(%__MODULE__{} = service) do
    {device, _cache} = HubServiceEx.Device.header(service, HubServiceEx.Device.new_cache())
    auth_headers(service, :current, device)
  end

  @doc """
  The hub key v1 tokens are bound to, or nil while connecting with v0. Once
  started, this is the connection's current key.
  """
  def hub_key(%__MODULE__{conn: nil, hub_key: hub_key}), do: hub_key
  def hub_key(%__MODULE__{conn: conn}), do: Connection.hub_key(conn)

  @doc "The last connect error (e.g. a refused v1 connect), or nil."
  def last_error(%__MODULE__{conn: nil}), do: nil
  def last_error(%__MODULE__{conn: conn}), do: Connection.last_error(conn)

  @doc """
  Clears the pinned hub key for this address, so the next connect uses v0
  and pins whatever key `hub/info` returns. Use it when a hub's key changed
  on purpose. Returns the updated service.
  """
  def forget_hub_key(%__MODULE__{} = service) do
    if service.pins, do: HubServiceEx.HubPins.remove(service.pins, address_key(service))
    if service.conn, do: Connection.forget_hub_key(service.conn)
    %{service | hub_key: nil}
  end

  @doc "The address as `hubs.json` keys it (`normalize_hub_address/1`)."
  def address_key(%__MODULE__{address: address}), do: normalize_hub_address(address)

  @doc """
  Normalizes a hub address like channel TS does (protocol.md section 2): a
  bare port becomes `ws://localhost:<port>`; a URL keeps its form with the
  scheme and host lowercased and no trailing slash.
  """
  def normalize_hub_address(port) when is_integer(port), do: "ws://localhost:#{port}"

  def normalize_hub_address(address) when is_binary(address) do
    text = String.trim(address)

    cond do
      text =~ ~r/^\d+$/ ->
        "ws://localhost:#{text}"

      String.contains?(text, "://") ->
        [scheme, rest] = String.split(text, "://", parts: 2)

        {authority, path} =
          case String.split(rest, "/", parts: 2) do
            [authority, path] -> {authority, "/" <> path}
            [authority] -> {authority, ""}
          end

        String.trim_trailing(String.downcase(scheme) <> "://" <> String.downcase(authority) <> path, "/")

      true ->
        String.trim_trailing(text, "/")
    end
  end

  @doc """
  The hub-pro headers for one connect with `hub_key`: a fresh token and the
  protocol version, `"1"` with a token bound to the hub key, else `"0"`.
  """
  def auth_headers(%__MODULE__{} = service, hub_key \\ :current, device \\ nil) do
    hub_key = if hub_key == :current, do: service.hub_key, else: hub_key

    headers =
      cond do
        service.sign -> %{"auth" => service.sign.(), "v" => "0"}
        hub_key -> %{"auth" => HubServiceEx.Keychain.sign_hub(hub_key), "v" => "1"}
        true -> %{"auth" => HubServiceEx.Keychain.sign(), "v" => "0"}
      end

    if device, do: Map.put(headers, "device", device), else: headers
  end

  @doc """
  Registers a request/response API endpoint. `handler` receives the request
  body and returns the response. `settings` (optional) is a keyword list or map
  with `:permissions` (`group`/`name`/`allows`) and `:limit` (wire parity;
  hub-lite ignores them).
  """
  def post(%__MODULE__{} = service, path, handler, settings \\ nil)
      when is_binary(path) and is_function(handler, 1) do
    service = add_path(service, path, settings)
    channel = ChannelEx.post(service.channel, path, fn request -> handler.(request.body) end)
    %{service | channel: channel}
  end

  @doc """
  Registers a streaming API endpoint. `handler` receives the request body and
  returns an enumerable of values to emit.
  """
  def stream(%__MODULE__{} = service, path, handler, settings \\ nil)
      when is_binary(path) and is_function(handler, 1) do
    service = add_path(service, path, settings)

    channel =
      ChannelEx.stream(service.channel, path, fn request -> handler.(request.body) end)

    %{service | channel: channel}
  end

  @doc """
  Registers an app: its header is appended to the hub apps list and its path
  serves the AppInterface (all 5 keys: header/body/top/bottom/data) as a
  stream. The app path is also callable and appears in the services list.
  """
  def app(%__MODULE__{} = service, %HubServiceEx.App{} = app) do
    service = %{service | apps: service.apps ++ [app.header]}
    service = add_path(service, app.header.path, nil)
    interface = HubServiceEx.App.interface(app)

    channel =
      ChannelEx.stream(service.channel, app.header.path, fn _request -> [interface] end)

    %{service | channel: channel}
  end

  @doc """
  Calls an API through the hub. Raises if the service has not been started.
  Returns `{:ok, response}` or `{:error, reason}`.
  """
  def send(service, path, body \\ nil, context \\ nil, timeout \\ 5_000)

  def send(%__MODULE__{conn: nil}, _path, _body, _context, _timeout) do
    raise "Service not started"
  end

  def send(%__MODULE__{conn: conn}, path, body, context, timeout) do
    sender = Connection.sender(conn)
    ChannelEx.send(sender, path, body, context, timeout)
  end

  @doc """
  Opens a stream call through the hub. Raises if the service has not been
  started. Returns a lazy `Stream` of values.
  """
  def values(service, path, body \\ nil, context \\ nil)

  def values(%__MODULE__{conn: nil}, _path, _body, _context) do
    raise "Service not started"
  end

  def values(%__MODULE__{conn: conn}, path, body, context) do
    sender = Connection.sender(conn)
    ChannelEx.values(sender, path, body, context)
  end

  @doc """
  Connects to the hub. On every (re)connect sends `hub/profile/update` (if a
  profile is set) then `hub/service/update`. Reconnects automatically.
  """
  def start(%__MODULE__{conn: nil} = service) do
    {:ok, conn} = Connection.start_link(service)
    sender = Connection.sender(conn)
    %{service | conn: conn, sender: sender}
  end

  def start(%__MODULE__{} = service), do: service

  @doc """
  hub/profile/update payload (ordered jiffy object), or `nil` when no profile
  (name/icon) is set.
  """
  def profile_payload(%__MODULE__{profile: nil}), do: nil
  def profile_payload(%__MODULE__{profile: profile}), do: profile

  @doc """
  hub/service/update payload: ordered jiffy object with one services entry per
  registered path (sorted by path) plus the apps list (`type` always `"app"`).
  """
  def update_payload(%__MODULE__{} = service) do
    services =
      service.paths
      |> Enum.sort()
      |> Enum.map(fn path ->
        settings = Map.get(service.settings, path, [])

        entry = [{"path", path}]

        entry =
          if settings[:permissions],
            do: entry ++ [{"permissions", settings[:permissions]}],
            else: entry

        entry =
          if settings[:limit] != nil,
            do: entry ++ [{"limit", settings[:limit]}],
            else: entry

        {entry}
      end)

    apps =
      Enum.map(service.apps, fn header ->
        {[{"type", "app"}, {"name", header.name}, {"path", header.path}]}
      end)

    {[{"services", services}, {"apps", apps}]}
  end

  @doc false
  def send_updates(%__MODULE__{} = service, sender) do
    if service.profile do
      ChannelEx.Sender.request(sender, "hub/profile/update", service.profile, nil)
    end

    ChannelEx.Sender.request(sender, "hub/service/update", update_payload(service), nil)
    :ok
  end

  defp add_path(%__MODULE__{} = service, path, nil) do
    %{service | paths: MapSet.put(service.paths, path), path_order: remember_path(service, path)}
  end

  defp add_path(%__MODULE__{} = service, path, settings)
       when is_map(settings) or is_list(settings) do
    %{
      service
      | paths: MapSet.put(service.paths, path),
        path_order: remember_path(service, path),
        settings: Map.put(service.settings, path, normalize_settings(settings, path))
    }
  end

  # Registration order, newest first (the instance defaults to the oldest).
  defp remember_path(service, path) do
    if path in service.path_order, do: service.path_order, else: [path | service.path_order]
  end

  defp normalize_settings(settings, path) do
    settings = if is_map(settings), do: Map.to_list(settings), else: settings
    permissions = Keyword.get(settings, :permissions)
    limit = Keyword.get(settings, :limit)

    permissions =
      if permissions do
        permissions = if is_map(permissions), do: Map.to_list(permissions), else: permissions
        group = Keyword.get(permissions, :group)
        name = Keyword.get(permissions, :name)
        allows = Keyword.get(permissions, :allows)
        group = if group in [nil, ""], do: path |> String.split("/") |> hd(), else: group

        entry = [{"group", group}]
        entry = if name, do: entry ++ [{"name", name}], else: entry
        entry = if allows != nil, do: entry ++ [{"allows", allows}], else: entry
        {entry}
      end

    out = []
    out = if permissions, do: out ++ [permissions: permissions], else: out
    if limit != nil, do: out ++ [limit: limit], else: out
  end

  defp build_profile(name, icon) do
    entry = []
    entry = if name, do: entry ++ [{"name", name}], else: entry
    entry = if icon, do: entry ++ [{"icon", icon}], else: entry
    {entry}
  end

  defp normalize_address(address) when is_binary(address) do
    case Integer.parse(address) do
      {port, ""} when port > 0 -> port
      _ -> address
    end
  end

  defp normalize_address(address), do: address
end
