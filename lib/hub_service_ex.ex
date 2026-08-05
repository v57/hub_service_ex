defmodule HubServiceEx do
  @moduledoc """
  HubServiceEx — Elixir port of the hub-service library (TS reference).

  Lets an Elixir process connect to a hub (hub-lite/hub-pro), host post/stream
  API endpoints, and call API through the hub. Lite port: no auth, no keychain,
  no crypto.

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
            settings: %{},
            conn: nil,
            sender: nil

  @type t :: %__MODULE__{}

  @doc """
  Creates a Service.

  Options:
    * `:address` — port integer or `ws://` URL (default: `1997` or `$HUB`)
    * `:name` — profile name shown in the hub
    * `:icon` — profile icon: a string or `%{symbol: ..., text: ...}`
  """
  def new(options \\ []) do
    address = normalize_address(options[:address] || System.get_env("HUB") || 1997)
    name = options[:name]
    icon = options[:icon]

    profile = if name || icon, do: build_profile(name, icon), else: nil

    %__MODULE__{channel: ChannelEx.new(), address: address, profile: profile}
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

        if settings[:limit] != nil, do: entry ++ [{"limit", settings[:limit]}], else: entry
      end)

    apps =
      Enum.map(service.apps, fn header ->
        [{"type", "app"}, {"name", header.name}, {"path", header.path}]
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
    %{service | paths: MapSet.put(service.paths, path)}
  end

  defp add_path(%__MODULE__{} = service, path, settings)
       when is_map(settings) or is_list(settings) do
    %{
      service
      | paths: MapSet.put(service.paths, path),
        settings: Map.put(service.settings, path, normalize_settings(settings, path))
    }
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
        if allows != nil, do: entry ++ [{"allows", allows}], else: entry
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
