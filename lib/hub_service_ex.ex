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
