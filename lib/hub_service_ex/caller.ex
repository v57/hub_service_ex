defmodule HubServiceEx.Caller do
  @moduledoc """
  Who is calling, as the hub reports it in `context.hub.caller`
  (`Docs/Devices/protocol.md` section 4). The hub replaces any `context.hub`
  a client sent, and services accept requests only from the hub connection,
  so handlers can trust it.

    * `:key` — the caller's service SPKI; nil for anonymous callers
    * `:device_id`, `:device_name` — the caller's device; nil unless its
      connection is device-attached
    * `:groups` — every group the key or its device belongs to
    * `:owner` — whether the caller is in the owners group
    * `:via`, `:claimed` — through a merged hub: the merged hub's SPKI and
      its own (unverified) caller
    * `:raw` — the `caller` map as received
  """

  defstruct key: nil, device_id: nil, device_name: nil, groups: [], owner: false, via: nil, claimed: nil, raw: %{}

  @type t :: %__MODULE__{}

  @doc "The caller in a request context, or nil when the hub sent none (hub-lite, older hub-pro)."
  def from_context(%{"hub" => %{"caller" => caller}}), do: from(caller)
  def from_context(_context), do: nil

  @doc "Parses a `caller` map, or nil if it isn't one."
  def from(%{} = caller) do
    device = if is_map(caller["device"]), do: caller["device"], else: %{}

    %__MODULE__{
      key: string(caller["key"]),
      device_id: string(device["id"]),
      device_name: string(device["name"]),
      groups: if(is_list(caller["groups"]), do: Enum.filter(caller["groups"], &is_binary/1), else: []),
      owner: caller["owner"] == true,
      via: string(caller["via"]),
      claimed: from(caller["claimed"]),
      raw: caller
    }
  end

  def from(_value), do: nil

  @doc "The hub's SPKI from a request context (`context.hub.hubKey`), or nil."
  def hub_key(%{"hub" => %{"hubKey" => key}}) when is_binary(key), do: key
  def hub_key(_context), do: nil

  @doc "Whether the caller's connection is attached to a device."
  def device?(%__MODULE__{device_id: id}), do: id != nil

  defp string(value) when is_binary(value), do: value
  defp string(_value), do: nil
end

defmodule HubServiceEx.Request do
  @moduledoc """
  A request handed to post and stream handlers registered with a
  `fn body, request -> ... end` handler.

    * `:path` — the API path called
    * `:body` — the request body
    * `:caller` — who is calling (`context.hub.caller`); nil when the hub sent none
    * `:hub_key` — the forwarding hub's SPKI (`context.hub.hubKey`); nil when the hub sent none
    * `:context` — the whole request context (selection keys such as `service` and `device` included)
  """

  alias HubServiceEx.Caller

  defstruct [:path, :body, :caller, :hub_key, context: %{}]

  @type t :: %__MODULE__{}

  @doc false
  def from(%{path: path, body: body} = request) do
    context = if is_map(request[:context]), do: request.context, else: %{}

    %__MODULE__{
      path: path,
      body: body,
      caller: Caller.from_context(context),
      hub_key: Caller.hub_key(context),
      context: context
    }
  end
end
