defmodule HubServiceEx.HubPins do
  @moduledoc """
  Pinned hub keys (`Docs/Devices/protocol.md` section 2): the file `hubs.json`
  beside the service key file, a JSON object `{"<address>": "<hub SPKI>"}`
  keyed by the normalized address (`HubServiceEx.normalize_address/1`). A
  service learns a hub's key from `hub/info` on its first (v0) connection and
  signs v1 tokens bound to it from then on.
  """

  @doc "The pin file beside `key_path`."
  def beside(key_path) do
    key_path |> Path.expand() |> Path.dirname() |> Path.join("hubs.json")
  end

  @doc "The pinned key for `address` in the pin file `path`, or nil."
  def get(path, address) do
    case Map.get(read(path), address) do
      key when is_binary(key) -> key
      _ -> nil
    end
  end

  @doc "Pins `hub_key` for `address`."
  def put(path, address, hub_key) do
    path |> read() |> Map.put(address, hub_key) |> write(path)
  end

  @doc "Forgets the pinned key for `address`."
  def remove(path, address) do
    pins = read(path)
    if Map.has_key?(pins, address), do: pins |> Map.delete(address) |> write(path)
    :ok
  end

  # A corrupt pin file counts as empty: the next hub/info pins again.
  defp read(path) do
    with {:ok, text} <- File.read(path),
         {:ok, %{} = pins} <- Jason.decode(text) do
      pins
    else
      _ -> %{}
    end
  end

  defp write(pins, path) do
    HubServiceEx.KeyFile.write_atomic!(path, Jason.encode!(pins), false)
  end
end
