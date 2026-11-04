defmodule HubServiceEx.HubProof do
  @moduledoc """
  Auth v2's client side (`Docs/Devices/protocol.md` section 2): before every
  connect the SDK asks `hub/info` on an anonymous connection with a fresh nonce,
  and sends its token only if the hub proved the key it claims, over that nonce.
  """

  @address ~r/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/(?:[^\/?#@]*@)?(\[[^\]]*\]|[^\/?#:]*)/

  @doc """
  Classifies an address (a port or a URL) before anything is dialed:
  `:encrypted`, `:loopback`, `:overlay`, `:local_network` or `:refused`.
  `:refused` is plain `ws://` beyond loopback, the overlay and the LAN: it isn't
  dialed unless `:allow_plaintext` says so.
  """
  def transport_of(port) when is_integer(port), do: :loopback

  def transport_of(address) when is_binary(address) do
    text = String.trim(address)

    cond do
      text =~ ~r/^\d+$/ ->
        :loopback

      match = Regex.run(@address, text) ->
        [_, scheme, host] = match
        transport(String.downcase(scheme), host |> String.downcase() |> String.trim_trailing("."))

      true ->
        :refused
    end
  end

  defp transport(scheme, _host) when scheme in ["wss", "https", "quic"], do: :encrypted

  defp transport(scheme, host) when scheme in ["ws", "http"] do
    cond do
      String.starts_with?(host, "[") -> transport_v6(String.slice(host, 1..-2//1))
      bytes = ipv4(host) -> transport_v4(bytes)
      host == "localhost" or String.ends_with?(host, ".localhost") -> :loopback
      String.ends_with?(host, ".hub.invalid") -> :overlay
      String.ends_with?(host, ".local") -> :local_network
      true -> :refused
    end
  end

  defp transport(_scheme, _host), do: :refused

  defp transport_v6("::1"), do: :loopback

  defp transport_v6(host) do
    if host =~ ~r/^(f[cd]|fe[89ab])/, do: :local_network, else: :refused
  end

  defp transport_v4([127, _]), do: :loopback
  defp transport_v4([100, b]) when b in 64..127, do: :overlay
  defp transport_v4([10, _]), do: :local_network
  defp transport_v4([172, b]) when b in 16..31, do: :local_network
  defp transport_v4([192, 168]), do: :local_network
  defp transport_v4([169, 254]), do: :local_network
  defp transport_v4(_), do: :refused

  defp ipv4(host) do
    parts = String.split(host, ".")

    if length(parts) == 4 and Enum.all?(parts, &(&1 =~ ~r/^\d{1,3}$/)) do
      bytes = Enum.map(parts, &String.to_integer/1)
      if Enum.all?(bytes, &(&1 <= 255)), do: Enum.take(bytes, 2)
    end
  end

  @doc "The nonce for one `hub/info`: 32 fresh random bytes in base64url."
  def make_client_nonce, do: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

  @doc "The string a `hub/info` proof signs."
  def signed_data(hub_key, nonce), do: "hubinfo1:#{hub_key}:#{nonce}"

  @doc """
  Whether a `hub/info` answer proves its key over `nonce`. A relayed answer
  passes too, so it never decides which credentials a hub gets.
  """
  def proves?(%{"key" => key, "proof" => proof, "challenge" => challenge}, nonce)
      when is_binary(key) and is_binary(proof) and is_binary(challenge) do
    with {:ok, public_der} <- Base.decode64(key),
         {:ok, signature} <- Base.decode64(proof),
         <<0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, raw::binary-size(32)>> <- public_der do
      :crypto.verify(:eddsa, :ed25519, signed_data(key, nonce), signature, [raw, :ed25519])
    else
      _ -> false
    end
  rescue
    _ -> false
  end

  def proves?(_info, _nonce), do: false

  @doc """
  Asks the hub at `address` for its key and a challenge, on a short anonymous
  connection. Returns `{:ok, %{"key" => .., "challenge" => ..}}` only with a valid
  proof, else `{:error, message}`.
  """
  def ask(address, timeout \\ 5_000) do
    nonce = make_client_nonce()

    case ChannelEx.connect(ChannelEx.new(), address, connect_timeout: timeout) do
      %ChannelEx.ClientSender{} = client ->
        try do
          case ChannelEx.send(client, "hub/info", %{"nonce" => nonce}, nil, timeout) do
            {:ok, info} ->
              if proves?(info, nonce), do: {:ok, info}, else: {:error, "the hub didn't prove its key"}

            {:error, reason} ->
              {:error, "hub/info: #{describe(reason)}"}
          end
        after
          ChannelEx.ClientSender.stop(client)
        end

      {:error, reason} ->
        {:error, describe(reason)}
    end
  end

  defp describe(reason) when is_binary(reason), do: reason
  defp describe(reason), do: inspect(reason)
end
