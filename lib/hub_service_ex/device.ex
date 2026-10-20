defmodule HubServiceEx.Device do
  @moduledoc """
  Device identity (`Docs/Devices/protocol.md` sections 1 and 3).

  The device key is one ed25519 key per OS instance, in the key file format,
  at `$HUB_DEVICE_KEY`, `/var/lib/hub/device.key` for root, or
  `~/.hub/device.key` (directory 0700, file 0600, created atomically). It
  signs a short certificate for each service key it runs, sent in the
  `device` connection header next to `auth`.
  """

  alias HubServiceEx.{KeyFile, Keychain}

  @certificate_lifetime 7 * 24 * 3600
  @renew_before 24 * 3600

  @doc "Default certificate lifetime: 7 days."
  def certificate_lifetime, do: @certificate_lifetime

  @doc "A certificate with less than this left is renewed at connect: 24 hours."
  def renew_before, do: @renew_before

  @doc "The device key location: `$HUB_DEVICE_KEY`, root's system path, or `~/.hub/device.key`."
  def default_key_path do
    cond do
      (env = System.get_env("HUB_DEVICE_KEY")) not in [nil, ""] -> env
      System.get_env("USER") == "root" and match?({:unix, _}, :os.type()) -> "/var/lib/hub/device.key"
      true -> Path.join([System.user_home!(), ".hub", "device.key"])
    end
  end

  @doc "Loads the device key at `path`, creating it (0600, atomic) if absent."
  def load_or_create_key(path), do: KeyFile.load_or_create!(path, true)

  @doc "The device id: the first 32 lowercase hex characters of SHA-256 of the SPKI DER."
  def id(public_key), do: binary_part(hex(public_key), 0, 32)

  @doc ~s(The safety code shown while approving: `"ddd ddd"`.)
  def safety_code(public_key) do
    {n, ""} = public_key |> hex() |> binary_part(0, 8) |> Integer.parse(16)
    code = n |> rem(1_000_000) |> Integer.to_string() |> String.pad_leading(6, "0")
    binary_part(code, 0, 3) <> " " <> binary_part(code, 3, 3)
  end

  @doc "The suggested device name: the computer name on macOS, else the host name without `.local`."
  def default_name do
    computer_name =
      if default_platform() == "macos" do
        try do
          case System.cmd("scutil", ["--get", "ComputerName"], stderr_to_stdout: true) do
            {name, 0} -> String.trim(name)
            _ -> ""
          end
        rescue
          _ -> ""
        end
      else
        ""
      end

    if computer_name != "" do
      computer_name
    else
      case :inet.gethostname() do
        {:ok, name} -> name |> List.to_string() |> String.replace_suffix(".local", "")
        _ -> nil
      end
    end
  end

  @doc "The certificate `platform` for this OS."
  def default_platform do
    case :os.type() do
      {:unix, :darwin} -> "macos"
      {:unix, :linux} -> "linux"
      {:win32, _} -> "windows"
      _ -> "other"
    end
  end

  @doc """
  The certificate payload as an ordered list, fields in protocol order with
  optional ones omitted when nil: `v, device, service, instance, deviceName,
  platform, parent, iat, exp`.
  """
  def certificate_payload(device_key, service_key, instance, device_name, platform, parent, iat, exp) do
    [
      {"v", 1},
      {"device", device_key},
      {"service", service_key},
      {"instance", instance},
      {"deviceName", device_name},
      {"platform", platform},
      {"parent", parent},
      {"iat", iat},
      {"exp", exp}
    ]
    |> Enum.reject(fn {_key, value} -> is_nil(value) end)
  end

  @doc "Encodes a payload as `JSON.stringify` does: no whitespace, only quotes, backslashes and control characters escaped."
  def payload_json(payload) do
    fields = Enum.map_join(payload, ",", fn {key, value} -> json_string(key) <> ":" <> json_value(value) end)
    "{" <> fields <> "}"
  end

  @doc "Signs a certificate: `<base64url(JSON)>.<base64 signature>`, the signature covering the payload string."
  def certificate(%KeyFile{} = device_key, payload) do
    encoded = Base.url_encode64(payload_json(payload), padding: false)
    encoded <> "." <> KeyFile.sign(device_key, encoded)
  end

  @doc "Decodes the payload of a `device` header (no signature check)."
  def decode_certificate(header) do
    [encoded | _] = String.split(header, ".")
    encoded |> Base.url_decode64!(padding: false) |> Jason.decode!()
  end

  @doc false
  # A fresh certificate cache for `header/3`.
  def new_cache, do: %{key: nil, certificate: nil, expiry: 0, name: nil, off: false}

  @doc false
  # The `device` header for a connect of `service` and the updated cache: nil
  # with device mode off; the cached certificate while it has more than 24
  # hours left. A device key that can't be read or created turns it off.
  def header(service, cache, now \\ System.system_time(:second)) do
    cond do
      cache.off or not service.device or service.sign != nil ->
        {nil, cache}

      cache.certificate != nil and cache.expiry - now >= @renew_before ->
        {cache.certificate, cache}

      true ->
        try do
          key = cache.key || service.device_key || load_or_create_key(service.device_key_path || default_key_path())
          name = cache.name || service.device_name || default_name()
          exp = now + @certificate_lifetime

          payload =
            certificate_payload(
              KeyFile.public_key(key),
              Keychain.public_key(),
              HubServiceEx.instance(service),
              name,
              service.platform || default_platform(),
              service.parent,
              now,
              exp
            )

          header = certificate(key, payload)
          {header, %{cache | key: key, name: name, certificate: header, expiry: exp}}
        rescue
          error ->
            IO.puts(:stderr, "hub-service: device mode off: #{Exception.message(error)}")
            {nil, %{cache | off: true}}
        end
    end
  end

  defp json_value(value) when is_binary(value), do: json_string(value)
  defp json_value(value) when is_integer(value), do: Integer.to_string(value)

  defp json_string(value) do
    escaped =
      for <<c::utf8 <- value>>, into: "" do
        case c do
          ?" -> "\\\""
          ?\\ -> "\\\\"
          ?\b -> "\\b"
          ?\f -> "\\f"
          ?\n -> "\\n"
          ?\r -> "\\r"
          ?\t -> "\\t"
          c when c < 0x20 -> "\\u" <> String.pad_leading(Integer.to_string(c, 16) |> String.downcase(), 4, "0")
          c -> <<c::utf8>>
        end
      end

    "\"" <> escaped <> "\""
  end

  defp hex(public_key) do
    :crypto.hash(:sha256, Base.decode64!(public_key)) |> Base.encode16(case: :lower)
  end
end
