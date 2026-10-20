defmodule HubServiceEx.KeyFile do
  @moduledoc """
  An ed25519 key in the hub key file format (`Docs/Devices/protocol.md`
  section 1): base64 of the 48-byte PKCS8 DER private key followed by the
  44-byte SPKI DER public key (92 bytes). Service keys (`auth`) and the
  device key (`~/.hub/device.key`) both use it.
  """

  @private_der_length 48
  @public_der_length 44
  @seed_offset 16
  @seed_length 32

  # Fixed DER prefixes for ed25519 keys (RFC 8410):
  # PKCS8: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 },
  #                   OCTET STRING { OCTET STRING { 32-byte seed } } }
  # SPKI:  SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { pub } }
  @pkcs8_prefix <<0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B,
                  0x65, 0x70, 0x04, 0x22, 0x04, 0x20>>
  @spki_prefix <<0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03,
                 0x21, 0x00>>

  defstruct [:data]

  @type t :: %__MODULE__{data: binary}

  @doc "Parses key file text (base64, surrounding whitespace ignored). Raises `ArgumentError` with `label`."
  def parse!(text, label \\ "bad key file") when is_binary(text) do
    data =
      case Base.decode64(String.trim(text)) do
        {:ok, data} -> data
        :error -> raise ArgumentError, "#{label}: not base64"
      end

    expected = @private_der_length + @public_der_length

    cond do
      byte_size(data) != expected ->
        raise ArgumentError, "#{label}: expected #{expected} bytes, got #{byte_size(data)}"

      binary_part(data, 0, byte_size(@pkcs8_prefix)) != @pkcs8_prefix ->
        raise ArgumentError, "#{label}: PKCS8 private key prefix mismatch"

      binary_part(data, @private_der_length, byte_size(@spki_prefix)) != @spki_prefix ->
        raise ArgumentError, "#{label}: SPKI public key prefix mismatch"

      true ->
        %__MODULE__{data: data}
    end
  end

  @doc "A fresh random key."
  def generate do
    {public_raw, seed} = :crypto.generate_key(:eddsa, :ed25519, :undefined)
    %__MODULE__{data: @pkcs8_prefix <> seed <> @spki_prefix <> public_raw}
  end

  @doc "Reads the key file at `path`."
  def load!(path, label \\ nil) do
    parse!(File.read!(path), label || "bad key file #{path}")
  end

  @doc """
  Reads the key file at `path`, creating it if absent. With `secure`, the
  parent directory is created 0700 and the file written 0600 to a temp file
  renamed into place (device key rules, protocol.md section 3).
  """
  def load_or_create!(path, secure, label \\ nil) do
    if File.exists?(path) do
      load!(path, label)
    else
      key = generate()

      if secure do
        write_atomic!(path, text(key), true)
      else
        File.write!(path, text(key))
      end

      key
    end
  end

  @doc "The key file text: base64 of the 92 bytes."
  def text(%__MODULE__{data: data}), do: Base.encode64(data)

  @doc "The public key: base64 of the 44-byte SPKI DER."
  def public_key(%__MODULE__{data: data}) do
    data |> binary_part(@private_der_length, @public_der_length) |> Base.encode64()
  end

  @doc "Base64 ed25519 signature over the UTF-8 bytes of `text`."
  def sign(%__MODULE__{data: data}, text) when is_binary(text) do
    seed = binary_part(data, @seed_offset, @seed_length)
    :crypto.sign(:eddsa, :ed25519, text, [seed, :ed25519]) |> Base.encode64()
  end

  @doc false
  # Writes `text` to a temp file beside `path` and renames it into place.
  def write_atomic!(path, text, secure) do
    dir = path |> Path.expand() |> Path.dirname()

    unless File.dir?(dir) do
      File.mkdir_p!(dir)
      if secure, do: File.chmod!(dir, 0o700)
    end

    temp = Path.join(dir, ".#{Path.basename(path)}.#{System.unique_integer([:positive])}.tmp")

    try do
      File.touch!(temp)
      if secure, do: File.chmod!(temp, 0o600)
      File.write!(temp, text)
      File.rename!(temp, path)
    after
      File.rm(temp)
    end
  end
end
