defmodule HubServiceEx.Keychain do
  @moduledoc """
  ed25519 keychain: load-or-generate the `auth` key file and sign tokens.

  Hub-pro auth parity with the TS reference (hub-service/keychain.ts):

  - The key file (`auth` in the working directory, matching the TS keychain)
    is the base64 encoding of the 48-byte PKCS8 DER ed25519 private key
    followed by the 44-byte SPKI DER public key (92 bytes total, 124 base64
    chars). If the file is missing it is generated on first use.
  - A signed token has the shape `key.<pub>.<sig>.<expiry>` where:
      pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
      sig     = base64 ed25519 signature over the expiry string
      expiry  = DECIMAL epoch-seconds string of now + 10 (TS parity;
                hub-pro reads it as base-36, so the decimal form never
                trips the expiry check)
  - The hub verifies the signature against the embedded public key and
    treats the key as the connection identity (owner/host/group).

  Crypto backend: OTP's `:crypto` NIF (ed25519, RFC 8032). The key file
  layout is identical to the TS/Python/Ruby ports either way.

  Usage:

      token = HubServiceEx.Keychain.sign()      # fresh token for a connect
      pub = HubServiceEx.Keychain.public_key()  # the service's public key
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

  @doc """
  Overrides the key file location (default: `auth` in the cwd, or `$HUBKEY`).
  """
  def set_key_path(path) when is_binary(path) do
    :persistent_term.put({__MODULE__, :key_path}, path)
    :ok
  end

  @doc "Forgets any configured key path (back to `auth` in cwd / `$HUBKEY`)."
  def reset do
    :persistent_term.erase({__MODULE__, :key_path})
    :ok
  end

  @doc "The service's public key: base64 of the 44-byte SPKI DER public key."
  def public_key do
    key_bytes()
    |> binary_part(@private_der_length, @public_der_length)
    |> Base.encode64()
  end

  @doc """
  A fresh auth token: `key.<pub>.<sig>.<expiry>`.

  `expires` is the token lifetime in seconds (default 10, TS parity). The
  signed payload is the decimal expiry string itself.
  """
  def sign(expires \\ 10) when is_integer(expires) do
    bytes = key_bytes()
    expiry = "#{System.system_time(:second) + expires}"
    seed = binary_part(bytes, @seed_offset, @seed_length)
    pub = binary_part(bytes, @private_der_length, @public_der_length)
    signature = :crypto.sign(:eddsa, :ed25519, expiry, [seed, :ed25519])
    "key.#{Base.encode64(pub)}.#{Base.encode64(signature)}.#{expiry}"
  end

  defp key_path do
    case :persistent_term.get({__MODULE__, :key_path}, :__unset__) do
      :__unset__ -> System.get_env("HUBKEY") || "auth"
      path -> path
    end
  end

  defp key_bytes do
    path = key_path()

    if File.exists?(path) do
      load(path)
    else
      generate(path)
    end
  end

  defp load(path) do
    data = path |> File.read!() |> String.trim() |> Base.decode64!()

    expected = @private_der_length + @public_der_length

    if byte_size(data) != expected do
      raise ArgumentError,
            "bad auth file #{path}: expected #{expected} bytes, got #{byte_size(data)}"
    end

    if binary_part(data, 0, byte_size(@pkcs8_prefix)) != @pkcs8_prefix do
      raise ArgumentError, "bad auth file #{path}: PKCS8 private key prefix mismatch"
    end

    if binary_part(data, @private_der_length, byte_size(@spki_prefix)) != @spki_prefix do
      raise ArgumentError, "bad auth file #{path}: SPKI public key prefix mismatch"
    end

    data
  end

  defp generate(path) do
    {public_raw, seed} = :crypto.generate_key(:eddsa, :ed25519, :undefined)
    data = @pkcs8_prefix <> seed <> @spki_prefix <> public_raw
    File.write!(path, Base.encode64(data))
    data
  end
end
