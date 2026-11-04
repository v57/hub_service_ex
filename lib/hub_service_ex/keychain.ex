defmodule HubServiceEx.Keychain do
  @moduledoc """
  ed25519 keychain: load-or-generate the `auth` key file and sign tokens.

  hub-server auth parity with the TS reference (hub-service/keychain.ts) and
  `Docs/Devices/protocol.md` section 2:

  - The key file (`auth` in the working directory, or `$HUBKEY`) is the
    base64 encoding of the 48-byte PKCS8 DER ed25519 private key followed by
    the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars). If the
    file is missing it is generated on first use.
  - A signed token has the shape `key.<pub>.<sig>.<expiry>.<nonce>` where:
      pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
      expiry  = DECIMAL epoch-seconds string of now + 30
      nonce   = the challenge the hub answered in `hub/info`
      sig     = base64 ed25519 signature over
                `hub1:<hub SPKI>:<nonce>:<expiry>`, for one connection to one
                hub. hub-server allows 30 s of clock skew and at most 60 s ahead.
  - The hub verifies the signature against the embedded public key and
    treats the key as the connection identity (owner/host/group).

  Crypto backend: OTP's `:crypto` NIF (ed25519, RFC 8032). The key file
  layout is identical to the TS/Python/Ruby ports either way.

  Usage:

      token = HubServiceEx.Keychain.sign_hub(hub_key, nonce) # a token for one connect to that hub
      pub = HubServiceEx.Keychain.public_key()               # the service's public key
  """

  alias HubServiceEx.KeyFile

  @default_expires 30

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

  @doc "The key file location in use. Hub key pins (`hubs.json`) live beside it."
  def key_path do
    case :persistent_term.get({__MODULE__, :key_path}, :__unset__) do
      :__unset__ -> System.get_env("HUBKEY") || "auth"
      path -> path
    end
  end

  @doc "The service key, loaded or generated."
  def key do
    path = key_path()
    KeyFile.load_or_create!(path, false, "bad auth file #{path}")
  end

  @doc "The service's public key: base64 of the 44-byte SPKI DER public key."
  def public_key, do: KeyFile.public_key(key())

  @doc """
  A fresh auth token for one connection to the hub `hub_key` (its SPKI), over its
  `nonce`: `key.<pub>.<sig>.<expiry>.<nonce>`. `expires` is the token lifetime in
  seconds (default 30).
  """
  def sign_hub(hub_key, nonce, expires \\ @default_expires)
      when is_binary(hub_key) and is_binary(nonce) and is_integer(expires) do
    token(key(), hub_key, nonce, System.system_time(:second) + expires)
  end

  @doc "An auth token with `key` over `hub1:<hub_key>:<nonce>:<expiry>`."
  def token(%KeyFile{} = key, hub_key, nonce, expiry) when is_integer(expiry) do
    data = Integer.to_string(expiry)
    "key.#{KeyFile.public_key(key)}.#{KeyFile.sign(key, "hub1:#{hub_key}:#{nonce}:#{data}")}.#{data}.#{nonce}"
  end
end
