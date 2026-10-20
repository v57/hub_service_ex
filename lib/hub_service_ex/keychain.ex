defmodule HubServiceEx.Keychain do
  @moduledoc """
  ed25519 keychain: load-or-generate the `auth` key file and sign tokens.

  Hub-pro auth parity with the TS reference (hub-service/keychain.ts) and
  `Docs/Devices/protocol.md` section 2:

  - The key file (`auth` in the working directory, or `$HUBKEY`) is the
    base64 encoding of the 48-byte PKCS8 DER ed25519 private key followed by
    the 44-byte SPKI DER public key (92 bytes total, 124 base64 chars). If the
    file is missing it is generated on first use.
  - A signed token has the shape `key.<pub>.<sig>.<expiry>` where:
      pub     = base64 of the 44-byte SPKI public key (bytes 48..92)
      expiry  = DECIMAL epoch-seconds string of now + 60
      sig     = base64 ed25519 signature over `<expiry>` (header `v: 0`) or
                over `hub1:<hub SPKI>:<expiry>` (header `v: 1`, bound to one
                hub). hub-pro allows 30 s of clock skew and at most 300 s
                ahead.
  - The hub verifies the signature against the embedded public key and
    treats the key as the connection identity (owner/host/group).

  Crypto backend: OTP's `:crypto` NIF (ed25519, RFC 8032). The key file
  layout is identical to the TS/Python/Ruby ports either way.

  Usage:

      token = HubServiceEx.Keychain.sign()            # fresh v0 token for a connect
      token = HubServiceEx.Keychain.sign_hub(hub_key) # fresh v1 token for that hub
      pub = HubServiceEx.Keychain.public_key()        # the service's public key
  """

  alias HubServiceEx.KeyFile

  @default_expires 60

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
  A fresh v0 auth token: `key.<pub>.<sig>.<expiry>`.

  `expires` is the token lifetime in seconds (default 60).
  """
  def sign(expires \\ @default_expires) when is_integer(expires) do
    token(key(), nil, System.system_time(:second) + expires)
  end

  @doc "A fresh v1 auth token bound to `hub_key` (the hub's SPKI)."
  def sign_hub(hub_key, expires \\ @default_expires) when is_binary(hub_key) and is_integer(expires) do
    token(key(), hub_key, System.system_time(:second) + expires)
  end

  @doc """
  An auth token with `key` expiring at `expiry`: v1 (over
  `hub1:<hub_key>:<expiry>`) when `hub_key` is set, else v0 (over `<expiry>`).
  """
  def token(%KeyFile{} = key, hub_key, expiry) when is_integer(expiry) do
    data = Integer.to_string(expiry)
    signed = if hub_key, do: "hub1:#{hub_key}:#{data}", else: data
    "key.#{KeyFile.public_key(key)}.#{KeyFile.sign(key, signed)}.#{data}"
  end
end
