defmodule HubServiceEx.KeychainTest do
  # Keychain state (key path override) is process-global — no async.
  use ExUnit.Case, async: false

  alias HubServiceEx.Keychain

  # TS reference test key (hub-service/keychain.ts test vector / /tmp/hubpro-test/auth):
  # base64 of 48-byte PKCS8 ed25519 DER + 44-byte SPKI DER public key.
  @ts_auth "MC4CAQAwBQYDK2VwBCIEINguo0cc0FACJ0oRV3V/+ZqIyj04ON5wdMJGH4a/do8CMCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ="
  @ts_pub "MCowBQYDK2VwAyEAHZSDpmbLRjLrOyNMugsStFqK5EYcNluUekE4di+FalQ="

  setup do
    tmp = Path.join(System.tmp_dir!(), "hub_service_ex_keychain_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    on_exit(fn -> File.rm_rf(tmp) end)
    %{tmp: tmp}
  end

  defp use_auth(tmp, contents) do
    path = Path.join(tmp, "auth")
    File.write!(path, contents)
    Keychain.set_key_path(path)
  end

  test "loads a TS-generated auth file and reproduces its public key", %{tmp: tmp} do
    use_auth(tmp, @ts_auth)

    assert Keychain.public_key() == @ts_pub
  end

  test "sign produces key.<pub>.<sig>.<decimalExpiry> and the signature verifies", %{tmp: tmp} do
    use_auth(tmp, @ts_auth)

    token = Keychain.sign()
    assert ["key", pub, sig, expiry] = String.split(token, ".")
    assert pub == @ts_pub

    # expiry is a decimal epoch-seconds string (TS parity; hub-server rejects
    # it once expired or if over 5 minutes ahead)
    assert {expiry_epoch, ""} = Integer.parse(expiry)
    assert_in_delta expiry_epoch, System.system_time(:second) + 60, 2

    # signature is 64-byte ed25519 over the expiry string, verifiable with
    # the raw public key embedded in the SPKI DER (bytes 48..92 -> raw pub)
    assert byte_size(Base.decode64!(sig)) == 64
    bytes = Base.decode64!(@ts_auth)
    raw_pub = binary_part(bytes, 48 + 12, 32)

    assert :crypto.verify(:eddsa, :ed25519, expiry, Base.decode64!(sig), [raw_pub, :ed25519])
  end

  test "sign honours a custom expires offset", %{tmp: tmp} do
    use_auth(tmp, @ts_auth)

    [_key, _pub, _sig, expiry] = String.split(Keychain.sign(30), ".")
    {expiry_epoch, ""} = Integer.parse(expiry)
    assert_in_delta expiry_epoch, System.system_time(:second) + 30, 2
  end

  test "auth file round-trip: generates when missing, loads back identically" do
    tmp = Path.join(System.tmp_dir!(), "rt#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    path = Path.join(tmp, "auth")
    Keychain.set_key_path(path)

    pub1 = Keychain.public_key()
    assert File.exists?(path)

    contents = File.read!(path)
    assert byte_size(contents) == 124

    bytes = Base.decode64!(String.trim(contents))
    assert byte_size(bytes) == 92

    # PKCS8 + SPKI DER prefixes (RFC 8410) wrap a 32-byte seed + raw pub
    assert binary_part(bytes, 0, 16) ==
             <<0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04,
               0x22, 0x04, 0x20>>

    assert binary_part(bytes, 48, 12) ==
             <<0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00>>

    # a fresh load (new path override, same file) reproduces the same identity
    Keychain.set_key_path(path)
    assert Keychain.public_key() == pub1

    # and the generated key actually signs/verifies
    token = Keychain.sign()
    assert ["key", pub, sig, expiry] = String.split(token, ".")
    assert pub == pub1
    raw_pub = binary_part(bytes, 48 + 12, 32)
    assert :crypto.verify(:eddsa, :ed25519, expiry, Base.decode64!(sig), [raw_pub, :ed25519])

    File.rm_rf!(tmp)
  end

  test "two generated key files are distinct identities" do
    tmp1 = Path.join(System.tmp_dir!(), "g1#{System.unique_integer([:positive])}")
    tmp2 = Path.join(System.tmp_dir!(), "g2#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp1)
    File.mkdir_p!(tmp2)

    Keychain.set_key_path(Path.join(tmp1, "auth"))
    pub1 = Keychain.public_key()
    Keychain.set_key_path(Path.join(tmp2, "auth"))
    pub2 = Keychain.public_key()

    assert pub1 != pub2

    File.rm_rf!(tmp1)
    File.rm_rf!(tmp2)
  end

  test "bad auth file raises", %{tmp: tmp} do
    use_auth(tmp, Base.encode64(<<1, 2, 3>>))

    assert_raise ArgumentError, ~r/bad auth file/, fn -> Keychain.public_key() end
  end
end
