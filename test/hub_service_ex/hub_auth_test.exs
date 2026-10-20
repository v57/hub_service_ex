defmodule HubServiceEx.HubAuthTest do
  # Keychain state (key path override) is process-global — no async.
  use ExUnit.Case, async: false

  alias HubServiceEx.{HubPins, Keychain}

  @hub_key "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="

  setup do
    tmp = Path.join(System.tmp_dir!(), "hub_service_ex_auth_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    Keychain.set_key_path(Path.join(tmp, "auth"))

    on_exit(fn ->
      Keychain.reset()
      File.rm_rf(tmp)
    end)

    %{tmp: tmp}
  end

  defp verifies?(public_key, data, signature) do
    raw = public_key |> Base.decode64!() |> binary_part(12, 32)
    :crypto.verify(:eddsa, :ed25519, data, Base.decode64!(signature), [raw, :ed25519])
  end

  test "sign_hub signs the hub-bound string" do
    ["key", pub, sig, expiry] = String.split(Keychain.sign_hub(@hub_key), ".")
    assert verifies?(pub, "hub1:#{@hub_key}:#{expiry}", sig)
    refute verifies?(pub, expiry, sig)
    {expiry, ""} = Integer.parse(expiry)
    assert_in_delta expiry, System.system_time(:second) + 60, 2
  end

  test "connects with v0 until a hub key is known" do
    service = HubServiceEx.new(address: 4100)
    assert HubServiceEx.hub_key(service) == nil
    assert %{"v" => "0"} = HubServiceEx.auth_headers(service)
  end

  test "the hub_key option signs v1" do
    headers = HubServiceEx.auth_headers(HubServiceEx.new(address: 4100, hub_key: @hub_key))
    assert headers["v"] == "1"
    ["key", pub, sig, expiry] = String.split(headers["auth"], ".")
    assert verifies?(pub, "hub1:#{@hub_key}:#{expiry}", sig)
  end

  test "a pinned key beside the key file is used and forgotten", %{tmp: tmp} do
    pins = Path.join(tmp, "hubs.json")
    HubPins.put(pins, "ws://localhost:4100", @hub_key)
    assert File.read!(pins) == ~s({"ws://localhost:4100":"#{@hub_key}"})

    service = HubServiceEx.new(address: 4100)
    assert HubServiceEx.hub_key(service) == @hub_key
    assert %{"v" => "1"} = HubServiceEx.auth_headers(service)
    assert HubServiceEx.hub_key(HubServiceEx.new(address: "ws://other:1997")) == nil

    service = HubServiceEx.forget_hub_key(service)
    assert HubServiceEx.hub_key(service) == nil
    assert %{"v" => "0"} = HubServiceEx.auth_headers(service)
    assert File.read!(pins) == "{}"
  end

  test "addresses normalize like channel TS" do
    assert HubServiceEx.normalize_hub_address(1997) == "ws://localhost:1997"
    assert HubServiceEx.normalize_hub_address("1997") == "ws://localhost:1997"
    assert HubServiceEx.normalize_hub_address("WSS://Hub.Example.COM/path/") == "wss://hub.example.com/path"
    assert HubServiceEx.normalize_hub_address("ws://127.0.0.1:1997/") == "ws://127.0.0.1:1997"
  end

  test "a custom sign stays v0" do
    service = HubServiceEx.new(hub_key: @hub_key, sign: fn -> "key.custom" end)
    assert HubServiceEx.auth_headers(service) == %{"auth" => "key.custom", "v" => "0"}
  end

  test "a corrupt pin file counts as empty", %{tmp: tmp} do
    pins = Path.join(tmp, "hubs.json")
    File.write!(pins, "not json")
    assert HubPins.get(pins, "ws://localhost:1997") == nil
    HubPins.put(pins, "ws://localhost:1997", @hub_key)
    assert HubPins.get(pins, "ws://localhost:1997") == @hub_key
  end
end
