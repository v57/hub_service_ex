defmodule HubServiceEx.HubAuthTest do
  # Keychain state (key path override) is process-global — no async.
  use ExUnit.Case, async: false

  alias HubServiceEx.{FakeHub, HubPins, Keychain}

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

  # A fake hub reporting `{:connect, headers}`, `{:asked, nonce}` and `{:update, headers}` to the test.
  defp fake_hub(answer \\ FakeHub.proving("hub"), setup \\ & &1) do
    test = self()

    hub =
      ChannelEx.new()
      |> FakeHub.answer_hub_info(answer, &send(test, {:asked, &1}))
      |> ChannelEx.post("hub/service/update", fn request ->
        send(test, {:update, ChannelEx.ConnectionState.get(request.state)})
        nil
      end)
      |> setup.()

    listener =
      ChannelEx.listen(hub, 0,
        state: fn headers ->
          send(test, {:connect, headers})
          headers
        end
      )

    on_exit(fn -> ChannelEx.ServerListener.stop(listener) end)
    "ws://127.0.0.1:#{listener.port}"
  end

  defp connects(found \\ []) do
    receive do
      {:connect, headers} -> connects([headers | found])
    after
      0 -> Enum.reverse(found)
    end
  end

  defp credentials_sent, do: Enum.filter(connects(), &(Map.has_key?(&1, "auth") or Map.has_key?(&1, "device")))

  test "sign_hub signs its challenge" do
    ["key", pub, sig, expiry, "nonce-1"] = String.split(Keychain.sign_hub(@hub_key, "nonce-1"), ".")
    assert verifies?(pub, "hub1:#{@hub_key}:nonce-1:#{expiry}", sig)
    {expiry, ""} = Integer.parse(expiry)
    assert_in_delta expiry, System.system_time(:second) + 30, 2
  end

  test "sends a token only after proof and pins the key", %{tmp: tmp} do
    address = fake_hub()

    service =
      HubServiceEx.new(address: address, name: "Echo", device_name: "Mac Studio", device_key_path: Path.join(tmp, "device.key"))
      |> HubServiceEx.start()

    assert_receive {:update, headers}, 5_000
    assert [first, ^headers] = connects()
    refute Map.has_key?(first, "auth")
    refute Map.has_key?(first, "device")
    refute Map.has_key?(first, "v")
    assert headers["v"] == "1"
    assert Map.has_key?(headers, "device")
    ["key", pub, sig, expiry, "challenge-1"] = String.split(headers["auth"], ".")
    assert verifies?(pub, "hub1:#{@hub_key}:challenge-1:#{expiry}", sig)

    assert HubServiceEx.hub_key(service) == @hub_key
    assert File.read!(Path.join(tmp, "hubs.json")) == ~s({"#{address}":"#{@hub_key}"})
    assert_received {:asked, nonce}
    assert nonce =~ ~r/^[A-Za-z0-9_-]{43}$/
    HubServiceEx.stop(service)
  end

  test "calls made right after start wait for the connection" do
    address = fake_hub(FakeHub.proving("hub"), &ChannelEx.post(&1, "ping", fn _ -> "pong" end))
    service = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()
    assert {:ok, "pong"} = HubServiceEx.send(service, "ping")
    HubServiceEx.stop(service)
  end

  test "every connect gets its own nonce and challenge" do
    address = fake_hub()
    first = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()
    assert_receive {:update, one}, 5_000
    assert_received {:asked, nonce_one}
    HubServiceEx.stop(first)

    second = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()
    assert_receive {:update, two}, 5_000
    assert_received {:asked, nonce_two}
    HubServiceEx.stop(second)

    assert nonce_one != nonce_two
    assert Enum.at(String.split(one["auth"], "."), 4) != Enum.at(String.split(two["auth"], "."), 4)
  end

  test "a reconnect asks again" do
    test = self()

    hub =
      ChannelEx.new()
      |> FakeHub.answer_hub_info(FakeHub.proving("hub"), &send(test, {:asked, &1}))
      |> ChannelEx.post("hub/service/update", fn request ->
        send(test, {:update, ChannelEx.ConnectionState.get(request.state)})
        nil
      end)

    listener =
      ChannelEx.listen(hub, 0,
        state: & &1,
        on_connect: fn %{sender: sender} -> send(test, {:hub_sender, sender}) end
      )

    on_exit(fn -> ChannelEx.ServerListener.stop(listener) end)
    service = HubServiceEx.new(address: "ws://127.0.0.1:#{listener.port}", device: false) |> HubServiceEx.start()
    assert_receive {:update, one}, 5_000
    assert_received {:asked, _nonce}
    sender = last_hub_sender()
    ChannelEx.Sender.stop(sender)
    assert_receive {:update, two}, 5_000
    assert_received {:asked, _nonce}
    assert one["auth"] != two["auth"]
    HubServiceEx.stop(service)
  end

  defp last_hub_sender(sender \\ nil) do
    receive do
      {:hub_sender, next} -> last_hub_sender(next)
    after
      100 -> sender
    end
  end

  defp gets_nothing(answer, tmp) do
    address = fake_hub(answer)
    service = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()
    assert_receive {:asked, _nonce}, 5_000
    refute_receive {:update, _}, 1_500
    assert credentials_sent() == []
    assert HubServiceEx.hub_key(service) == nil
    refute File.exists?(Path.join(tmp, "hubs.json"))
    assert HubServiceEx.last_error(service) =~ "didn't prove"
    HubServiceEx.stop(service)
  end

  test "a hub without proof gets nothing", %{tmp: tmp} do
    gets_nothing(fn _nonce, challenge -> %{"key" => @hub_key, "protocol" => 2, "challenge" => challenge} end, tmp)
  end

  test "a hub claiming the real key but signing with its own gets nothing", %{tmp: tmp} do
    own = FakeHub.key("service")
    gets_nothing(fn nonce, challenge -> FakeHub.proof(own, @hub_key, nonce, challenge) end, tmp)
  end

  test "a hub proving another key than the pin gets nothing", %{tmp: tmp} do
    address = fake_hub(FakeHub.proving("service"))
    pins = Path.join(tmp, "hubs.json")
    HubPins.put(pins, address, @hub_key)
    service = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()
    assert_receive {:asked, _nonce}, 5_000
    refute_receive {:update, _}, 1_500
    assert credentials_sent() == []
    assert HubServiceEx.hub_key(service) == @hub_key
    assert HubPins.get(pins, address) == @hub_key
    assert HubServiceEx.last_error(service) =~ "not the pinned"
    HubServiceEx.stop(service)
  end

  test "stop ends a waiting handshake and its calls" do
    address = fake_hub(fn _nonce, _challenge -> %{"key" => @hub_key} end)
    service = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()

    call =
      Task.async(fn ->
        try do
          HubServiceEx.send(service, "ping", nil, nil, 60_000)
        rescue
          error -> Exception.message(error)
        end
      end)

    assert_receive {:asked, _nonce}, 5_000
    HubServiceEx.stop(service)
    assert Task.await(call, 1_000) == "Service not started"
    refute_receive {:asked, _nonce}, 1_500
  end

  test "a call gives up at its timeout while nothing connects" do
    address = fake_hub(fn _nonce, _challenge -> %{"key" => @hub_key} end)
    service = HubServiceEx.new(address: address, device: false) |> HubServiceEx.start()
    assert_raise RuntimeError, "Service not started", fn -> HubServiceEx.send(service, "ping", nil, nil, 100) end
    HubServiceEx.stop(service)
  end

  test "a public plain address isn't dialed" do
    service = HubServiceEx.new(address: "ws://hub.example.com:1997", device: false) |> HubServiceEx.start()
    assert service.conn == nil
    assert_raise RuntimeError, ~r/unencrypted/, fn -> HubServiceEx.send(service, "x") end
    assert_raise RuntimeError, ~r/unencrypted/, fn -> HubServiceEx.values(service, "x") end
  end

  test "allow_plaintext dials a refused address" do
    # The option lets a refused address through, to a name that goes nowhere.
    service = HubServiceEx.new(address: "ws://hub.invalid:1", device: false, allow_plaintext: true) |> HubServiceEx.start()
    assert service.conn != nil
    HubServiceEx.stop(service)
  end

  test "wss isn't dialed, as channel_ex has no TLS" do
    service = HubServiceEx.new(address: "wss://hub.example.com", device: false, allow_plaintext: true) |> HubServiceEx.start()
    assert service.conn == nil
    assert_raise RuntimeError, ~r/TLS/, fn -> HubServiceEx.send(service, "x") end
  end

  test "a pinned key beside the key file is used and forgotten", %{tmp: tmp} do
    pins = Path.join(tmp, "hubs.json")
    HubPins.put(pins, "ws://localhost:4100", @hub_key)
    assert File.read!(pins) == ~s({"ws://localhost:4100":"#{@hub_key}"})

    service = HubServiceEx.new(address: 4100)
    assert HubServiceEx.hub_key(service) == @hub_key
    assert HubServiceEx.hub_key(HubServiceEx.new(address: "ws://other:1997")) == nil

    service = HubServiceEx.forget_hub_key(service)
    assert HubServiceEx.hub_key(service) == nil
    assert File.read!(pins) == "{}"
  end

  test "the hub_key option is the pin" do
    service = HubServiceEx.new(address: 4100, hub_key: @hub_key)
    assert HubServiceEx.hub_key(service) == @hub_key
    assert HubServiceEx.hub_key(HubServiceEx.forget_hub_key(service)) == nil
  end

  test "addresses normalize like channel TS" do
    assert HubServiceEx.normalize_hub_address(1997) == "ws://localhost:1997"
    assert HubServiceEx.normalize_hub_address("1997") == "ws://localhost:1997"
    assert HubServiceEx.normalize_hub_address("WSS://Hub.Example.COM/path/") == "wss://hub.example.com/path"
    assert HubServiceEx.normalize_hub_address("ws://127.0.0.1:1997/") == "ws://127.0.0.1:1997"
  end

  test "a custom sign gets the proven key and the challenge" do
    address = fake_hub()

    service =
      HubServiceEx.new(address: address, sign: fn key, challenge -> "key.custom.#{key}.#{challenge}" end)
      |> HubServiceEx.start()

    assert_receive {:update, headers}, 5_000
    assert headers["auth"] == "key.custom.#{@hub_key}.challenge-1"
    assert headers["v"] == "1"
    refute Map.has_key?(headers, "device")
    HubServiceEx.stop(service)
  end

  test "a custom sign doesn't run without proof" do
    test = self()
    address = fake_hub(fn _nonce, challenge -> %{"key" => @hub_key, "challenge" => challenge} end)

    service =
      HubServiceEx.new(
        address: address,
        sign: fn _key, _challenge ->
          send(test, :signed)
          "key.custom"
        end
      )
      |> HubServiceEx.start()

    assert_receive {:asked, _nonce}, 5_000
    refute_receive :signed, 300
    assert credentials_sent() == []
    HubServiceEx.stop(service)
  end

  test "a corrupt pin file counts as empty", %{tmp: tmp} do
    pins = Path.join(tmp, "hubs.json")
    File.write!(pins, "not json")
    assert HubPins.get(pins, "ws://localhost:1997") == nil
    HubPins.put(pins, "ws://localhost:1997", @hub_key)
    assert HubPins.get(pins, "ws://localhost:1997") == @hub_key
  end
end
