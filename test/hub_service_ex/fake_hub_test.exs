defmodule HubServiceEx.FakeHubTest do
  # End to end against a fake hub: hub/info pinning, the v1 reconnect, the device header and caller identity.
  use ExUnit.Case, async: false

  alias HubServiceEx.Keychain

  @hub_key "MCowBQYDK2VwAyEAiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="

  setup do
    tmp = Path.join(System.tmp_dir!(), "hub_service_ex_fakehub_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    Keychain.set_key_path(Path.join(tmp, "auth"))
    test = self()

    hub =
      ChannelEx.new()
      |> ChannelEx.post("hub/info", fn _ ->
        %{"key" => @hub_key, "protocol" => 1, "pro" => true, "mode" => "default-allow"}
      end)
      |> ChannelEx.post("hub/service/update", fn _ ->
        send(test, :update)
        nil
      end)

    listener =
      ChannelEx.listen(hub, 0,
        state: fn headers ->
          send(test, {:connect, headers})
          headers
        end,
        on_connect: fn %{sender: sender} -> send(test, {:hub_sender, sender}) end
      )

    on_exit(fn ->
      ChannelEx.ServerListener.stop(listener)
      Keychain.reset()
      File.rm_rf(tmp)
    end)

    %{tmp: tmp, port: listener.port}
  end

  defp verifies?(public_key, data, signature) do
    raw = public_key |> Base.decode64!() |> binary_part(12, 32)
    :crypto.verify(:eddsa, :ed25519, data, Base.decode64!(signature), [raw, :ed25519])
  end

  test "starts while the hub is down and connects once it is up", %{tmp: tmp} do
    {:ok, probe} = :gen_tcp.listen(0, [])
    {:ok, port} = :inet.port(probe)
    :gen_tcp.close(probe)

    service =
      HubServiceEx.new(address: "ws://127.0.0.1:#{port}", device: false, sign: fn -> "key.x.y.1" end)
      |> HubServiceEx.post("echo", & &1)
      |> HubServiceEx.start()

    assert_raise RuntimeError, "Service not started", fn -> HubServiceEx.send(service, "echo", 1) end

    test = self()
    hub = ChannelEx.post(ChannelEx.new(), "hub/service/update", fn _ -> send(test, :late_update) end)
    listener = ChannelEx.listen(hub, port)
    on_exit(fn -> ChannelEx.ServerListener.stop(listener) end)
    assert_receive :late_update, 5_000
    assert File.ls!(tmp) == []
  end

  test "pins the hub key from hub/info and reconnects with v1", %{tmp: tmp, port: port} do
    address = "ws://127.0.0.1:#{port}"

    service =
      HubServiceEx.new(
        address: address,
        name: "Echo",
        device_name: "Mac Studio",
        device_key_path: Path.join(tmp, "device.key")
      )
      |> HubServiceEx.post("echo/caller", fn _body, request ->
        caller = request.caller

        %{
          "key" => caller.key,
          "device" => caller.device_name,
          "owner" => caller.owner,
          "hubKey" => request.hub_key,
          "service" => request.context["service"]
        }
      end)
      |> HubServiceEx.start()

    assert_receive {:connect, first}, 5_000
    assert first["v"] == "0"
    assert_receive {:connect, second}, 5_000
    assert second["v"] == "1"
    # The updates go only to the v1 connection.
    assert_receive :update, 5_000
    refute_receive {:connect, _}, 200

    ["key", pub, sig, expiry] = String.split(second["auth"], ".")
    assert verifies?(pub, "hub1:#{@hub_key}:#{expiry}", sig)
    assert File.read!(Path.join(tmp, "hubs.json")) == ~s({"#{address}":"#{@hub_key}"})
    assert HubServiceEx.hub_key(service) == @hub_key

    payload = HubServiceEx.Device.decode_certificate(second["device"])
    assert payload["service"] == pub
    assert payload["instance"] == "Echo"
    # Reconnects reuse the certificate.
    assert first["device"] == second["device"]

    context = %{
      "service" => "s1",
      "hub" => %{
        "caller" => %{
          "key" => pub,
          "device" => %{"id" => HubServiceEx.Device.id(payload["device"]), "name" => "Mac Studio"},
          "groups" => ["owners"],
          "owner" => true
        },
        "hubKey" => @hub_key
      }
    }

    # The latest hub-side sender is the v1 connection's.
    hub_sender = last_hub_sender()

    assert {:ok, %{"key" => ^pub, "device" => "Mac Studio", "owner" => true, "hubKey" => @hub_key, "service" => "s1"}} =
             ChannelEx.send(hub_sender, "echo/caller", nil, context)
  end

  defp last_hub_sender(sender \\ nil) do
    receive do
      {:hub_sender, next} -> last_hub_sender(next)
    after
      100 -> sender
    end
  end
end
