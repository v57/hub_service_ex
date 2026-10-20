defmodule HubServiceEx.FakeHubTest do
  # End to end against a fake hub: hub/info pinning and the v1 reconnect.
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

  test "pins the hub key from hub/info and reconnects with v1", %{tmp: tmp, port: port} do
    address = "ws://127.0.0.1:#{port}"

    service =
      HubServiceEx.new(address: address, name: "Echo")
      |> HubServiceEx.post("echo", fn body -> body end)
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
  end
end
