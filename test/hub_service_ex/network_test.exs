defmodule HubServiceEx.NetworkTest do
  # Share publication against a fake hub-net agent (Unix socket) and a fake hub.
  use ExUnit.Case, async: false

  alias HubServiceEx.{KeyFile, Keychain, Network}

  setup do
    # Unix socket paths are short (104 bytes on macOS), so stay out of the deep per-user temp dir.
    tmp = "/tmp/hse#{System.unique_integer([:positive])}"
    File.mkdir_p!(tmp)
    Keychain.set_key_path(Path.join(tmp, "auth"))
    socket = Path.join(tmp, "agent.sock")
    test = self()
    edit = :ets.new(:attestation_edit, [:public])
    :ets.insert(edit, {:edit, fn attestation -> attestation end})

    {:ok, listen} = :gen_tcp.listen(0, [{:ifaddr, {:local, String.to_charlist(socket)}}, :binary, active: false])
    agent = spawn(fn -> serve(listen, test, edit) end)
    :gen_tcp.controlling_process(listen, agent)

    on_exit(fn ->
      Process.exit(agent, :kill)
      Keychain.reset()
      File.rm_rf(tmp)
    end)

    %{tmp: tmp, socket: socket, edit: edit}
  end

  defp serve(listen, test, edit) do
    case :gen_tcp.accept(listen) do
      {:ok, connection} ->
        request = read_request(connection, "")
        [head, body] = String.split(request, "\r\n\r\n", parts: 2)
        path = head |> String.split(" ") |> Enum.at(1)
        body = Jason.decode!(body)
        send(test, {:agent, path, body})

        reply =
          if path == "/challenge" do
            ~s({"type":"attest_response","nonce":"nonce-1"})
          else
            [{:edit, edit_fun}] = :ets.lookup(edit, :edit)

            %{
              "version" => 1,
              "attestationId" => "att-1",
              "serviceKey" => body["serviceKey"],
              "key" => "agent-key",
              "shareName" => body["shareName"],
              "protocol" => body["protocol"],
              "target" => body["target"],
              "issuedAt" => DateTime.utc_now() |> DateTime.to_iso8601(),
              "expiresAt" => DateTime.utc_now() |> DateTime.add(300) |> DateTime.to_iso8601(),
              "signature" => "agent-signature"
            }
            |> edit_fun.()
            |> Jason.encode!()
          end

        :gen_tcp.send(
          connection,
          "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{byte_size(reply)}\r\n\r\n" <> reply
        )

        :gen_tcp.close(connection)
        serve(listen, test, edit)

      _ ->
        :ok
    end
  end

  defp read_request(connection, acc) do
    {:ok, data} = :gen_tcp.recv(connection, 0, 5_000)
    acc = acc <> data

    with [head, body] <- String.split(acc, "\r\n\r\n", parts: 2),
         [_, length] <- Regex.run(~r/(?i)content-length: *(\d+)/, head),
         true <- byte_size(body) >= String.to_integer(length) do
      acc
    else
      _ -> read_request(connection, acc)
    end
  end

  defp publications(%{"shares" => shares}) do
    list =
      shares
      |> Enum.with_index()
      |> Enum.map(fn {share, i} ->
        %{
          "version" => 1,
          "resourceId" => "hnr1_" <> share["name"],
          "authority" => "a#{i}",
          "providerId" => "p",
          "protocol" => share["protocol"],
          "overlayAddress" => "100.96.0.2",
          "port" => 40_000 + i
        }
      end)

    {:ok, %{"shares" => list}}
  end

  defp verifies?(public_key, data, signature) do
    raw = public_key |> Base.decode64!() |> binary_part(12, 32)
    :crypto.verify(:eddsa, :ed25519, data, Base.decode64!(signature), [raw, :ed25519])
  end

  test "publishes attested shares in name order", %{socket: socket} do
    key = Keychain.key()
    test = self()

    shares = %{
      "web" => Network.share("web", "tcp", "127.0.0.1", 8080, %{"mode" => "hub"}),
      "db" => Network.share("db", "tcp", "localhost", 5432)
    }

    {:ok, result} =
      Network.synchronize!(shares, key, socket, fn body ->
        send(test, {:sent, body})
        publications(body)
      end)

    # The agent's JSON decoder refuses unknown fields: exactly these go out.
    assert_receive {:agent, "/challenge", challenge}
    assert Map.keys(challenge) |> Enum.sort() == ["protocol", "serviceKey", "shareName", "target"]
    assert_receive {:agent, "/attest", attest}
    assert Map.keys(attest) |> Enum.sort() == ["protocol", "serviceKey", "shareName", "signature", "target"]
    assert attest["serviceKey"] == KeyFile.public_key(key)
    assert verifies?(KeyFile.public_key(key), "nonce-1", attest["signature"])

    assert_receive {:sent, %{"shares" => wire}}
    assert Enum.map(wire, & &1["name"]) == ["db", "web"]
    assert hd(wire)["version"] == 1
    assert hd(wire)["attestation"]["attestationId"] == "att-1"
    assert hd(wire)["policy"] == %{"mode" => "private"}
    assert result["web"]["resourceId"] == "hnr1_web"
  end

  test "a mismatched attestation is refused", %{socket: socket, edit: edit} do
    :ets.insert(edit, {:edit, &Map.put(&1, "shareName", "other")})

    error =
      assert_raise Network.AgentError, fn ->
        Network.synchronize!(%{"web" => Network.share("web", "tcp", "127.0.0.1", 8080)}, Keychain.key(), socket, &publications/1)
      end

    assert error.code == "attestation-mismatch"
  end

  test "an expired attestation is refused", %{socket: socket, edit: edit} do
    expired = DateTime.utc_now() |> DateTime.add(-1) |> DateTime.to_iso8601()
    :ets.insert(edit, {:edit, &Map.put(&1, "expiresAt", expired)})

    error =
      assert_raise Network.AgentError, fn ->
        Network.synchronize!(%{"web" => Network.share("web", "tcp", "127.0.0.1", 8080)}, Keychain.key(), socket, &publications/1)
      end

    assert error.code == "attestation-expired"
  end

  test "a missing agent is reported", %{tmp: tmp} do
    error =
      assert_raise Network.AgentError, fn ->
        Network.synchronize!(
          %{"web" => Network.share("web", "tcp", "127.0.0.1", 8080)},
          Keychain.key(),
          Path.join(tmp, "none.sock"),
          &publications/1
        )
      end

    assert error.code == "agent-unavailable"
  end

  test "invalid shares and publications are refused", %{socket: socket} do
    assert_raise ArgumentError, fn -> Network.share("", "tcp", "h", 1) end
    assert_raise ArgumentError, fn -> Network.share("a", "sctp", "h", 1) end
    assert_raise ArgumentError, fn -> Network.share("a", "tcp", "h", 70_000) end
    assert_raise ArgumentError, fn -> Network.share("a", "tcp", "h", 1, %{"mode" => "keys"}) end

    assert_raise RuntimeError, ~r/0 publications for 1 shares/, fn ->
      Network.synchronize!(%{"web" => Network.share("web", "tcp", "127.0.0.1", 8080)}, Keychain.key(), socket, fn _ ->
        {:ok, %{"shares" => []}}
      end)
    end
  end

  test "declared shares are published on connect", %{socket: socket} do
    test = self()

    hub =
      ChannelEx.new()
      |> ChannelEx.post("hub/service/update", fn _ -> nil end)
      |> ChannelEx.post("network/shares/replace", fn request ->
        send(test, :replaced)
        {:ok, result} = publications(request.body)
        result
      end)

    listener = ChannelEx.listen(hub, 0)
    on_exit(fn -> ChannelEx.ServerListener.stop(listener) end)

    service =
      HubServiceEx.new(address: "ws://127.0.0.1:#{listener.port}", device: false, agent_socket: socket)
      |> HubServiceEx.share("web", "tcp", "127.0.0.1", 8080)
      |> HubServiceEx.start()

    assert_receive :replaced, 5_000
    Process.sleep(50)
    assert [%{"resourceId" => "hnr1_web"}] = HubServiceEx.publications(service)

    assert {:ok, [%{"resourceId" => "hnr1_web"}]} =
             HubServiceEx.update_share(service, "web", policy: %{"mode" => "hub"}, port: 9090)

    assert {:ok, []} = HubServiceEx.remove_share(service, "web")
    assert {:error, "Share 'web' not found"} = HubServiceEx.remove_share(service, "web")
  end
end
