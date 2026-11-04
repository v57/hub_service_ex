defmodule HubServiceEx.Connection do
  @moduledoc false
  # Owns the hub websocket connection. channel_ex's client socket does NOT
  # auto-reconnect (it stops on tcp_closed/tcp_error), so this GenServer
  # monitors the socket and re-dials on disconnect. On every (re)connect the
  # socket's on_connect callback tells this GenServer, which re-sends
  # hub/profile/update + hub/service/update (the hub drops a sender's services on
  # disconnect).
  #
  # Auth v2 (protocol.md section 2): channel_ex takes its headers before dialing,
  # so every attempt starts here. A task asks `hub/info` on a short anonymous
  # connection with a fresh nonce, so this process stays free meanwhile; only an
  # answer with a valid proof that matches the pin leads to a dial, with a token
  # over that answer's challenge. Anything else sends the hub nothing and retries
  # with a growing delay. Calls wait for the dial (`sender/2`).
  #
  # Hub Network shares live here too: declared ones are republished from a
  # task after every connect, and publish/update/remove calls attest and
  # replace the whole set through the current sender.

  use GenServer

  alias HubServiceEx.{HubPins, HubProof}

  @reconnect_delay 1_000
  @handshake_max_delay 30_000
  @hub_info_timeout 5_000

  def start_link(service) do
    GenServer.start_link(__MODULE__, service)
  end

  @doc """
  Current sender. While disconnected the caller waits for a connection, up to
  `timeout`, then raises `Service not started`, as it does once the service stopped.
  """
  def sender(pid, timeout \\ 10_000) do
    GenServer.call(pid, :sender, timeout)
  catch
    :exit, _reason -> raise "Service not started"
  end

  def stop(pid) do
    GenServer.stop(pid)
  catch
    :exit, _reason -> :ok
  end

  def hub_key(pid), do: GenServer.call(pid, :hub_key)
  def last_error(pid), do: GenServer.call(pid, :last_error)
  def forget_hub_key(pid), do: GenServer.call(pid, :forget_hub_key)
  def publish(pid, share), do: GenServer.call(pid, {:publish, share}, 60_000)
  def update_share(pid, name, changes), do: GenServer.call(pid, {:update_share, name, changes}, 60_000)
  def remove_share(pid, name), do: GenServer.call(pid, {:remove_share, name}, 60_000)
  def publications(pid), do: GenServer.call(pid, :publications)

  @impl true
  def init(service) do
    Process.flag(:trap_exit, true)
    HubServiceEx.put_current_hub_key(service, service.hub_key)

    state = %{
      service: service,
      hub_key: service.hub_key,
      client: nil,
      sender: nil,
      mon: nil,
      retry: nil,
      handshake: nil,
      handshake_delay: @reconnect_delay,
      waiting: [],
      last_error: nil,
      device: HubServiceEx.Device.new_cache(),
      shares: service.shares,
      publications: %{}
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    {:noreply, connect(state)}
  end

  @impl true
  def handle_call(:sender, _from, %{sender: sender} = state) when not is_nil(sender) do
    {:reply, sender, state}
  end

  def handle_call(:sender, from, state) do
    {:noreply, %{state | waiting: [from | state.waiting]}}
  end

  def handle_call(:hub_key, _from, state), do: {:reply, state.hub_key, state}
  def handle_call(:last_error, _from, state), do: {:reply, state.last_error, state}
  def handle_call(:publications, _from, state), do: {:reply, publication_list(state.publications), state}

  def handle_call({:publish, share}, _from, state) do
    replace_shares(state, Map.put(state.shares, share.name, share))
  end

  def handle_call({:update_share, name, changes}, _from, state) do
    case Map.fetch(state.shares, name) do
      {:ok, share} ->
        share = %{share | policy: changes[:policy] || share.policy, port: changes[:port] || share.port}
        HubServiceEx.Network.validate!(share)
        replace_shares(state, Map.put(state.shares, name, share))

      :error ->
        {:reply, {:error, "Share '#{name}' not found"}, state}
    end
  end

  def handle_call({:remove_share, name}, _from, state) do
    if Map.has_key?(state.shares, name) do
      replace_shares(state, Map.delete(state.shares, name))
    else
      {:reply, {:error, "Share '#{name}' not found"}, state}
    end
  end

  def handle_call(:forget_hub_key, _from, state) do
    HubServiceEx.put_current_hub_key(state.service, nil)
    {:reply, :ok, %{state | hub_key: nil}}
  end

  @impl true
  def handle_info({:connected, client_ws, sender}, state) do
    if current?(state, client_ws) do
      HubServiceEx.send_updates(state.service, sender)
      {:noreply, republish(%{state | last_error: nil}, client_ws, sender)}
    else
      {:noreply, state}
    end
  end

  def handle_info({:hub_proof, ref, result}, %{handshake: ref} = state) do
    state = %{state | handshake: nil}

    case check_proof(state, result) do
      {:ok, state, key, challenge} -> {:noreply, dial(%{state | handshake_delay: @reconnect_delay}, key, challenge)}
      {:error, message} -> {:noreply, state |> report("#{address(state)}: #{message}, sending it nothing") |> retry_handshake()}
    end
  end

  def handle_info({:republished, client_ws, result}, state) do
    case result do
      {:ok, publications} when is_map(publications) ->
        if current?(state, client_ws), do: {:noreply, %{state | publications: publications}}, else: {:noreply, state}

      {:error, message} ->
        IO.puts(:stderr, "hub-service: failed to republish network shares: #{message}")
        {:noreply, state}
    end
  end

  def handle_info({:DOWN, mon, :process, _pid, _reason}, %{mon: mon} = state) do
    {:noreply, schedule_reconnect(%{state | client: nil, sender: nil, mon: nil})}
  end

  def handle_info({:EXIT, _pid, _reason}, %{mon: mon} = state) do
    if mon do
      {:noreply, state}
    else
      {:noreply, schedule_reconnect(%{state | sender: nil})}
    end
  end

  def handle_info(:reconnect, state) do
    {:noreply, connect(%{state | retry: nil})}
  end

  def handle_info(_message, state) do
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    drop_client(state)
    :ok
  end

  # Attests and replaces the whole share set; keeps the old set on failure.
  defp replace_shares(state, shares) do
    cond do
      state.sender == nil ->
        {:reply, {:error, "Service not started"}, state}

      state.service.sign != nil ->
        {:reply, {:error, "Share publication needs the keychain service key, not a custom sign"}, state}

      true ->
        case run_synchronize(state, shares, state.sender) do
          {:ok, publications} ->
            {:reply, {:ok, publication_list(publications)}, %{state | shares: shares, publications: publications}}

          {:error, _} = error ->
            {:reply, error, state}
        end
    end
  end

  # Republishes the declared shares after a connect, from a task: the calls
  # need this process free to answer.
  defp republish(%{shares: shares} = state, client_ws, sender) when map_size(shares) > 0 do
    if state.service.sign == nil do
      owner = self()
      Task.start(fn -> send(owner, {:republished, client_ws, run_synchronize(state, shares, sender)}) end)
    end

    state
  end

  defp republish(state, _client_ws, _sender), do: state

  defp run_synchronize(state, shares, sender) do
    socket = state.service.agent_socket || HubServiceEx.Network.default_agent_socket()
    send_fun = fn body -> ChannelEx.send(sender, "network/shares/replace", body, nil, 10_000) end
    HubServiceEx.Network.synchronize!(shares, HubServiceEx.Keychain.key(), socket, send_fun)
  rescue
    error in HubServiceEx.Network.AgentError -> {:error, {error.code, error.message}}
    error -> {:error, Exception.message(error)}
  end

  defp publication_list(publications) do
    publications |> Enum.sort_by(&elem(&1, 0)) |> Enum.map(&elem(&1, 1))
  end

  defp current?(%{client: %ChannelEx.ClientSender{ws: ws}}, ws), do: true
  defp current?(_state, _ws), do: false

  defp drop_client(%{client: client, mon: mon} = state) do
    if mon, do: Process.demonitor(mon, [:flush])

    if client do
      try do
        ChannelEx.ClientSender.stop(client)
      catch
        _, _ -> :ok
      end
    end

    %{state | client: nil, sender: nil, mon: nil}
  end

  # Starts an attempt: a task asks the hub for its proof, and `{:hub_proof, ..}`
  # goes on from there.
  defp connect(%{handshake: ref} = state) when not is_nil(ref), do: state
  defp connect(%{client: client} = state) when not is_nil(client), do: state

  defp connect(%{service: service, retry: retry} = state) do
    if retry, do: Process.cancel_timer(retry)
    owner = self()
    ref = make_ref()

    Task.start(fn ->
      # The asking socket is linked here: its exit must still end in an answer.
      Process.flag(:trap_exit, true)

      result =
        try do
          HubProof.ask(service.address, @hub_info_timeout)
        rescue
          error -> {:error, Exception.message(error)}
        catch
          _, reason -> {:error, inspect(reason)}
        end

      send(owner, {:hub_proof, ref, result})
    end)

    %{state | handshake: ref, retry: nil}
  end

  # Takes a proven answer only if it matches the pin, and pins a first key.
  defp check_proof(_state, {:error, message}), do: {:error, message}

  defp check_proof(%{service: service} = state, {:ok, %{"key" => key, "challenge" => challenge}}) do
    pinned = state.hub_key || HubPins.get(service.pins, HubServiceEx.address_key(service))

    cond do
      pinned == nil ->
        # An unwritable pin file keeps the key for this process only.
        try do
          HubPins.put(service.pins, HubServiceEx.address_key(service), key)
        rescue
          error -> IO.puts(:stderr, "hub-service: pin hub key: #{Exception.message(error)}")
        end

        HubServiceEx.put_current_hub_key(service, key)
        {:ok, %{state | hub_key: key}, key, challenge}

      pinned == key ->
        HubServiceEx.put_current_hub_key(service, key)
        {:ok, %{state | hub_key: key}, key, challenge}

      true ->
        {:error, "it answers with key #{key}, not the pinned #{pinned}. Call forget_hub_key/1 if its key really changed"}
    end
  end

  defp dial(%{service: service} = state, key, challenge) do
    owner = self()
    {device, device_cache} = HubServiceEx.Device.header(service, state.device)
    state = %{state | device: device_cache}
    headers = HubServiceEx.auth_headers(service, key, challenge, device)

    case ChannelEx.connect(service.channel, service.address,
           headers: fn -> headers end,
           on_connect: fn sender -> send(owner, {:connected, self(), sender}) end
         ) do
      %ChannelEx.ClientSender{} = client ->
        mon = Process.monitor(client.ws)
        Enum.each(state.waiting, &GenServer.reply(&1, client.sender))
        %{state | client: client, sender: client.sender, mon: mon, retry: nil, waiting: []}

      # Refused connection, failed handshake or silent hub: retry later.
      {:error, reason} ->
        state |> report_error(reason) |> schedule_reconnect()
    end
  rescue
    error -> state |> report_error(error) |> schedule_reconnect()
  catch
    _, reason -> state |> report_error(reason) |> schedule_reconnect()
  end

  defp address(state), do: HubServiceEx.address_key(state.service)

  defp report_error(state, reason) do
    message = if is_exception(reason), do: Exception.message(reason), else: inspect(reason)

    # hub-server refuses a bad token with HTTP 401 (a failed handshake here); its reason (invalid
    # signature, key revoked) stays on the hub.
    report(
      state,
      "connect to #{address(state)} (hub key #{state.hub_key}) failed: #{message}. " <>
        "If the hub key changed or a different server answers, call forget_hub_key/1."
    )
  end

  # Records a failure, and reports it once per distinct message.
  defp report(state, message) do
    if message != state.last_error, do: IO.puts(:stderr, "hub-service: #{message}")
    %{state | last_error: message}
  end

  defp retry_handshake(state) do
    ref = Process.send_after(self(), :reconnect, state.handshake_delay)
    %{state | retry: ref, handshake_delay: min(state.handshake_delay * 2, @handshake_max_delay)}
  end

  defp schedule_reconnect(%{retry: nil} = state) do
    ref = Process.send_after(self(), :reconnect, @reconnect_delay)
    %{state | retry: ref}
  end

  defp schedule_reconnect(state), do: state
end
