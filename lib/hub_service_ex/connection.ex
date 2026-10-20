defmodule HubServiceEx.Connection do
  @moduledoc false
  # Owns the hub websocket connection. channel_ex's client socket does NOT
  # auto-reconnect (it stops on tcp_closed/tcp_error), so this GenServer
  # monitors the socket and re-dials on disconnect. On every (re)connect the
  # socket's on_connect callback fires `HubServiceEx.send_updates/2`, which
  # re-sends hub/profile/update + hub/service/update (hub-lite drops a
  # sender's services on disconnect). Every (re)connect also carries fresh
  # hub-pro auth headers ({auth: <signed token>, v}) — the headers map is
  # built here once per dial, so the token is always freshly signed (TS
  # reference parity). hub-lite ignores the headers.
  #
  # Hub-bound auth: while no hub key is known, on_connect hands the sender to
  # this GenServer, which asks `hub/info` from a task (a blocking call inside
  # the socket's own callback would wait on itself). A key from it is pinned
  # and the connection re-dialed at once with a v1 token; an error (hub-lite)
  # keeps v0 and sends the updates.

  use GenServer

  alias HubServiceEx.HubPins

  @reconnect_delay 1_000

  def start_link(service) do
    GenServer.start_link(__MODULE__, service)
  end

  @doc "Current sender, or raises `Service not started` when disconnected."
  def sender(pid, timeout \\ 10_000) do
    case GenServer.call(pid, :sender, timeout) do
      {:ok, sender} -> sender
      :error -> raise "Service not started"
    end
  end

  def hub_key(pid), do: GenServer.call(pid, :hub_key)
  def last_error(pid), do: GenServer.call(pid, :last_error)
  def forget_hub_key(pid), do: GenServer.call(pid, :forget_hub_key)

  @impl true
  def init(service) do
    Process.flag(:trap_exit, true)

    state = %{
      service: service,
      hub_key: service.hub_key,
      client: nil,
      sender: nil,
      mon: nil,
      retry: nil,
      last_error: nil,
      device: HubServiceEx.Device.new_cache()
    }

    {:ok, state, {:continue, :connect}}
  end

  @impl true
  def handle_continue(:connect, state) do
    {:noreply, connect(state)}
  end

  @impl true
  def handle_call(:sender, _from, %{sender: sender} = state) when not is_nil(sender) do
    {:reply, {:ok, sender}, state}
  end

  def handle_call(:sender, _from, state) do
    {:reply, :error, state}
  end

  def handle_call(:hub_key, _from, state), do: {:reply, state.hub_key, state}
  def handle_call(:last_error, _from, state), do: {:reply, state.last_error, state}
  def handle_call(:forget_hub_key, _from, state), do: {:reply, :ok, %{state | hub_key: nil}}

  @impl true
  def handle_info({:connected, client_ws, sender}, state) do
    state = %{state | last_error: nil}

    cond do
      not current?(state, client_ws) ->
        {:noreply, state}

      state.service.pins == nil or state.hub_key != nil ->
        HubServiceEx.send_updates(state.service, sender)
        {:noreply, state}

      true ->
        owner = self()

        Task.start(fn ->
          send(owner, {:hub_info, client_ws, sender, ChannelEx.send(sender, "hub/info", nil, nil, 5_000)})
        end)

        {:noreply, state}
    end
  end

  def handle_info({:hub_info, client_ws, sender, result}, state) do
    cond do
      not current?(state, client_ws) ->
        {:noreply, state}

      key = hub_info_key(result) ->
        # An unwritable pin file keeps the key for this process only.
        try do
          HubPins.put(state.service.pins, HubServiceEx.address_key(state.service), key)
        rescue
          _ -> :ok
        end

        # Pinned the hub key: reconnect at once with a v1 token.
        {:noreply, state |> Map.put(:hub_key, key) |> drop_client() |> connect()}

      true ->
        # hub-lite or an older hub-pro: stay on v0.
        HubServiceEx.send_updates(state.service, sender)
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

  defp hub_info_key({:ok, %{"key" => key}}) when is_binary(key), do: key
  defp hub_info_key(_), do: nil

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

  defp connect(%{service: service, retry: retry} = state) do
    if retry, do: Process.cancel_timer(retry)
    owner = self()
    {device, device_cache} = HubServiceEx.Device.header(service, state.device)
    state = %{state | device: device_cache}
    headers = HubServiceEx.auth_headers(service, state.hub_key, device)

    on_connect =
      if service.pins == nil or state.hub_key != nil do
        fn sender -> HubServiceEx.send_updates(service, sender) end
      else
        fn sender -> send(owner, {:connected, self(), sender}) end
      end

    case ChannelEx.connect(service.channel, service.address,
           headers: fn -> headers end,
           on_connect: on_connect
         ) do
      %ChannelEx.ClientSender{} = client ->
        mon = Process.monitor(client.ws)
        %{state | client: client, sender: client.sender, mon: mon, retry: nil}

      # Refused connection, failed handshake or silent hub: retry later.
      {:error, reason} ->
        state |> report_error(headers, reason) |> schedule_reconnect()
    end
  rescue
    error -> state |> report_error(%{}, error) |> schedule_reconnect()
  catch
    _, reason -> state |> report_error(%{}, reason) |> schedule_reconnect()
  end

  defp report_error(state, headers, reason) do
    message = if is_exception(reason), do: Exception.message(reason), else: inspect(reason)

    if headers["v"] == "1" and message != state.last_error do
      IO.puts(
        :stderr,
        "hub-service: the hub at #{HubServiceEx.address_key(state.service)} refused the v1 connect for " <>
          "hub key #{state.hub_key} (#{message}). If it says invalid signature, the hub key changed or a " <>
          "different server answers; call forget_hub_key/1 if the change is expected."
      )
    end

    %{state | last_error: message}
  end

  defp schedule_reconnect(%{retry: nil} = state) do
    ref = Process.send_after(self(), :reconnect, @reconnect_delay)
    %{state | retry: ref}
  end

  defp schedule_reconnect(state), do: state
end
