defmodule HubServiceEx.Connection do
  @moduledoc false
  # Owns the hub websocket connection. channel_ex's client socket does NOT
  # auto-reconnect (it stops on tcp_closed/tcp_error), so this GenServer
  # monitors the socket and re-dials on disconnect. On every (re)connect the
  # socket's on_connect callback fires `HubServiceEx.send_updates/2`, which
  # re-sends hub/profile/update + hub/service/update (hub-lite drops a
  # sender's services on disconnect). Every (re)connect also carries fresh
  # hub-pro auth headers ({auth: <signed token>, v: "0"}) — the headers fun
  # is invoked once per socket init by channel_ex, so the token is always
  # freshly signed (TS reference parity). hub-lite ignores the headers.

  use GenServer

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

  @impl true
  def init(service) do
    Process.flag(:trap_exit, true)
    {:ok, %{service: service, sender: nil, mon: nil, retry: nil}, {:continue, :connect}}
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

  @impl true
  def handle_info({:DOWN, mon, :process, _pid, _reason}, %{mon: mon} = state) do
    {:noreply, schedule_reconnect(%{state | sender: nil, mon: nil})}
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

  defp connect(%{service: service, retry: retry} = state) do
    if retry, do: Process.cancel_timer(retry)

    client =
      ChannelEx.connect(service.channel, service.address,
        headers: fn -> %{"auth" => service.sign.(), "v" => "0"} end,
        on_connect: fn sender -> HubServiceEx.send_updates(service, sender) end
      )

    mon = Process.monitor(client.ws)
    %{state | sender: client.sender, mon: mon, retry: nil}
  rescue
    _ -> schedule_reconnect(state)
  catch
    _, _ -> schedule_reconnect(state)
  end

  defp schedule_reconnect(%{retry: nil} = state) do
    ref = Process.send_after(self(), :reconnect, @reconnect_delay)
    %{state | retry: ref}
  end

  defp schedule_reconnect(state), do: state
end
