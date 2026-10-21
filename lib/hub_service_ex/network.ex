defmodule HubServiceEx.Network do
  @moduledoc """
  Hub Network share publication, ported from the TS SDK
  (`hub-service/network.ts`). A share makes a local TCP/UDP port reachable
  through Hub Network: for each share the local hub-net agent attests that
  this service owns the port (POST `/challenge`, sign the nonce with the
  service key, POST `/attest` over the agent's Unix socket), then the
  complete set goes to the hub with `network/shares/replace`, which answers
  one publication per share in request order. The declared set is
  republished after every reconnect.

  A share is a map `%{name:, protocol: "tcp" | "udp", host:, port:, policy:}`
  where `policy` is `%{"mode" => "hub" | "private" | "disabled"}`,
  `%{"mode" => "group", "group" => ...}` or
  `%{"mode" => "keys", "keys" => [...]}`.
  """

  alias HubServiceEx.KeyFile

  @wire_version 1
  @max_share_name_length 255

  defmodule AgentError do
    @moduledoc """
    A local-agent failure; `code` is `"agent-unavailable"`, `"agent-timeout"`,
    `"agent-rejected"`, `"invalid-agent-response"`, `"attestation-mismatch"` or
    `"attestation-expired"`.
    """
    defexception [:code, :message]
  end

  @doc "`$HUB_NET_AGENT_SOCKET`, else the platform's hub-net agent socket."
  def default_agent_socket do
    case System.get_env("HUB_NET_AGENT_SOCKET") do
      path when path not in [nil, ""] -> path
      _ -> if :os.type() == {:unix, :linux}, do: "/run/hub-net/agent.sock", else: "/var/run/hub-net/agent.sock"
    end
  end

  @doc "Builds and validates a share (a nil policy means private)."
  def share(name, protocol, host, port, policy \\ nil) do
    share = %{name: name, protocol: protocol, host: host, port: port, policy: policy || %{"mode" => "private"}}
    validate!(share)
    share
  end

  @doc "Validates a share like the TS SDK: name, protocol, target and policy. Raises `ArgumentError`."
  def validate!(share) do
    require_text!(share.name, "share name", @max_share_name_length)
    unless share.protocol in ["tcp", "udp"], do: raise(ArgumentError, "Invalid Hub Network protocol")
    require_text!(share.host, "target host")

    unless is_integer(share.port) and share.port in 1..65_535,
      do: raise(ArgumentError, "Invalid Hub Network target port")

    case share.policy do
      nil -> :ok
      %{"mode" => mode} when mode in ["hub", "private", "disabled"] -> :ok
      %{"mode" => "group", "group" => group} -> require_text!(group, "policy group")
      %{"mode" => "keys", "keys" => [_ | _] = keys} -> Enum.each(keys, &require_text!(&1, "policy key"))
      %{"mode" => "keys"} -> raise ArgumentError, "Invalid Hub Network policy keys"
      _ -> raise ArgumentError, "Invalid Hub Network policy mode"
    end

    :ok
  end

  @doc """
  Attests every share in `shares` (a map of name to share) and sends the set
  with `network/shares/replace` through `send` (a 1-arity fun taking the call
  body and returning `{:ok, result} | {:error, reason}`). Returns
  `{:ok, publications_by_name}` or raises.
  """
  def synchronize!(shares, %KeyFile{} = key, agent_socket, send, timeout \\ 5_000) do
    declared = shares |> Map.values() |> Enum.sort_by(& &1.name)

    wire =
      Enum.map(declared, fn share ->
        share
        |> wire_share()
        |> Map.merge(%{"version" => @wire_version, "attestation" => request_attestation!(share, key, agent_socket, timeout)})
      end)

    list =
      case send.(%{"shares" => wire}) do
        {:ok, %{"shares" => list}} when is_list(list) -> list
        {:error, reason} -> raise RuntimeError, "network/shares/replace failed: #{inspect(reason)}"
        _ -> raise RuntimeError, "Hub returned an invalid shares/replace response"
      end

    if length(list) != length(declared) do
      raise RuntimeError, "Hub returned #{length(list)} publications for #{length(declared)} shares"
    end

    # Protocol v1 publications carry no share name: the hub keeps request order.
    {publications, _ids} =
      declared
      |> Enum.zip(list)
      |> Enum.with_index()
      |> Enum.reduce({%{}, MapSet.new()}, fn {{share, publication}, index}, {acc, ids} ->
        publication = validate_publication!(publication, share, index)
        id = publication["resourceId"]
        if MapSet.member?(ids, id), do: raise(RuntimeError, "Hub returned duplicate resourceId at share index #{index}")
        {Map.put(acc, share.name, publication), MapSet.put(ids, id)}
      end)

    {:ok, publications}
  end

  @doc "Asks the local agent to attest `share`: `/challenge` returns a nonce, which the service key signs for `/attest`."
  def request_attestation!(share, %KeyFile{} = key, agent_socket, timeout \\ 5_000) do
    validate!(share)

    body = %{
      "serviceKey" => KeyFile.public_key(key),
      "shareName" => share.name,
      "protocol" => share.protocol,
      "target" => %{"host" => share.host, "port" => share.port}
    }

    nonce =
      case agent_post!(agent_socket, "/challenge", body, "challenge", timeout) do
        %{"nonce" => nonce} when is_binary(nonce) and nonce != "" -> nonce
        _ -> raise AgentError, code: "invalid-agent-response", message: "Hub Network agent returned an invalid challenge"
      end

    attestation = agent_post!(agent_socket, "/attest", Map.put(body, "signature", KeyFile.sign(key, nonce)), "attestation", timeout)
    validate_attestation!(attestation, share, KeyFile.public_key(key))
    attestation
  end

  defp wire_share(share) do
    base = %{"name" => share.name, "protocol" => share.protocol, "target" => %{"host" => share.host, "port" => share.port}}
    if share.policy, do: Map.put(base, "policy", share.policy), else: base
  end

  defp validate_publication!(%{} = p, share, index) do
    cond do
      p["version"] != @wire_version ->
        raise RuntimeError, "Invalid Hub publication version at share index #{index}"

      not (is_binary(p["resourceId"]) and String.starts_with?(p["resourceId"], "hnr1_") and byte_size(p["resourceId"]) > 5) ->
        raise RuntimeError, "Invalid Hub publication resourceId at share index #{index}"

      field = Enum.find(["authority", "providerId", "overlayAddress"], &(not (is_binary(p[&1]) and String.trim(p[&1]) != ""))) ->
        raise RuntimeError, "Invalid Hub publication #{field} at share index #{index}"

      p["protocol"] != share.protocol ->
        raise RuntimeError, "Hub publication protocol mismatch at share index #{index}"

      not (is_integer(p["port"]) and p["port"] in 1..65_535) ->
        raise RuntimeError, "Invalid Hub publication port at share index #{index}"

      true ->
        p
    end
  end

  defp validate_publication!(_value, _share, index) do
    raise RuntimeError, "Invalid Hub publication at share index #{index}"
  end

  defp validate_attestation!(attestation, share, service_key) do
    target = if is_map(attestation["target"]), do: attestation["target"], else: %{}

    unless attestation["version"] == @wire_version and attestation["serviceKey"] == service_key and
             attestation["shareName"] == share.name and attestation["protocol"] == share.protocol and
             target["host"] == share.host and target["port"] == share.port do
      raise AgentError, code: "attestation-mismatch", message: "Local-agent attestation does not match the share"
    end

    now = DateTime.utc_now()

    with {:ok, issued_at, _} <- DateTime.from_iso8601(to_string(attestation["issuedAt"])),
         {:ok, expires_at, _} <- DateTime.from_iso8601(to_string(attestation["expiresAt"])),
         true <- DateTime.compare(expires_at, issued_at) == :gt,
         true <- DateTime.compare(issued_at, DateTime.add(now, 30)) != :gt,
         true <- DateTime.compare(expires_at, now) == :gt do
      :ok
    else
      _ -> raise AgentError, code: "attestation-expired", message: "Local-agent attestation is expired"
    end
  end

  defp require_text!(value, field, max_length \\ nil) do
    valid =
      is_binary(value) and String.trim(value) != "" and (max_length == nil or String.length(value) <= max_length) and
        not String.match?(value, ~r/[\x00-\x1f\x7f]/)

    unless valid, do: raise(ArgumentError, "Invalid Hub Network #{field}")
  end

  # POSTs JSON to the agent over its Unix socket and decodes the JSON answer.
  defp agent_post!(socket_path, path, body, operation, timeout) do
    payload = Jason.encode!(body)

    request =
      "POST #{path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n" <>
        "Content-Length: #{byte_size(payload)}\r\nConnection: close\r\n\r\n" <> payload

    deadline = System.monotonic_time(:millisecond) + timeout

    raw =
      case :gen_tcp.connect({:local, String.to_charlist(socket_path)}, 0, [:binary, active: false], timeout) do
        {:ok, socket} ->
          try do
            :ok = :gen_tcp.send(socket, request)
            read_all(socket, "", deadline, timeout)
          after
            :gen_tcp.close(socket)
          end

        {:error, :timeout} ->
          raise AgentError, code: "agent-timeout", message: "Hub Network agent timed out after #{timeout} ms"

        {:error, _reason} ->
          raise AgentError, code: "agent-unavailable", message: "Hub Network agent is unavailable at #{socket_path}"
      end

    {code, headers, response} =
      case String.split(raw, "\r\n\r\n", parts: 2) do
        [head, response] ->
          [status | header_lines] = String.split(head, "\r\n")
          code = status |> String.split(" ") |> Enum.at(1, "0") |> Integer.parse() |> then(&if(&1 == :error, do: 0, else: elem(&1, 0)))
          {code, Enum.map(header_lines, &String.downcase/1), response}

        _ ->
          raise AgentError, code: "invalid-agent-response", message: "Hub Network agent returned an invalid response"
      end

    response =
      if Enum.any?(headers, &(String.starts_with?(&1, "transfer-encoding:") and String.contains?(&1, "chunked"))),
        do: dechunk(response),
        else: response

    unless code in 200..299 do
      detail = String.trim(response)

      raise AgentError,
        code: "agent-rejected",
        message: "Hub Network agent rejected #{operation} (#{code})" <> if(detail == "", do: "", else: ": " <> detail)
    end

    case Jason.decode(response) do
      {:ok, %{} = map} -> map
      _ -> raise AgentError, code: "invalid-agent-response", message: "Hub Network agent returned invalid JSON"
    end
  end

  defp read_all(socket, acc, deadline, timeout) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    case :gen_tcp.recv(socket, 0, remaining) do
      {:ok, data} -> read_all(socket, acc <> data, deadline, timeout)
      {:error, :closed} -> acc
      {:error, :timeout} -> raise AgentError, code: "agent-timeout", message: "Hub Network agent timed out after #{timeout} ms"
      {:error, _} -> raise AgentError, code: "agent-unavailable", message: "Hub Network agent connection failed"
    end
  end

  defp dechunk(body, acc \\ "") do
    with [size_line, rest] <- String.split(body, "\r\n", parts: 2),
         {size, _} when size > 0 <- size_line |> String.split(";") |> hd() |> String.trim() |> Integer.parse(16) do
      <<chunk::binary-size(^size), "\r\n", tail::binary>> = rest
      dechunk(tail, acc <> chunk)
    else
      _ -> acc
    end
  end
end
