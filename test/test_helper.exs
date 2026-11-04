# A channel server standing in for hub-server: it answers `hub/info` as told and
# reports every connection's headers to the test. Its tokens are checked by the tests.
defmodule HubServiceEx.FakeHub do
  alias HubServiceEx.{HubProof, KeyFile}

  @vectors __DIR__ |> Path.join("fixtures/device-vectors.json") |> File.read!() |> Jason.decode!()

  def key(name), do: KeyFile.parse!(@vectors["keys"][name]["keyFile"])

  @doc "A `hub/info` answer claiming `claimed`, signed with `key`."
  def proof(key, claimed, nonce, challenge) do
    %{
      "key" => claimed,
      "protocol" => 2,
      "challenge" => challenge,
      "proof" => KeyFile.sign(key, HubProof.signed_data(claimed, nonce))
    }
  end

  @doc "Answers as a hub proving the vectors' key `name`."
  def proving(name) do
    key = key(name)
    fn nonce, challenge -> proof(key, KeyFile.public_key(key), nonce, challenge) end
  end

  @doc "Makes `channel` answer hub/info with a proof of the vectors' hub key and a fresh challenge."
  def answer_hub_info(channel, answer \\ proving("hub"), notify \\ fn _nonce -> :ok end) do
    counter = :counters.new(1, [])

    ChannelEx.post(channel, "hub/info", fn request ->
      nonce = nonce(request.body)
      :counters.add(counter, 1, 1)
      notify.(nonce)
      answer.(nonce, "challenge-#{:counters.get(counter, 1)}")
    end)
  end

  defp nonce(%{"nonce" => nonce}) when is_binary(nonce), do: nonce
  defp nonce(_body), do: ""
end

ExUnit.start()
