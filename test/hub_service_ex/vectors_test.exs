defmodule HubServiceEx.VectorsTest do
  # The device layer test vectors (Docs/Devices/vectors.json, copied to
  # test/fixtures/device-vectors.json). Ed25519 is deterministic, so the
  # exact strings must match.
  use ExUnit.Case, async: true

  alias HubServiceEx.{Caller, Device, HubProof, KeyFile, Keychain}

  @vectors __DIR__ |> Path.join("../fixtures/device-vectors.json") |> File.read!() |> Jason.decode!()

  defp key(name), do: KeyFile.parse!(@vectors["keys"][name]["keyFile"])
  defp public_key(name), do: @vectors["keys"][name]["publicKey"]

  test "key files give the public keys" do
    for name <- ["hub", "service", "device"] do
      assert KeyFile.public_key(key(name)) == public_key(name)
    end
  end

  test "device id and safety code" do
    assert Device.id(public_key("device")) == @vectors["keys"]["device"]["deviceId"]

    for code <- @vectors["safetyCode"]["cases"] do
      assert Device.safety_code(code["hubKey"], code["deviceKey"], code["codeValue"]) == code["code"]
    end
  end

  test "auth token" do
    auth = @vectors["auth"]
    service = key("service")

    assert auth["v1"]["signedData"] == "hub1:#{public_key("hub")}:#{auth["nonce"]}:#{auth["expiry"]}"
    assert KeyFile.sign(service, auth["v1"]["signedData"]) == auth["v1"]["signature"]
    assert Keychain.token(service, public_key("hub"), auth["nonce"], auth["expiry"]) == auth["v1"]["header"]
  end

  test "hub/info proof" do
    vector = @vectors["hubInfo"]
    hub = public_key("hub")
    nonce = vector["nonce"]
    info = %{"key" => hub, "proof" => vector["proof"], "challenge" => "c"}

    assert HubProof.signed_data(hub, nonce) == vector["signedData"]
    assert HubProof.proves?(info, nonce)
    refute HubProof.proves?(info, "another-nonce-another-nonce")
    refute HubProof.proves?(%{info | "key" => public_key("service")}, nonce)
    refute HubProof.proves?(Map.delete(info, "proof"), nonce)
    refute HubProof.proves?(Map.delete(info, "challenge"), nonce)
    refute HubProof.proves?(%{info | "proof" => "not base64!"}, nonce)
    refute HubProof.proves?(%{info | "key" => "not a key"}, nonce)
    refute HubProof.proves?(nil, nonce)
  end

  test "transports" do
    names = %{
      "encrypted" => :encrypted,
      "loopback" => :loopback,
      "overlay" => :overlay,
      "localNetwork" => :local_network,
      "refused" => :refused
    }

    assert @vectors["transport"] != []

    for %{"url" => url, "transport" => transport} <- @vectors["transport"] do
      assert {url, HubProof.transport_of(url)} == {url, names[transport]}
    end

    assert HubProof.transport_of(1997) == :loopback
    assert HubProof.transport_of("1997") == :loopback
    assert HubProof.transport_of("hub:1997") == :refused
  end

  test "certificate" do
    check_certificate(@vectors["certificate"], "s3-local/Backup Disk", "Mac Studio", "macos", nil)
  end

  test "child certificate with a parent" do
    check_certificate(@vectors["childCertificate"], "builder", "builder", "linux", "Mac Studio")
  end

  defp check_certificate(vector, instance, device_name, platform, parent) do
    device = key("device")

    payload =
      Device.certificate_payload(
        KeyFile.public_key(device),
        KeyFile.public_key(key("service")),
        instance,
        device_name,
        platform,
        parent,
        1_792_500_000,
        1_793_104_800
      )

    assert Device.payload_json(payload) == vector["json"]
    header = Device.certificate(device, payload)
    assert header == vector["header"]
    assert header == vector["payload"] <> "." <> vector["signature"]
    assert KeyFile.sign(device, vector["payload"]) == vector["signature"]
    assert Device.decode_certificate(header) == Jason.decode!(vector["json"])
  end

  test "caller context" do
    context = @vectors["caller"]["context"]
    caller = Caller.from_context(context)
    assert caller.key == public_key("service")
    assert caller.device_id == @vectors["keys"]["device"]["deviceId"]
    assert caller.device_name == "Mac Studio"
    assert caller.groups == ["owners"]
    assert caller.owner
    assert Caller.hub_key(context) == public_key("hub")
  end
end
