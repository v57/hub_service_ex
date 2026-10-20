defmodule HubServiceEx.DeviceTest do
  # Keychain state (key path override) is process-global — no async.
  use ExUnit.Case, async: false

  alias HubServiceEx.{Device, KeyFile, Keychain}

  setup do
    tmp = Path.join(System.tmp_dir!(), "hub_service_ex_device_#{System.unique_integer([:positive])}")
    File.mkdir_p!(tmp)
    Keychain.set_key_path(Path.join(tmp, "auth"))

    on_exit(fn ->
      Keychain.reset()
      File.rm_rf(tmp)
    end)

    %{tmp: tmp, device_key_path: Path.join([tmp, "dev", "device.key"])}
  end

  defp service(ctx, options) do
    HubServiceEx.new(options ++ [address: 4100, device_key_path: ctx.device_key_path, device_name: "box"])
  end

  defp verifies?(public_key, data, signature) do
    raw = public_key |> Base.decode64!() |> binary_part(12, 32)
    :crypto.verify(:eddsa, :ed25519, data, Base.decode64!(signature), [raw, :ed25519])
  end

  test "creates the device key with private modes", %{tmp: tmp} do
    path = Path.join([tmp, "hub", "device.key"])
    key = Device.load_or_create_key(path)
    assert byte_size(File.read!(path)) == 124
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
    assert Bitwise.band(File.stat!(Path.dirname(path)).mode, 0o777) == 0o700
    assert KeyFile.public_key(Device.load_or_create_key(path)) == KeyFile.public_key(key)
    assert File.ls!(Path.dirname(path)) == ["device.key"]
  end

  test "connect headers carry a signed certificate", ctx do
    service = service(ctx, name: "Echo", device_name: "Mac Studio", platform: "macos")
    headers = HubServiceEx.connect_headers(service)
    [payload_part, signature] = String.split(headers["device"], ".")
    payload = Device.decode_certificate(headers["device"])
    device_key = KeyFile.public_key(KeyFile.load!(ctx.device_key_path))

    assert verifies?(device_key, payload_part, signature)
    assert payload["v"] == 1
    assert payload["device"] == device_key
    assert payload["service"] == Keychain.public_key()
    assert ["key", service_key | _] = String.split(headers["auth"], ".")
    assert payload["service"] == service_key
    assert payload["instance"] == "Echo"
    assert payload["deviceName"] == "Mac Studio"
    assert payload["platform"] == "macos"
    refute Map.has_key?(payload, "parent")
    assert payload["exp"] - payload["iat"] == Device.certificate_lifetime()
    assert_in_delta payload["iat"], System.system_time(:second), 2
  end

  test "the certificate is reused until renewal", ctx do
    service = service(ctx, [])
    {first, cache} = Device.header(service, Device.new_cache(), 1_000_000)
    assert {^first, _} = Device.header(service, cache, 1_000_000 + 3600)
    {renewed, _} = Device.header(service, cache, 1_000_000 + Device.certificate_lifetime() - 3600)
    assert renewed != first
  end

  test "instance defaults", ctx do
    assert HubServiceEx.instance(service(ctx, name: "Backup", instance: "s3-local/Backup Disk")) ==
             "s3-local/Backup Disk"

    assert HubServiceEx.instance(service(ctx, name: "Backup")) == "Backup"
    unnamed = ctx |> service([]) |> HubServiceEx.post("s3/read", & &1)
    assert HubServiceEx.instance(unnamed) == Path.basename(File.cwd!())
  end

  test "parent is declared", ctx do
    headers = HubServiceEx.connect_headers(service(ctx, device_name: "builder", platform: "linux", parent: "Mac Studio"))
    assert Device.decode_certificate(headers["device"])["parent"] == "Mac Studio"
  end

  test "device mode can be turned off", ctx do
    refute Map.has_key?(HubServiceEx.connect_headers(service(ctx, device: false)), "device")
    refute File.exists?(ctx.device_key_path)
  end

  test "a caller-provided key is used", ctx do
    key = KeyFile.generate()
    headers = HubServiceEx.connect_headers(service(ctx, device_key: key))
    assert Device.decode_certificate(headers["device"])["device"] == KeyFile.public_key(key)
    refute File.exists?(ctx.device_key_path)
  end

  test "an unreadable device key turns device mode off", %{tmp: tmp} do
    path = Path.join(tmp, "bad.key")
    File.write!(path, "garbage")

    {header, cache} =
      ExUnit.CaptureIO.with_io(:stderr, fn ->
        Device.header(HubServiceEx.new(device_key_path: path), Device.new_cache())
      end)
      |> elem(0)

    assert header == nil
    assert cache.off
  end
end
