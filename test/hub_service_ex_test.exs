defmodule HubServiceExTest do
  use ExUnit.Case, async: true

  alias HubServiceEx, as: Service
  alias HubServiceEx.App

  defp wire(payload), do: ChannelEx.JSON.encode!(payload)
  defp obj({list}), do: list

  test "update payload services are sorted by path, apps carry type app" do
    service =
      Service.new()
      |> Service.post("echo", fn body -> body end)
      |> Service.post("echo/upper", fn body -> body end)
      |> Service.stream("zebra", fn body -> [body] end)
      |> Service.app(App.new("Echo", "echo/ui", []))

    payload = Service.update_payload(service)
    services = :proplists.get_value("services", obj(payload))
    apps = :proplists.get_value("apps", obj(payload))

    assert Enum.map(services, &:proplists.get_value("path", obj(&1))) ==
             ["echo", "echo/ui", "echo/upper", "zebra"]

    assert apps ==
             [{[{"type", "app"}, {"name", "Echo"}, {"path", "echo/ui"}]}]
  end

  test "settings auto-fill permissions group from the first path segment" do
    service =
      Service.new()
      |> Service.post("echo", fn body -> body end,
        permissions: %{name: "Echo", allows: true},
        limit: 5
      )

    [entry] = :proplists.get_value("services", obj(Service.update_payload(service)))

    assert :proplists.get_value("permissions", obj(entry)) ==
             {[{"group", "echo"}, {"name", "Echo"}, {"allows", true}]}

    assert :proplists.get_value("limit", obj(entry)) == 5
  end

  test "update payload JSON equals the exact wire contract string" do
    service =
      Service.new()
      |> Service.post("echo", fn body -> body end,
        permissions: %{name: "Echo", allows: true},
        limit: 5
      )
      |> Service.app(App.new("Echo", "echo/ui", []))

    json = wire(Service.update_payload(service))

    assert json ==
             ~s({"services":[{"path":"echo","permissions":{"group":"echo","name":"Echo","allows":true},"limit":5},{"path":"echo/ui"}],"apps":[{"type":"app","name":"Echo","path":"echo/ui"}]})
  end

  test "send and values before start raise" do
    service = Service.new()

    assert_raise RuntimeError, "Service not started", fn ->
      Service.send(service, "echo", "hi")
    end

    assert_raise RuntimeError, "Service not started", fn ->
      Service.values(service, "echo")
    end
  end

  test "profile payload only when name/icon set; icon may be a map or string" do
    assert Service.profile_payload(Service.new()) == nil

    assert wire(
             Service.profile_payload(
               Service.new(name: "Echo", icon: %{symbol: "speaker.wave.2", text: "E"})
             )
           ) == ~s({"name":"Echo","icon":{"symbol":"speaker.wave.2","text":"E"}})

    assert wire(Service.profile_payload(Service.new(icon: "E"))) == ~s({"icon":"E"})
    assert wire(Service.profile_payload(Service.new(name: "Echo"))) == ~s({"name":"Echo"})
  end

  test "app interface has all 5 keys with null top/bottom and app header" do
    app =
      App.new("Echo", "echo/ui", [App.text("hi"), App.cell(title: "t")],
        data: %{"k" => "v"}
      )

    interface = App.interface(app)

    assert Map.keys(interface) |> Enum.sort() == [:body, :bottom, :data, :header, :top]
    assert interface.header == %{type: "app", name: "Echo", path: "echo/ui"}
    assert interface.top == :null
    assert interface.bottom == :null
    assert interface.data == %{"k" => "v"}

    assert interface.body == [
             %{type: "text", value: "hi"},
             %{type: "cell", title: "t"}
           ]
  end

  test "element helpers produce wire shapes" do
    assert App.text("hi", secondary: true) == %{type: "text", value: "hi", secondary: true}

    assert App.progress("50", min: 0, max: 100) ==
             %{type: "progress", value: "50", min: 0, max: 100}

    assert App.text_field("", placeholder: "Type", action: App.action("echo/upper")) ==
             %{type: "textField", value: "", placeholder: "Type", action: %{path: "echo/upper"}}

    assert App.button("Go", App.action("echo", body: "x")) ==
             %{type: "button", title: "Go", action: %{path: "echo", body: "x"}}

    assert App.slider("3", min: 0, max: 10, step: 1) ==
             %{type: "slider", value: "3", min: 0, max: 10, step: 1}

    assert App.list("data", App.text("row")) ==
             %{type: "list", data: "data", content: %{type: "text", value: "row"}}

    assert App.picker(["a", "b"], "a") ==
             %{type: "picker", options: ["a", "b"], selected: "a"}

    assert App.cell() == %{type: "cell"}

    assert App.hstack([App.spacer()]) ==
             %{type: "hstack", content: [%{type: "spacer"}]}

    assert App.action("echo", body: %{"k" => "v"}, output: "out") ==
             %{path: "echo", body: %{"k" => "v"}, output: "out"}
  end
end
