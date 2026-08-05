# Echo service example for hub_service_ex.
#
# Run:  mix run example/echo.exs
# Verify (against a live hub on 1997):
#   bun ../hub-service/tests/verify.ts echo echo/upper '"hello"' '"HELLO"'
#   bun ../hub-service/tests/appcheck.ts echo/ui Echo

alias HubServiceEx, as: Service
alias HubServiceEx.App

service =
  Service.new(
    name: "Echo",
    icon: %{symbol: "speaker.wave.2", text: "E"}
  )
  |> Service.post("echo", fn body -> body end)
  |> Service.post("echo/upper", fn body -> String.upcase(to_string(body)) end)
  |> Service.app(
    App.new("Echo", "echo/ui", [
      App.text("Echo"),
      App.text_field("", placeholder: "Type something…"),
      App.cell(title: "Echo service", subtitle: "echo / echo/upper"),
      App.button("Upper", App.action("echo/upper", body: "hello"))
    ])
  )
  |> Service.start()

IO.puts("Echo service registered on hub (echo, echo/upper, echo/ui)")
Process.sleep(:infinity)
