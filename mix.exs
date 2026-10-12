defmodule HubServiceEx.MixProject do
  use Mix.Project

  def project do
    [
      app: :hub_service_ex,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:channel_ex, path: "../../Channel/channel_ex"}
    ]
  end
end
