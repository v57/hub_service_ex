defmodule HubServiceEx.CallerTest do
  use ExUnit.Case, async: true

  alias HubServiceEx.{Caller, Request}

  test "no hub context means no caller" do
    assert Caller.from_context(nil) == nil
    assert Caller.from_context(%{"service" => "x"}) == nil
    request = Request.from(%{path: "echo", body: "hi", context: %{}})
    assert request.caller == nil
    assert request.hub_key == nil
    assert request.context == %{}
  end

  test "an anonymous caller has no key or device" do
    caller = Caller.from_context(%{"hub" => %{"caller" => %{"groups" => [], "owner" => false}}})
    assert caller.key == nil
    refute Caller.device?(caller)
    refute caller.owner
    assert caller.groups == []
  end

  test "a merged hub caller keeps the unverified claim" do
    caller =
      Caller.from_context(%{
        "hub" => %{
          "caller" => %{
            "key" => "merging",
            "groups" => ["g1", 5],
            "owner" => false,
            "via" => "merged-hub",
            "claimed" => %{"key" => "remote", "device" => %{"id" => "d1", "name" => "Phone"}, "owner" => true}
          }
        }
      })

    assert caller.key == "merging"
    assert caller.groups == ["g1"]
    assert caller.via == "merged-hub"
    assert caller.claimed.key == "remote"
    assert caller.claimed.device_name == "Phone"
    assert caller.claimed.owner
  end
end
