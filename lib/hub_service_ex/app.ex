defmodule HubServiceEx.App do
  @moduledoc """
  A hub app: a header (`type`/`name`/`path`) plus a UI body of elements
  (TS app.ts parity).

  Body entries may be plain strings (shorthand text) or element maps built
  with the helpers below: `text/2`, `progress/2`, `text_field/2`, `button/2`,
  `slider/2`, `list/2`, `picker/2`, `cell/1`, `files/3`, `file_operation/2`,
  `hstack/2`, `vstack/2`, `zstack/1`, `spacer/0`.
  """

  defstruct header: nil, body: [], top: nil, bottom: nil, data: %{}

  @type t :: %__MODULE__{}

  @doc """
  Creates an App.

  Options:
    * `:data` — map of app data (default `%{}`)
    * `:top` — top element (default nil)
    * `:bottom` — bottom element (default nil)
  """
  def new(name, path, body, options \\ [])
      when is_binary(name) and is_binary(path) and is_list(body) do
    %__MODULE__{
      header: %{type: "app", name: name, path: path},
      body: body,
      top: options[:top],
      bottom: options[:bottom],
      data: options[:data] || %{}
    }
  end

  @doc """
  The AppInterface map streamed at the app path: all 5 keys (`header`, `body`,
  `top`, `bottom`, `data`) always present. `top`/`bottom` encode as JSON `null`
  when unset.
  """
  def interface(%__MODULE__{} = app) do
    %{
      header: app.header,
      body: app.body,
      top: app.top || :null,
      bottom: app.bottom || :null,
      data: app.data || %{}
    }
  end

  @doc "text element; `secondary: true` marks secondary text."
  def text(value, options \\ []) do
    element = %{type: "text", value: value}
    if options[:secondary], do: Map.put(element, :secondary, true), else: element
  end

  @doc "progress element. Options: `:min`, `:max`."
  def progress(value, options \\ []) do
    element = %{type: "progress", value: value}

    element =
      if options[:min] != nil, do: Map.put(element, :min, options[:min]), else: element

    if options[:max] != nil, do: Map.put(element, :max, options[:max]), else: element
  end

  @doc "textField element. Options: `:placeholder`, `:action`."
  def text_field(value, options \\ []) do
    element = %{type: "textField", value: value}

    element =
      if options[:placeholder] != nil,
        do: Map.put(element, :placeholder, options[:placeholder]),
        else: element

    if options[:action] != nil, do: Map.put(element, :action, options[:action]), else: element
  end

  @doc "button element."
  def button(title, action), do: %{type: "button", title: title, action: action}

  @doc "slider element. Options: `:defaultValue`, `:min`, `:max`, `:step`, `:action`."
  def slider(value, options \\ []) do
    element = %{type: "slider", value: value}

    element =
      if options[:defaultValue] != nil,
        do: Map.put(element, :defaultValue, options[:defaultValue]),
        else: element

    element =
      if options[:min] != nil, do: Map.put(element, :min, options[:min]), else: element

    element =
      if options[:max] != nil, do: Map.put(element, :max, options[:max]), else: element

    element =
      if options[:step] != nil, do: Map.put(element, :step, options[:step]), else: element

    if options[:action] != nil, do: Map.put(element, :action, options[:action]), else: element
  end

  @doc "list element."
  def list(data, content), do: %{type: "list", data: data, content: content}

  @doc "picker element."
  def picker(options, selected), do: %{type: "picker", options: options, selected: selected}

  @doc "cell element. Options: `:title`, `:subtitle`."
  def cell(options \\ []) do
    element = %{type: "cell"}

    element =
      if options[:title] != nil, do: Map.put(element, :title, options[:title]), else: element

    if options[:subtitle] != nil,
      do: Map.put(element, :subtitle, options[:subtitle]),
      else: element
  end

  @doc "files element. Options: `:title`."
  def files(value, action, options \\ []) do
    element = %{type: "files", value: value, action: action}
    if options[:title] != nil, do: Map.put(element, :title, options[:title]), else: element
  end

  @doc "fileOperation element. Options: `:format`, `:title`."
  def file_operation(action, options \\ []) do
    element = %{type: "fileOperation", action: action}

    element =
      if options[:format] != nil, do: Map.put(element, :format, options[:format]), else: element

    if options[:title] != nil, do: Map.put(element, :title, options[:title]), else: element
  end

  @doc "hstack element. Options: `:spacing`."
  def hstack(content, options \\ []) do
    element = %{type: "hstack", content: content}
    if options[:spacing] != nil, do: Map.put(element, :spacing, options[:spacing]), else: element
  end

  @doc "vstack element. Options: `:spacing`."
  def vstack(content, options \\ []) do
    element = %{type: "vstack", content: content}
    if options[:spacing] != nil, do: Map.put(element, :spacing, options[:spacing]), else: element
  end

  @doc "zstack element."
  def zstack(content), do: %{type: "zstack", content: content}

  @doc "spacer element."
  def spacer, do: %{type: "spacer"}

  @doc "Action referencing an API call from a UI element. Options: `:body`, `:output`."
  def action(path, options \\ []) do
    element = %{path: path}

    element =
      if options[:body] != nil, do: Map.put(element, :body, options[:body]), else: element

    if options[:output] != nil, do: Map.put(element, :output, options[:output]), else: element
  end
end
