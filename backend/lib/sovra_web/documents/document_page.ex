defmodule SovraWeb.DocumentPage do
  @moduledoc """
  Renders a signed document as a standalone HTML page: the issuer's layout on an
  A4 sheet, a provenance footer, and a QR carrying the whole credential.

  Everything here is our rendering of the claims. The QR is what lets a reader
  check the signature instead of trusting the page.
  """

  alias Sovra.Documents
  alias Sovra.Documents.Attestation

  @page %{width: 794, height: 1123}
  @margin 48
  @footer_top 920
  @qr_size 130
  @default_color "#111827"

  # Kept in step with the issuer's canvas (frontend/issuer/src/lib/document-layout.ts).
  # Not the dashboard's webfonts: this page cannot load them, and different
  # metrics move every text. Helvetica and Arial are metric compatible, so the
  # sheet measures the same across systems.
  @font ~s("Helvetica Neue", Helvetica, Arial, sans-serif)
  @font_mono ~s(ui-monospace, SFMono-Regular, Menlo, "Courier New", monospace)

  # The print dialog is where a PDF comes from: the sheet is already laid out in
  # A4, so the browser writes a proper one.
  @print_script ~s[addEventListener("load", () => window.print())]
  @print_script_hash Base.encode64(:crypto.hash(:sha256, @print_script))

  @doc """
  A policy to send with the page. Nothing may load or run except the data URIs of
  the images and the page's own styles, so a value that slipped past escaping
  still cannot do anything.
  """
  def csp(opts \\ []) do
    script =
      if Keyword.get(opts, :print, false),
        do: " script-src 'sha256-#{@print_script_hash}';",
        else: ""

    # `frame-ancestors` does not fall back to `default-src`, so it is spelled out:
    # nobody gets to frame a signed document inside their own page.
    "default-src 'none'; img-src data:; style-src 'unsafe-inline'; " <>
      "frame-ancestors 'none';#{script}"
  end

  @doc """
  The document as a standalone page. With `print: true` it opens the browser's
  print dialog.
  """
  def render(document, opts \\ []) do
    layout = Documents.layout_for(document.schema_id) || %{}
    page = page_size(layout)
    # From the credential, never from a copy: the page must only be able to show
    # what the signature covers.
    claims = Attestation.claims(document.credential, document.schema)

    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>#{escape(document.schema.name)}</title>
    #{styles(page)}
    </head>
    <body>
    <div class="sheet">
    #{background(layout)}
    #{Enum.map_join(elements(layout), "\n", &element(&1, claims, page))}
    #{footer(document)}
    </div>
    #{print_script(opts)}
    </body>
    </html>
    """
  end

  defp print_script(opts) do
    if Keyword.get(opts, :print, false), do: "<script>#{@print_script}</script>", else: ""
  end

  defp background(layout) do
    case image_src(layout["background"]) do
      nil -> ""
      src -> ~s(<img class="bg" src="#{src}" alt="">)
    end
  end

  defp styles(page) do
    """
    <style>
    *{box-sizing:border-box}
    body{margin:0;background:#f3f4f6;font-family:#{@font}}
    .sheet{position:relative;width:#{page.width}px;height:#{page.height}px;margin:24px auto;background:#fff;
           box-shadow:0 1px 3px rgba(0,0,0,.2);overflow:hidden}
    .bg{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
    .el{position:absolute;white-space:nowrap;line-height:1.2}
    .el.text{white-space:pre-wrap;overflow-wrap:break-word}
    .footer{position:absolute;left:#{@margin}px;top:#{@footer_top}px;width:#{page.width - @margin * 2}px}
    .rule{height:1px;background:#d1d5db}
    .cols{display:flex;gap:16px;margin-top:16px}
    .fields{flex:1;min-width:0;display:grid;gap:10px}
    .row{display:flex;gap:10px;font-size:13px;line-height:1.35}
    .row .k{width:86px;flex:0 0 auto;color:#6b7280}
    .row .v{font-family:#{@font_mono};color:#374151;word-break:break-all}
    .row .v a{color:#1d4ed8}
    @media print{.row .v a{color:#374151;text-decoration:none}}
    .qr{flex:0 0 auto;width:#{@qr_size}px;height:#{@qr_size}px}
    @page{size:A4;margin:0}
    @media print{body{background:#fff}.sheet{margin:0;box-shadow:none}}
    </style>
    """
  end

  # Anything that is not a map is dropped: the renderer never trusts the layout's
  # shape, so a broken one costs a missing element and not a failed page.
  defp elements(layout) do
    case layout["elements"] do
      list when is_list(list) -> Enum.filter(list, &is_map/1)
      _ -> []
    end
  end

  defp element(%{"type" => "line"} = element, _claims, _page) do
    ~s(<div class="el" style="#{at(element)}) <>
      ~s(width:#{num(element["width"])}px;height:1px;background:#{color(element["color"])}"></div>)
  end

  defp element(%{"type" => "box"} = element, _claims, _page) do
    ~s(<div class="el" style="#{at(element)}) <>
      ~s(width:#{num(element["width"])}px;height:#{num(element["height"])}px;) <>
      ~s(background:#{color(element["color"])};border-radius:#{num(element["radius"])}px"></div>)
  end

  defp element(%{"type" => "image"} = element, _claims, _page) do
    case image_src(element["src"]) do
      nil ->
        ""

      src ->
        ~s(<img class="el" src="#{src}" alt="" style="#{at(element)}) <>
          ~s(width:#{num(element["width"])}px;height:#{num(element["height"])}px;object-fit:contain">)
    end
  end

  defp element(element, claims, page) do
    text =
      case element["type"] do
        "field" -> claims |> Map.get(element["bind"]) |> to_text()
        _ -> to_text(element["value"])
      end

    size = num(element["size"], 14)
    weight = if element["bold"], do: 700, else: 400
    room = max(0, page.width - @margin - num(element["x"]))

    # A fixed width keeps the box stable whatever the value turns out to be.
    # Without one the element hugs its text and wraps at the right margin.
    box =
      case element["width"] do
        w when is_number(w) -> "width:#{min(w, room)}px;"
        _ -> "max-width:#{room}px;"
      end

    ~s(<div class="el text" style="#{at(element)}#{box}text-align:#{align(element["align"])};) <>
      ~s(font-size:#{size}px;font-weight:#{weight};color:#{color(element["color"])};) <>
      ~s(#{fill(element, size)}">) <> escape(text) <> ~s(</div>)
  end

  defp align(value) when value in ["left", "center", "right"], do: value
  defp align(_value), do: "left"

  defp at(element), do: ~s(left:#{num(element["x"])}px;top:#{num(element["y"])}px;)

  # Background behind text hugs the content, so it fits whatever value arrives.
  defp fill(element, size) do
    case element["bg"] do
      bg when is_binary(bg) ->
        pad = round(size * 0.45)

        ~s(background:#{color(bg)};padding:#{pad}px #{round(pad * 1.6)}px;) <>
          ~s(border-radius:#{num(element["radius"], 4)}px;)

      _ ->
        ""
    end
  end

  defp footer(document) do
    rows = [
      {"Issued by", escape(issuer(document))},
      {"Transaction", transaction(document.tx_hash)},
      {"Digest", escape("0x" <> Documents.hex(document.digest))}
    ]

    """
    <div class="footer">
      <div class="rule"></div>
      <div class="cols">
        <div class="fields">
        #{Enum.map_join(rows, "\n", fn {label, value} -> ~s(<div class="row"><span class="k">#{escape(label)}</span><span class="v">#{value}</span></div>) end)}
        </div>
        <div class="qr">#{qr(document.credential)}</div>
      </div>
    </div>
    """
  end

  # Linked to the explorer on screen, still readable on paper.
  defp transaction(nil), do: "not anchored"

  defp transaction(hash) do
    url = explorer_url() <> "/tx/" <> hash
    ~s(<a href="#{escape(url)}" target="_blank" rel="noreferrer">#{escape(hash)}</a>)
  end

  defp explorer_url do
    Application.get_env(:sovra, :explorer_url, "https://explorer.testnet.sovra.io")
  end

  defp issuer(document) do
    [document.workspace.name, document.workspace.did]
    |> Enum.reject(&(&1 in [nil, ""]))
    |> Enum.join(" · ")
  end

  # PNG rather than SVG: the SVG is one rect per module, which is two orders of
  # magnitude heavier for a page that is served on every view. Rendered at four
  # times its display size so printing stays sharp.
  #
  # A QR tops out around 2.9 KB, so a document with a long enough claim does not
  # fit. Losing the QR is better than losing the page.
  defp qr(credential) do
    png =
      credential
      |> EQRCode.encode()
      |> EQRCode.png(width: @qr_size * 4)

    ~s(<img src="data:image/png;base64,#{Base.encode64(png)}" alt="" width="#{@qr_size}" height="#{@qr_size}">)
  rescue
    _ -> ""
  end

  defp page_size(layout) do
    case layout["page"] do
      %{"width" => w, "height" => h} when is_number(w) and is_number(h) -> %{width: w, height: h}
      _ -> @page
    end
  end

  defp num(value, default \\ 0)
  defp num(value, _default) when is_integer(value), do: value
  defp num(value, _default) when is_float(value), do: Float.round(value, 2)
  defp num(_value, default), do: default

  # Only base64 data URIs, and only the two types the editor accepts. Nothing
  # else reaches a src attribute: no http, no javascript, no unencoded payload.
  @image_uri ~r"^data:image/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$"

  defp image_src(value) when is_binary(value) do
    if Regex.match?(@image_uri, value), do: value, else: nil
  end

  defp image_src(_value), do: nil

  # Layout colors are issuer-controlled but still end up inside a style
  # attribute, so anything that is not a plain hex color is dropped.
  defp color(value) when is_binary(value) do
    if Regex.match?(~r/^#[0-9a-fA-F]{3,8}$/, value), do: value, else: @default_color
  end

  defp color(_value), do: @default_color

  defp to_text(nil), do: ""
  defp to_text(value) when is_binary(value), do: value
  defp to_text(value) when is_number(value) or is_boolean(value), do: to_string(value)
  defp to_text(value), do: inspect(value)

  defp escape(value), do: value |> to_text() |> Plug.HTML.html_escape()
end
