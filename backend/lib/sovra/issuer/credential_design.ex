defmodule Sovra.Issuer.CredentialDesign do
  use Ecto.Schema
  import Ecto.Changeset

  alias Sovra.Issuer.ClaimUtils

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  @path_format ~r/^\$\.[A-Za-z_][A-Za-z0-9_]*$/

  defmodule DisplayMapping do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key false
    embedded_schema do
      field :text, :string
      field :path, {:array, :string}
      field :schema, :map
      field :fallback, :string
      field :label, :string
    end

    def changeset(mapping, attrs) do
      mapping
      |> cast(attrs, [:text, :path, :schema, :fallback, :label])
      |> validate_text_or_path()
    end

    defp validate_text_or_path(cs) do
      text = get_field(cs, :text)
      path = get_field(cs, :path)

      cond do
        is_binary(text) and text != "" and is_list(path) and path != [] ->
          add_error(cs, :text, "provide either text or path, not both")

        (is_nil(text) or text == "") and (is_nil(path) or path == []) ->
          add_error(cs, :text, "one of text or path must be present")

        true ->
          cs
      end
    end
  end

  defmodule Display do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key false
    embedded_schema do
      embeds_one :title, Sovra.Issuer.CredentialDesign.DisplayMapping, on_replace: :update
      embeds_one :subtitle, Sovra.Issuer.CredentialDesign.DisplayMapping, on_replace: :update
      embeds_one :description, Sovra.Issuer.CredentialDesign.DisplayMapping, on_replace: :update
      embeds_many :properties, Sovra.Issuer.CredentialDesign.DisplayMapping, on_replace: :delete
    end

    def changeset(display, attrs) do
      display
      |> cast(attrs, [])
      |> cast_embed(:title)
      |> cast_embed(:subtitle)
      |> cast_embed(:description)
      |> cast_embed(:properties)
    end
  end

  defmodule ImageRef do
    use Ecto.Schema
    import Ecto.Changeset

    @max_uri_bytes 256 * 1024

    @primary_key false
    embedded_schema do
      field :uri, :string
      field :alt, :string
    end

    def changeset(ref, attrs) do
      ref
      |> cast(attrs, [:uri, :alt])
      |> validate_required([:uri])
      |> validate_change(:uri, fn :uri, uri ->
        if byte_size(uri) > @max_uri_bytes,
          do: [uri: "must be 256KB or smaller"],
          else: []
      end)
    end
  end

  defmodule ColorRef do
    use Ecto.Schema
    import Ecto.Changeset

    @hex_color ~r/^#[0-9a-fA-F]{6}$/

    @primary_key false
    embedded_schema do
      field :color, :string
    end

    def changeset(ref, attrs) do
      ref
      |> cast(attrs, [:color])
      |> validate_required([:color])
      |> validate_format(:color, @hex_color, message: "must be a hex color like #rrggbb")
    end
  end

  defmodule Styles do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key false
    embedded_schema do
      embeds_one :thumbnail, Sovra.Issuer.CredentialDesign.ImageRef, on_replace: :update
      embeds_one :hero, Sovra.Issuer.CredentialDesign.ImageRef, on_replace: :update
      embeds_one :background, Sovra.Issuer.CredentialDesign.ColorRef, on_replace: :update
      embeds_one :text, Sovra.Issuer.CredentialDesign.ColorRef, on_replace: :update
    end

    def changeset(styles, attrs) do
      styles
      |> cast(attrs, [])
      |> cast_embed(:thumbnail)
      |> cast_embed(:hero)
      |> cast_embed(:background)
      |> cast_embed(:text)
    end
  end

  defmodule Back do
    use Ecto.Schema
    import Ecto.Changeset

    @primary_key false
    embedded_schema do
      embeds_one :display, Sovra.Issuer.CredentialDesign.Display, on_replace: :update
      embeds_one :styles, Sovra.Issuer.CredentialDesign.Styles, on_replace: :update
    end

    def changeset(back, attrs) do
      back
      |> cast(attrs, [])
      |> cast_embed(:display)
      |> cast_embed(:styles)
    end
  end

  schema "credential_designs" do
    field :name, :string
    field :description, :string
    embeds_one :display, Display, on_replace: :update
    embeds_one :styles, Styles, on_replace: :update
    embeds_one :back, Back, on_replace: :delete
    field :version, :integer, default: 1

    belongs_to :credential_schema, Sovra.Issuer.CredentialSchema

    timestamps(type: :utc_datetime)
  end

  @required ~w(name credential_schema_id)a
  @optional ~w(description)a

  def create_changeset(attrs, opts \\ []) do
    %__MODULE__{}
    |> cast(attrs, @required ++ @optional)
    |> validate_required(@required)
    |> cast_embed(:display, required: true)
    |> cast_embed(:styles, required: true)
    |> cast_embed(:back)
    |> unique_constraint(:credential_schema_id)
    |> validate_property_paths(opts[:schema_claims])
  end

  def update_changeset(design, attrs, opts \\ []) do
    design
    |> cast(attrs, [:name, :description])
    |> validate_required([:name])
    |> cast_embed(:display)
    |> cast_embed(:styles)
    |> cast_embed(:back)
    |> put_change(:version, (design.version || 1) + 1)
    |> validate_property_paths(opts[:schema_claims])
  end

  defp validate_property_paths(cs, nil), do: cs

  defp validate_property_paths(cs, claim_defs) do
    allowed_keys =
      ClaimUtils.parse_claim_defs(claim_defs) |> Enum.map(& &1["key"]) |> MapSet.new()

    cs
    |> validate_display_paths(allowed_keys, :display)
    |> validate_back_paths(allowed_keys)
  end

  defp validate_back_paths(cs, allowed_keys) do
    case get_change(cs, :back) || get_field(cs, :back) do
      nil ->
        cs

      _back ->
        # back.display is nested; we validate via the embedded changeset path by
        # walking get_change on the back changeset
        case get_change(cs, :back) do
          %Ecto.Changeset{} = back_cs ->
            back_display = get_change(back_cs, :display) || get_field(back_cs, :display)
            validate_display_change(cs, back_display, allowed_keys, [:back, :display])

          _ ->
            cs
        end
    end
  end

  defp validate_display_paths(cs, allowed_keys, key) do
    display = get_change(cs, key) || get_field(cs, key)
    validate_display_change(cs, display, allowed_keys, [key])
  end

  defp validate_display_change(cs, nil, _allowed, _path_prefix), do: cs

  defp validate_display_change(cs, %Ecto.Changeset{} = display_cs, allowed, _prefix) do
    mappings =
      [:title, :subtitle, :description]
      |> Enum.flat_map(fn k ->
        case get_change(display_cs, k) || get_field(display_cs, k) do
          nil -> []
          m -> [m]
        end
      end)

    properties = get_change(display_cs, :properties) || get_field(display_cs, :properties) || []

    (mappings ++ properties)
    |> Enum.reduce(cs, fn mapping, acc -> validate_mapping_paths(acc, mapping, allowed) end)
  end

  defp validate_display_change(cs, %Display{} = display, allowed, _prefix) do
    mappings =
      [display.title, display.subtitle, display.description]
      |> Enum.reject(&is_nil/1)

    (mappings ++ (display.properties || []))
    |> Enum.reduce(cs, fn mapping, acc -> validate_mapping_paths(acc, mapping, allowed) end)
  end

  defp validate_mapping_paths(cs, %Ecto.Changeset{} = mapping_cs, allowed) do
    path = get_change(mapping_cs, :path) || get_field(mapping_cs, :path)
    check_path_list(cs, path, allowed)
  end

  defp validate_mapping_paths(cs, %DisplayMapping{path: path}, allowed) do
    check_path_list(cs, path, allowed)
  end

  defp check_path_list(cs, nil, _), do: cs
  defp check_path_list(cs, [], _), do: cs

  defp check_path_list(cs, paths, allowed) do
    Enum.reduce(paths, cs, fn p, acc ->
      cond do
        not Regex.match?(@path_format, p) ->
          add_error(acc, :display, "path #{inspect(p)} must be of form $.<claim_key>")

        true ->
          "$." <> key = p

          if MapSet.member?(allowed, key) do
            acc
          else
            add_error(acc, :display, "path #{inspect(p)} does not reference a known schema claim")
          end
      end
    end)
  end
end
