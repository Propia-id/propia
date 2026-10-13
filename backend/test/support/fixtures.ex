defmodule Sovra.Fixtures do
  @moduledoc """
  Shared test fixtures for users, organizations, workspaces, and webhooks.

  Auto-imported into every `Sovra.DataCase` and `SovraWeb.ConnCase` test
  via the `using` blocks of those case templates, so test files don't have
  to redefine the same `defp create_workspace/0` over and over.

  Each helper returns the freshly inserted record. `fixture_workspace/1`
  returns a map with `:workspace`, `:owner`, and `:org` so call sites can
  pattern-match what they need.
  """

  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Repo
  alias Sovra.Webhooks
  alias Sovra.Workspaces

  @doc """
  Insert a fresh user with a unique email.

  Uses `User.admin_changeset/1`, since that's the only path that doesn't
  require a workspace — fixtures must be usable in tests that exercise
  `Organizations`, `Workspaces`, etc. in isolation.

  Pass an explicit `suffix` to make the email deterministic in tests that
  care about the value.
  """
  def fixture_user(suffix \\ unique_suffix()) do
    {:ok, account} =
      User.admin_changeset(%{
        email: "user-#{suffix}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    account
  end

  @doc "Insert a fresh organization with a unique name."
  def fixture_org(suffix \\ unique_suffix()) do
    {:ok, org} =
      %{name: "Org #{suffix}"}
      |> Organization.create_changeset()
      |> Repo.insert()

    org
  end

  @doc """
  Create a workspace and return `%{workspace, owner, org}`.

  Options:
    * `:owner`        — a pre-existing user (default: a fresh `fixture_user/0`)
    * `:org`          — a pre-existing org  (default: a fresh `fixture_org/0`)
    * `:name`         — workspace name      (default: a unique name)
  """
  def fixture_workspace(opts \\ []) do
    owner = Keyword.get_lazy(opts, :owner, &fixture_user/0)
    org = Keyword.get_lazy(opts, :org, &fixture_org/0)
    name = Keyword.get(opts, :name, "Workspace #{unique_suffix()}")

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: name}, owner.id)

    %{workspace: ws, owner: owner, org: org}
  end

  @doc """
  Add a webhook endpoint to a workspace (or workspace id) and return
  `%{webhook, secret}`. Subscribed to every event type unless `attrs` says
  otherwise.

  Tests that assert on enqueued `Sovra.Webhooks.DeliveryJob`s need one: with
  no endpoint subscribed, an event enqueues nothing.
  """
  def fixture_webhook(workspace, attrs \\ %{})

  def fixture_webhook(%{id: workspace_id}, attrs), do: fixture_webhook(workspace_id, attrs)

  def fixture_webhook(workspace_id, attrs) when is_binary(workspace_id) do
    attrs =
      Map.merge(
        %{url: "https://example.com/hook-#{unique_suffix()}", events: Webhooks.event_types()},
        Map.new(attrs)
      )

    {:ok, %{webhook: webhook, secret: secret}} = Webhooks.create_webhook(workspace_id, attrs)
    %{webhook: webhook, secret: secret}
  end

  defp unique_suffix, do: System.unique_integer([:positive])
end
