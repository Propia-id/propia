defmodule Sovra.Verification.ExpiredSessionsSweeperTest do
  use Sovra.DataCase, async: false
  use Oban.Testing, repo: Sovra.Repo

  import Ecto.Query

  alias Sovra.Accounts.User
  alias Sovra.Organizations.Organization
  alias Sovra.Verification
  alias Sovra.Verification.ExpiredSessionsSweeper
  alias Sovra.Verification.Session
  alias Sovra.Workspaces

  defp create_workspace do
    {:ok, account} =
      User.admin_changeset(%{
        email: "user-#{System.unique_integer([:positive])}@example.com",
        password: "a-very-strong-password-123"
      })
      |> Repo.insert()

    {:ok, org} =
      %{name: "Org #{System.unique_integer([:positive])}"}
      |> Organization.create_changeset()
      |> Repo.insert()

    {:ok, %{workspace: ws}} = Workspaces.create_workspace(org.id, %{name: "V"}, account.id)
    ws
  end

  defp dcql_query do
    %{
      "credentials" => [
        %{"id" => "x", "format" => "vc+sd-jwt", "claims" => [%{"path" => ["a"]}]}
      ]
    }
  end

  defp force_expiry(session, offset_seconds) do
    new_exp =
      DateTime.utc_now()
      |> DateTime.add(offset_seconds, :second)
      |> DateTime.truncate(:second)

    Repo.update_all(
      from(s in Session, where: s.id == ^session.id),
      set: [expires_at: new_exp]
    )
  end

  test "marks expired pending sessions as expired" do
    ws = create_workspace()
    {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())
    force_expiry(session, -3600)

    assert :ok = perform_job(ExpiredSessionsSweeper, %{})

    refreshed = Repo.get!(Session, session.id)
    assert refreshed.status == "expired"
    assert refreshed.completed_at != nil
  end

  test "leaves still-pending sessions alone" do
    ws = create_workspace()
    {:ok, %{session: session}} = Verification.create_session(ws.id, dcql_query())

    assert :ok = perform_job(ExpiredSessionsSweeper, %{})

    refreshed = Repo.get!(Session, session.id)
    assert refreshed.status == "pending"
    assert refreshed.completed_at == nil
  end

  test "doesn't touch completed or failed sessions even if expired" do
    ws = create_workspace()
    {:ok, %{session: completed}} = Verification.create_session(ws.id, dcql_query())
    {:ok, %{session: failed}} = Verification.create_session(ws.id, dcql_query())

    Repo.update_all(
      from(s in Session, where: s.id == ^completed.id),
      set: [status: "completed"]
    )

    Repo.update_all(
      from(s in Session, where: s.id == ^failed.id),
      set: [status: "failed"]
    )

    force_expiry(completed, -3600)
    force_expiry(failed, -3600)

    assert :ok = perform_job(ExpiredSessionsSweeper, %{})

    assert Repo.get!(Session, completed.id).status == "completed"
    assert Repo.get!(Session, failed.id).status == "failed"
  end
end
