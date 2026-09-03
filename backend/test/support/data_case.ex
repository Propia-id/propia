defmodule Sovra.DataCase do
  @moduledoc """
  This module defines the setup for tests requiring
  access to the application's data layer.

  You may define functions here to be used as helpers in
  your tests.

  Finally, if the test case interacts with the database,
  we enable the SQL sandbox, so changes done to the database
  are reverted at the end of every test. If you are using
  PostgreSQL, you can even run database tests asynchronously
  by setting `use Sovra.DataCase, async: true`, although
  this option is not recommended for other databases.
  """

  use ExUnit.CaseTemplate

  require Logger

  using do
    quote do
      alias Sovra.Repo

      import Ecto
      import Ecto.Changeset
      import Ecto.Query
      import Sovra.DataCase
      import Sovra.Fixtures
    end
  end

  setup tags do
    Sovra.DataCase.setup_sandbox(tags)
    :ok
  end

  @doc """
  Sets up the sandbox based on the test tags.
  """
  def setup_sandbox(tags) do
    pid = Ecto.Adapters.SQL.Sandbox.start_owner!(Sovra.Repo, shared: not tags[:async])
    on_exit(fn -> Ecto.Adapters.SQL.Sandbox.stop_owner(pid) end)
  end

  @doc """
  Drain the workspace provisioning queue and reload the workspace. Use in
  tests that need a fully provisioned workspace (signing key, EOA, DID,
  `provisioning_status: "done"`). Relies on the test config wiring of
  `SovraTest.Ethereum.StubDIDRegistry` so the on-chain step succeeds
  without a live node.
  """
  def provision_workspace(%Sovra.Workspaces.Workspace{} = workspace) do
    Oban.drain_queue(queue: :provisioning, with_safety: false)

    # drain_queue/1 runs the job inline in the test process, so the context
    # Sovra.Log.adopt_job_context/1 sets would stay on this process and tag
    # every later line in the test. Production is unaffected — Oban runs each
    # attempt in its own task.
    Logger.metadata(oban_job_id: nil, oban_attempt: nil)

    Sovra.Repo.reload!(workspace)
  end

  @doc """
  A helper that transforms changeset errors into a map of messages.

      assert {:error, changeset} = Accounts.create_user(%{password: "short"})
      assert "password is too short" in errors_on(changeset).password
      assert %{password: ["password is too short"]} = errors_on(changeset)

  """
  def errors_on(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {message, opts} ->
      Regex.replace(~r"%{(\w+)}", message, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end
end
