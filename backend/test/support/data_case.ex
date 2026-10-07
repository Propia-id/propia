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
  Drain the chain queue, so the credential type registration a new schema
  enqueued runs, and reload the schema. Use in tests that issue from a schema
  they just created: nothing is issued from one whose type is not registered.
  Relies on the test config wiring of `SovraTest.Ethereum.StubIssuerRegistry`.
  """
  def register_schema(%Sovra.Issuer.CredentialSchema{} = schema) do
    run_chain_jobs()
    Sovra.Repo.reload!(schema)
  end

  @doc """
  Drain the chain queue, so every on-chain write enqueued so far runs: schema
  registrations, document anchors, credential status changes. Use in tests that
  need the outcome. Relies on the test config wiring of the stub registries.
  """
  def run_chain_jobs do
    Oban.drain_queue(queue: :chain, with_safety: false)

    # Same as provision_workspace/1: the jobs ran in this process.
    Logger.metadata(oban_job_id: nil, oban_attempt: nil)
    :ok
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
