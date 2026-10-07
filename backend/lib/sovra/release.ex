defmodule Sovra.Release do
  @app :sovra

  def migrate do
    load_app()

    for repo <- repos() do
      {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :up, all: true))
    end
  end

  def rollback(repo, version) do
    load_app()
    {:ok, _, _} = Ecto.Migrator.with_repo(repo, &Ecto.Migrator.run(&1, :down, to: version))
  end

  @doc """
  Registers every provisioned workspace as an issuer and initializes its status
  bitmaps. Workspace provisioning does both now; this runs them for workspaces
  that were provisioned before it did, when the first schema did them instead —
  or never did, if that schema's chain write failed.

  Needs the running application (the repo, the RPC client and the relayer
  signer), so run it on a live node with `rpc`, not `eval`:

      /opt/sovra/app/bin/sovra rpc 'Sovra.Release.backfill_issuer_setup()'

  Safe to re-run: what is already on-chain is skipped. Workspaces are handled
  one at a time, and each step waits for the one before it to land, because a
  bitmap can only be initialized for a registered issuer.
  """
  def backfill_issuer_setup do
    import Ecto.Query

    alias Sovra.Workspaces.Workspace
    alias Sovra.Workspaces.WorkspaceProvisioningJob

    workspaces =
      from(w in Workspace, where: w.provisioning_status == "done", order_by: w.inserted_at)
      |> Sovra.Repo.all()

    failed =
      Enum.flat_map(workspaces, fn ws ->
        with :ok <- WorkspaceProvisioningJob.register_issuer(ws),
             :ok <- WorkspaceProvisioningJob.initialize_bitmaps(ws) do
          []
        else
          {:error, reason} ->
            IO.puts("#{ws.id}: #{inspect(reason)}")
            [ws.id]
        end
      end)

    IO.puts("#{length(workspaces) - length(failed)} of #{length(workspaces)} workspaces set up")
    if failed == [], do: :ok, else: {:error, failed}
  end

  defp repos, do: Application.fetch_env!(@app, :ecto_repos)

  defp load_app do
    Application.ensure_all_started(:ssl)
    Application.ensure_loaded(@app)
    Application.ensure_all_started(:req)
  end
end
