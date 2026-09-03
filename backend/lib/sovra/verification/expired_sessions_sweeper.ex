defmodule Sovra.Verification.ExpiredSessionsSweeper do
  @moduledoc """
  Periodic job that marks `pending` verification sessions whose `expires_at`
  has passed as `expired`. The verifier already enforces expiry at submission
  time (a holder POSTing to a stale session gets a `session_expired`
  failure), so this job is purely cosmetic — it transitions abandoned
  sessions to a queryable terminal state for list/show views.

  Records are not deleted; rows remain available for audit alongside
  `completed` and `failed` sessions.
  """

  use Oban.Worker, queue: :verification, max_attempts: 3
  use Sovra.Log

  import Ecto.Query

  alias Sovra.Repo
  alias Sovra.Verification.Session

  @impl Oban.Worker
  def perform(%Oban.Job{} = job) do
    Log.adopt_job_context(job)
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {count, _} =
      from(s in Session,
        where: s.status == "pending" and s.expires_at < ^now
      )
      |> Repo.update_all(set: [status: "expired", completed_at: now, updated_at: now])

    # Abandoned QRs are the shape of the funnel: a jump here without a matching
    # jump in presentation.received means wallets are not completing the flow.
    if count > 0 do
      Log.event(:info, "verification sessions marked expired",
        event: "presentation.request.expired",
        count: count
      )
    end

    :ok
  end
end
