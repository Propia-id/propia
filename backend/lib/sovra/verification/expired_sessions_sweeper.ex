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

  import Ecto.Query

  alias Sovra.Repo
  alias Sovra.Verification.Session

  require Logger

  @impl Oban.Worker
  def perform(%Oban.Job{}) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    {count, _} =
      from(s in Session,
        where: s.status == "pending" and s.expires_at < ^now
      )
      |> Repo.update_all(set: [status: "expired", completed_at: now, updated_at: now])

    if count > 0, do: Logger.info("Marked #{count} verification sessions as expired")
    :ok
  end
end
