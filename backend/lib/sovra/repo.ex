defmodule Sovra.Repo do
  use Ecto.Repo,
    otp_app: :sovra,
    adapter: Ecto.Adapters.Postgres
end
