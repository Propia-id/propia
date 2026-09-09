defmodule Sovra.Signer.PromExTest do
  # async: false — PromEx is a singleton and its reporter owns named ETS tables.
  # No alias: `PromEx` must resolve to the library module, whose `get_metrics/1`
  # takes ours.
  use ExUnit.Case, async: false

  alias Sovra.BuildInfo
  alias Sovra.PromEx.BuildPlugin

  setup do
    original = Application.get_env(:sovra, Sovra.Signer.PromEx, [])

    Application.put_env(
      :sovra,
      Sovra.Signer.PromEx,
      Keyword.merge(original, disabled: false)
    )

    start_supervised!(Sovra.Signer.PromEx)

    on_exit(fn -> Application.put_env(:sovra, Sovra.Signer.PromEx, original) end)

    :ok
  end

  # The signer's only version surface in Prometheus, and the reason this module
  # exists separately from Sovra.PromEx.
  test "exports the build identity" do
    BuildPlugin.execute_build_metrics()

    text = PromEx.get_metrics(Sovra.Signer.PromEx)

    assert text =~
             ~s(sovra_build_info{ref="#{BuildInfo.ref()}",revision="#{BuildInfo.revision()}",version="#{BuildInfo.version()}"} 1)
  end

  # The API's plugins reach for the Repo, the Phoenix endpoint and the relayer,
  # none of which run in this tree.
  test "carries none of the API-only families" do
    text = PromEx.get_metrics(Sovra.Signer.PromEx)

    refute text =~ "sovra_prom_ex_ecto"
    refute text =~ "sovra_prom_ex_phoenix"
    refute text =~ "sovra_relayer"
    refute text =~ "sovra_health"
  end

  # Dropped deliberately: it would ship `git_sha_info{sha="Git SHA not
  # available"}` on the one host that now reports its revision properly.
  test "carries no Application-plugin dependency inventory" do
    text = PromEx.get_metrics(Sovra.Signer.PromEx)

    refute text =~ "sovra_prom_ex_application"
  end
end
