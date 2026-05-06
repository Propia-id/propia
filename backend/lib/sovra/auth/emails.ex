defmodule Sovra.Auth.Emails do
  @moduledoc """
  Transactional emails for the Auth subsystem.

  Templates use a 600px table-based layout, inline styles only, system-font
  fallbacks, and matching plain-text bodies — so they render acceptably in
  Outlook desktop, Gmail, Apple Mail, and webmail clients without custom CSS
  loading or external assets.
  """

  import Swoosh.Email

  @from {"Sovra", "no-reply@sovra.local"}

  # ── Public builders ─────────────────────────────────────────

  def password_reset(email_address, full_name, reset_link) do
    new()
    |> to({full_name || "", email_address})
    |> from(@from)
    |> subject("Reset your Sovra password")
    |> html_body(
      shell(
        "Reset your Sovra Issuer password. Link expires in 1 hour.",
        password_reset_body(full_name, email_address, reset_link)
      )
    )
    |> text_body(password_reset_text(full_name, email_address, reset_link))
  end

  def welcome(email_address, full_name, workspace_name) do
    new()
    |> to({full_name || "", email_address})
    |> from(@from)
    |> subject("Welcome to Sovra")
    |> html_body(
      shell(
        "Your Sovra Issuer workspace is ready.",
        welcome_body(full_name, workspace_name, console_url())
      )
    )
    |> text_body(welcome_text(full_name, workspace_name, console_url()))
  end

  def password_changed(email_address, full_name) do
    new()
    |> to({full_name || "", email_address})
    |> from(@from)
    |> subject("Your Sovra password was changed")
    |> html_body(
      shell(
        "Your Sovra Issuer password was updated.",
        password_changed_body(full_name, console_url())
      )
    )
    |> text_body(password_changed_text(full_name, console_url()))
  end

  # ── Bodies ──────────────────────────────────────────────────

  defp welcome_body(full_name, workspace_name, console_url) do
    name = escape(full_name) || "there"
    ws = escape(workspace_name) || "your workspace"

    """
    #{eyebrow("blue", "Welcome · Workspace ready")}

    #{headline("Welcome to Sovra,", ws)}

    #{body_paragraph("Hi #{name}, your Issuer workspace is provisioned. Sign in to manage credentials, schemas, and team members — or jump straight into your first issue.")}

    #{cta_row(button(console_url, "Open issuer console"))}

    #{divider()}

    #{section_label("What's next")}
    #{step(1, "Workspace created", "Your workspace and DID are ready.", :done)}
    #{step(2, "Define a credential schema", "Map the claims you'll issue.", :active)}
    #{step(3, "Issue your first credential", "From the console or via API.", :pending)}

    #{divider()}

    #{body_small("We'll occasionally send transactional notifications from this address. If you didn't sign up, please ignore this email and contact support@sovra.io.")}
    """
  end

  defp password_reset_body(full_name, email_address, reset_link) do
    name = escape(full_name) || "there"
    addr = escape(email_address)

    """
    #{eyebrow("blue", "Password reset · Requested")}

    #{headline("Reset your password", nil)}

    #{body_paragraph("Hi #{name}, someone — hopefully you — asked to reset the password for the Sovra Issuer account associated with <strong style=\"color:#ffffff\">#{addr}</strong>. Click below to choose a new one.")}

    #{cta_row(button(reset_link, "Choose a new password"))}

    <div style="font-size:13px;color:#888888;margin-top:12px;font-family:Arial,Helvetica,sans-serif;">
      Link expires in 1 hour.
    </div>

    #{fallback_link(reset_link)}

    #{divider()}

    #{callout("purple",
    "Didn't request this?",
    "You can safely ignore this email — your current password stays active. If requests keep arriving, contact <span style=\"color:#ffffff\">security@sovra.io</span>.")}
    """
  end

  defp password_changed_body(full_name, console_url) do
    name = escape(full_name) || "there"

    """
    #{eyebrow("green", "Password updated · Confirmation")}

    #{success_hero("Password updated.", "Your Sovra Issuer credentials are current. Sign in anywhere with the new password.")}

    #{body_paragraph("Hi #{name}, we're sending this so you have a record of the change. No action needed if it was you.")}

    #{cta_row(button(console_url, "Open issuer console"))}

    #{divider()}

    #{callout("danger",
    "Wasn't you?",
    "Reset your password again from the sign-in page and contact <a href=\"mailto:security@sovra.io\" style=\"color:#ef4444;text-decoration:none;font-weight:600\">security@sovra.io</a>. All previous sessions on your account have already been revoked.")}
    """
  end

  # ── Text fallbacks ──────────────────────────────────────────

  defp welcome_text(full_name, workspace_name, console_url) do
    name = full_name || "there"
    ws = workspace_name || "your workspace"

    """
    Hi #{name},

    Welcome to Sovra. Your Issuer workspace "#{ws}" is provisioned and ready.

    Sign in to the issuer console:
    #{console_url}

    What's next:
      1. Workspace created — your workspace and DID are ready.
      2. Define a credential schema — map the claims you'll issue.
      3. Issue your first credential — from the console or via API.

    If you didn't sign up, please ignore this email and contact support@sovra.io.

    — Sovra
    """
  end

  defp password_reset_text(full_name, email_address, reset_link) do
    name = full_name || "there"

    """
    Hi #{name},

    Someone — hopefully you — asked to reset the password for the Sovra
    Issuer account associated with #{email_address}.

    Open the link below within the next hour to choose a new password:

    #{reset_link}

    Didn't request this? You can safely ignore this message; your current
    password stays active.

    — Sovra
    """
  end

  defp password_changed_text(full_name, console_url) do
    name = full_name || "there"

    """
    Hi #{name},

    Your Sovra Issuer password was just updated. We're sending this so you
    have a record of the change.

    Sign in:
    #{console_url}

    Wasn't you? Reset your password again from the sign-in page and contact
    security@sovra.io. All previous sessions on your account have already
    been revoked.

    — Sovra
    """
  end

  # ── Layout primitives ───────────────────────────────────────

  defp shell(preheader, content) do
    """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width,initial-scale=1" />
      <meta name="x-apple-disable-message-reformatting" />
      <meta name="color-scheme" content="dark light" />
      <meta name="supported-color-schemes" content="dark light" />
      <title>Sovra</title>
    </head>
    <body style="margin:0;padding:0;background:#0a0915;color:#ffffff;-webkit-font-smoothing:antialiased;font-family:Figtree,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
      <!-- Preheader (hidden, shown in inbox preview) -->
      <div style="display:none;max-height:0;overflow:hidden;mso-hide:all;font-size:1px;line-height:1px;color:#0a0915;">
        #{escape(preheader)}
      </div>

      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#0a0915;width:100%;">
        <tr>
          <td align="center" style="padding:32px 16px;">
            <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:100%;max-width:600px;background:#0a0915;border:1px solid rgba(255,255,255,0.08);border-radius:16px;overflow:hidden;">
              <!-- Header -->
              <tr>
                <td style="padding:32px 32px 24px;background:#0a0915;border-bottom:1px solid rgba(255,255,255,0.08);">
                  #{wordmark()}
                </td>
              </tr>
              <!-- Accent hairline -->
              <tr>
                <td style="height:2px;line-height:2px;font-size:0;background:linear-gradient(90deg,transparent 0%,#0099ff 30%,#8b5cf6 70%,transparent 100%);">&nbsp;</td>
              </tr>
              <!-- Body -->
              <tr>
                <td style="padding:40px 40px 32px;background:#0a0915;color:#ffffff;font-family:Figtree,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
                  #{content}
                </td>
              </tr>
              <!-- Footer -->
              <tr>
                <td style="padding:24px 40px 32px;background:#0f0d1a;border-top:1px solid rgba(255,255,255,0.08);font-family:Figtree,-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;font-size:12px;color:#888888;line-height:1.65;">
                  <div style="margin-bottom:14px;">
                    <a href="#{console_url()}" style="color:#c2bccf;text-decoration:none;font-weight:500;margin-right:14px;">Issuer console</a>
                    <a href="https://docs.sovra.io" style="color:#c2bccf;text-decoration:none;font-weight:500;margin-right:14px;">Documentation</a>
                    <a href="https://status.sovra.io" style="color:#c2bccf;text-decoration:none;font-weight:500;margin-right:14px;">Status</a>
                    <a href="mailto:support@sovra.io" style="color:#c2bccf;text-decoration:none;font-weight:500;">Support</a>
                  </div>
                  <div style="color:#555062;font-size:11px;line-height:1.6;">
                    You're receiving this because of activity on your Sovra Issuer account. Sovra is operated by Pulsar Labs LLC. We don't store credential data — only the proofs that make it verifiable.
                  </div>
                  <div style="margin-top:10px;color:#555062;font-size:11px;">
                    Pulsar Labs LLC · sovra.io
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
    </html>
    """
  end

  defp wordmark do
    """
    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td valign="middle" style="padding-right:12px;">
          <div style="display:inline-block;width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#0099ff 0%,#2060df 100%);text-align:center;line-height:28px;color:#ffffff;font-weight:800;font-family:Figtree,Arial,sans-serif;font-size:16px;">S</div>
        </td>
        <td valign="middle" style="font-family:Figtree,-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-weight:700;font-size:20px;letter-spacing:-0.01em;color:#ffffff;padding-right:12px;">
          Sovra
        </td>
        <td valign="middle" style="border-left:1px solid rgba(255,255,255,0.14);padding-left:12px;font-family:Figtree,-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif;font-size:11px;font-weight:600;letter-spacing:0.14em;text-transform:uppercase;color:#888888;">
          Issuer
        </td>
      </tr>
    </table>
    """
  end

  defp eyebrow(tone, text) do
    color =
      case tone do
        "green" -> "#10b981"
        "orange" -> "#f97316"
        "purple" -> "#8b5cf6"
        "danger" -> "#ef4444"
        _ -> "#0099ff"
      end

    """
    <div style="font-size:11px;font-weight:700;letter-spacing:0.18em;text-transform:uppercase;color:#{color};margin-bottom:16px;font-family:Figtree,Arial,sans-serif;">
      <span style="display:inline-block;width:6px;height:6px;border-radius:999px;background:#{color};margin-right:8px;vertical-align:middle;"></span>
      #{escape(text)}
    </div>
    """
  end

  defp headline(main, accent) when is_binary(accent) do
    """
    <h1 style="font-family:'Plus Jakarta Sans',Figtree,-apple-system,Helvetica,Arial,sans-serif;font-weight:800;font-size:32px;line-height:1.15;letter-spacing:-0.025em;margin:0 0 18px;color:#ffffff;">
      #{escape(main)}<br/>
      <span style="background:linear-gradient(135deg,#0099ff 0%,#2060df 60%,#8b5cf6 100%);-webkit-background-clip:text;background-clip:text;color:#0099ff;-webkit-text-fill-color:transparent;">#{escape(accent)}</span>
    </h1>
    """
  end

  defp headline(main, nil) do
    """
    <h1 style="font-family:'Plus Jakarta Sans',Figtree,-apple-system,Helvetica,Arial,sans-serif;font-weight:800;font-size:32px;line-height:1.15;letter-spacing:-0.025em;margin:0 0 18px;color:#ffffff;">
      #{escape(main)}
    </h1>
    """
  end

  defp body_paragraph(html) do
    """
    <p style="font-family:Figtree,-apple-system,Helvetica,Arial,sans-serif;font-size:16px;line-height:1.65;color:#c2bccf;margin:0 0 20px;">
      #{html}
    </p>
    """
  end

  defp body_small(text) do
    """
    <p style="font-family:Figtree,-apple-system,Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#888888;margin:0 0 8px;">
      #{escape(text)}
    </p>
    """
  end

  defp button(href, label) do
    """
    <table role="presentation" cellpadding="0" cellspacing="0" border="0">
      <tr>
        <td bgcolor="#0099ff" style="background:#0099ff;background:linear-gradient(135deg,#0099ff 0%,#2060df 100%);border-radius:999px;mso-padding-alt:0;">
          <a href="#{escape(href)}" style="display:inline-block;padding:14px 28px;font-family:Figtree,-apple-system,Helvetica,Arial,sans-serif;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;border-radius:999px;letter-spacing:-0.005em;">
            #{escape(label)}
          </a>
        </td>
      </tr>
    </table>
    """
  end

  defp cta_row(button_html) do
    """
    <div style="margin:24px 0 8px;">
      #{button_html}
    </div>
    """
  end

  defp fallback_link(url) do
    """
    <div style="margin-top:24px;padding:14px 16px;border-radius:12px;background:#0f0d1a;border:1px solid rgba(255,255,255,0.08);">
      <div style="font-size:11px;color:#888888;margin-bottom:6px;font-weight:600;letter-spacing:0.06em;text-transform:uppercase;font-family:Figtree,Arial,sans-serif;">
        Button not working? Paste this in your browser
      </div>
      <div style="font-family:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#c2bccf;word-break:break-all;line-height:1.5;">
        #{escape(url)}
      </div>
    </div>
    """
  end

  defp section_label(text) do
    """
    <div style="font-family:Figtree,Arial,sans-serif;font-size:11px;color:#888888;letter-spacing:0.14em;text-transform:uppercase;font-weight:700;margin-bottom:14px;">
      #{escape(text)}
    </div>
    """
  end

  defp step(n, title, subtitle, state) do
    {bg, border, fg, mark} =
      case state do
        :done -> {"#10b981", "#10b981", "#0a0915", "&#10003;"}
        :active -> {"rgba(0,153,255,0.12)", "#0099ff", "#0099ff", to_string(n)}
        _ -> {"transparent", "rgba(255,255,255,0.18)", "#888888", to_string(n)}
      end

    title_color = if state == :done, do: "#c2bccf", else: "#ffffff"

    """
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:0 0 12px;">
      <tr>
        <td valign="top" width="36" style="padding-right:14px;">
          <div style="width:28px;height:28px;border-radius:999px;border:1.5px solid #{border};background:#{bg};color:#{fg};text-align:center;line-height:25px;font-family:Figtree,Arial,sans-serif;font-weight:700;font-size:13px;">
            #{mark}
          </div>
        </td>
        <td valign="top">
          <div style="font-family:Figtree,Arial,sans-serif;font-size:15px;font-weight:600;color:#{title_color};line-height:1.4;">
            #{escape(title)}
          </div>
          <div style="font-family:Figtree,Arial,sans-serif;font-size:13px;color:#888888;margin-top:2px;">
            #{escape(subtitle)}
          </div>
        </td>
      </tr>
    </table>
    """
  end

  defp success_hero(title, subtitle) do
    """
    <table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin:0 0 24px;background:#0f1f1c;border:1px solid rgba(16,185,129,0.22);border-radius:16px;">
      <tr>
        <td style="padding:28px 28px 24px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="width:48px;height:48px;background:#10b981;border-radius:14px;text-align:center;vertical-align:middle;font-family:Figtree,Arial,sans-serif;font-size:24px;font-weight:800;color:#0a0915;line-height:48px;">
                &#10003;
              </td>
            </tr>
          </table>
          <h2 style="font-family:'Plus Jakarta Sans',Figtree,Arial,sans-serif;font-weight:800;font-size:26px;line-height:1.15;letter-spacing:-0.025em;margin:18px 0 6px;color:#ffffff;">
            #{escape(title)}
          </h2>
          <div style="font-family:Figtree,Arial,sans-serif;font-size:15px;color:#c2bccf;line-height:1.55;">
            #{escape(subtitle)}
          </div>
        </td>
      </tr>
    </table>
    """
  end

  defp callout(tone, title, html) do
    {bg, border} =
      case tone do
        "purple" -> {"rgba(139,92,246,0.06)", "rgba(139,92,246,0.25)"}
        "danger" -> {"rgba(239,68,68,0.06)", "rgba(239,68,68,0.25)"}
        _ -> {"#0f0d1a", "rgba(255,255,255,0.08)"}
      end

    """
    <div style="padding:18px 18px;border-radius:12px;background:#{bg};border:1px solid #{border};">
      <div style="font-family:Figtree,Arial,sans-serif;font-size:14px;font-weight:600;color:#ffffff;margin-bottom:6px;">
        #{escape(title)}
      </div>
      <div style="font-family:Figtree,Arial,sans-serif;font-size:13px;color:#c2bccf;line-height:1.6;">
        #{html}
      </div>
    </div>
    """
  end

  defp divider do
    """
    <div style="height:1px;line-height:1px;font-size:0;background:rgba(255,255,255,0.08);margin:28px 0;">&nbsp;</div>
    """
  end

  # ── helpers ─────────────────────────────────────────────────

  defp console_url do
    Application.get_env(:sovra, :issuer_frontend_url, "http://localhost:5173")
  end

  defp escape(nil), do: nil

  defp escape(s) do
    s
    |> to_string()
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end
end
