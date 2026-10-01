"""Modern HTML wrappers for transactional ISPCENTRIC emails."""

from __future__ import annotations

import html
import re
from typing import Any

# Brand palette aligned with static/css/main.css
_THEMES: dict[str, dict[str, str]] = {
    "info": {
        "label": "Update",
        "accent": "#0c7a84",
        "accent_deep": "#07545c",
        "soft": "#e6f2f4",
        "badge_bg": "#d5eef1",
        "badge_fg": "#07545c",
        "icon": "●",
    },
    "success": {
        "label": "Success",
        "accent": "#145c3c",
        "accent_deep": "#0e4029",
        "soft": "#e8f6ef",
        "badge_bg": "#d5f0e2",
        "badge_fg": "#145c3c",
        "icon": "✓",
    },
    "warning": {
        "label": "Attention",
        "accent": "#e09a12",
        "accent_deep": "#9a6800",
        "soft": "#fff6e5",
        "badge_bg": "#ffe9bd",
        "badge_fg": "#6b4800",
        "icon": "!",
    },
    "danger": {
        "label": "Alert",
        "accent": "#c0392b",
        "accent_deep": "#8a1f1f",
        "soft": "#fdecea",
        "badge_bg": "#f8d7d3",
        "badge_fg": "#8a1f1f",
        "icon": "!",
    },
}

# Event key → visual tone for the email chrome.
EVENT_EMAIL_THEMES: dict[str, str] = {
    # Client — positive
    "client_welcome": "success",
    "hotspot_voucher": "success",
    "payment_received": "success",
    "subscription_extended": "success",
    "internet_reconnected": "success",
    "invoice_receipt": "info",
    # Client — caution / stop
    "stk_prompt": "info",
    "lead_installation": "info",
    "payment_failed": "danger",
    "renewal_reminder": "warning",
    "package_expired": "danger",
    "package_pause_resume": "warning",
    "account_status": "warning",
    "wifi_changed": "info",
    "fup_limit_reached": "warning",
    # ISP account
    "isp_password_reset": "info",
    "isp_employee_joined": "info",
    "isp_lead_open": "info",
    "isp_lead_allocated": "success",
    "isp_technician_assigned": "info",
    "isp_installation_result": "info",
    "isp_mikrotik_onboarding": "info",
    "isp_mikrotik_onboarded": "success",
    "isp_mikrotik_health_low": "warning",
    "isp_mikrotik_off": "danger",
    "isp_mikrotik_link_no_internet": "danger",
    "isp_mikrotik_accessed": "info",
    "isp_mikrotik_config_changed": "info",
    "isp_pppoe_connected_not_surfing": "danger",
    "isp_mikrotik_usage_high": "warning",
    "isp_stk_collection": "success",
    "isp_stk_failed": "danger",
    "isp_referral_active": "success",
    "isp_client_registered": "success",
    "isp_fup_limit_reached": "warning",
    # Platform → ISP / staff
    "platform_isp_welcome": "success",
    "platform_isp_verified": "success",
    "platform_isp_suspended": "danger",
    "platform_payment_received": "success",
    "platform_mikrotik_onboarded": "success",
}


_URL_RE = re.compile(r"(https?://[^\s<>\"']+|/(?:[A-Za-z0-9_\-./?=&%+#]+))")


def theme_for_event(event_key: str = "", theme: str = "") -> dict[str, str]:
    """Return palette + badge copy for an event or explicit theme name."""
    key = (theme or "").strip().lower()
    if key not in _THEMES:
        mapped = EVENT_EMAIL_THEMES.get(str(event_key or "").strip(), "info")
        key = mapped if mapped in _THEMES else "info"
    return dict(_THEMES[key])


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _linkify_escaped_line(escaped_line: str) -> str:
    """Turn URLs inside an already-escaped line into anchor tags."""

    def _repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        # Unescape was not needed — URLs in escaped text keep / : ? = & intact.
        href = raw
        if href.startswith("/") and not href.startswith("//"):
            # Relative paths are left as text; absolute http(s) only become links.
            return raw
        return (
            f'<a href="{href}" style="color:#0c7a84;text-decoration:underline;'
            f'word-break:break-all;">{raw}</a>'
        )

    return _URL_RE.sub(_repl, escaped_line)


def plain_body_to_html_blocks(body: str) -> str:
    """Convert plain-text notification body into styled HTML paragraphs."""
    text = (body or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not text:
        return (
            '<p style="margin:0;font-size:15px;line-height:1.65;color:#3d5a66;">'
            "No message content.</p>"
        )

    blocks: list[str] = []
    for paragraph in re.split(r"\n{2,}", text):
        lines = [ln.strip() for ln in paragraph.split("\n")]
        lines = [ln for ln in lines if ln]
        if not lines:
            continue
        # Bullet-ish lines → simple list
        if all(ln[:1] in {"-", "•", "*"} or ln[:2] in {"- ", "• ", "* "} for ln in lines):
            items = []
            for ln in lines:
                item = ln.lstrip("-•* ").strip()
                items.append(
                    "<li style=\"margin:0 0 8px;padding:0;color:#071820;"
                    f'font-size:15px;line-height:1.55;">{_linkify_escaped_line(_escape(item))}</li>'
                )
            blocks.append(
                '<ul style="margin:0 0 16px;padding:0 0 0 20px;">'
                + "".join(items)
                + "</ul>"
            )
            continue

        joined = "<br />".join(
            _linkify_escaped_line(_escape(ln)) for ln in lines
        )
        blocks.append(
            '<p style="margin:0 0 16px;font-size:15px;line-height:1.65;'
            f'color:#071820;">{joined}</p>'
        )

    if not blocks:
        return (
            '<p style="margin:0;font-size:15px;line-height:1.65;color:#3d5a66;">'
            f"{_escape(text)}</p>"
        )
    # Drop trailing margin on the last block.
    last = blocks[-1]
    blocks[-1] = last.replace("margin:0 0 16px;", "margin:0;", 1)
    return "".join(blocks)


def build_transactional_email_html(
    *,
    body: str,
    subject: str = "",
    title: str = "",
    company_name: str = "",
    event_key: str = "",
    theme: str = "",
    recipient_name: str = "",
) -> str:
    """
    Build a modern, brand-colored HTML email around a plain-text message.

    Uses table layout and inline styles for broad email-client support.
    """
    palette = theme_for_event(event_key, theme)
    brand = (company_name or "").strip() or "ISPCENTRIC"
    heading = (title or "").strip() or (subject or "").strip() or "Notification"
    preheader = " ".join((body or "").split())[:140]
    body_html = plain_body_to_html_blocks(body)
    greeting = ""
    if (recipient_name or "").strip():
        greeting = (
            f'<p style="margin:0 0 12px;font-size:15px;line-height:1.5;'
            f'color:#3d5a66;">Hi {_escape(recipient_name.strip())},</p>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta http-equiv="x-ua-compatible" content="ie=edge" />
<title>{_escape(heading)}</title>
<!--[if mso]><style type="text/css">table,td{{font-family:Arial,Helvetica,sans-serif !important;}}</style><![endif]-->
</head>
<body style="margin:0;padding:0;background:#d9ecef;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
<span style="display:none !important;visibility:hidden;opacity:0;color:transparent;height:0;width:0;overflow:hidden;">
{_escape(preheader)}
</span>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;background:#d9ecef;">
  <tr>
    <td align="center" style="padding:28px 16px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;max-width:600px;width:100%;">
        <tr>
          <td style="padding:0 0 14px;font-family:Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;font-size:13px;letter-spacing:0.04em;text-transform:uppercase;color:#3d5a66;">
            {_escape(brand)}
          </td>
        </tr>
        <tr>
          <td style="border-radius:16px;overflow:hidden;background:#ffffff;box-shadow:0 10px 30px rgba(7,24,32,0.08);">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
              <tr>
                <td bgcolor="{palette['accent']}" style="height:6px;line-height:6px;font-size:0;background-color:{palette['accent']};">&nbsp;</td>
              </tr>
              <tr>
                <td bgcolor="{palette['soft']}" style="padding:28px 28px 8px;background-color:{palette['soft']};font-family:Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;">
                  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
                    <tr>
                      <td bgcolor="{palette['badge_bg']}" style="padding:6px 12px;border-radius:999px;background-color:{palette['badge_bg']};color:{palette['badge_fg']};font-size:12px;font-weight:700;letter-spacing:0.06em;text-transform:uppercase;">
                        {palette['icon']}&nbsp; {_escape(palette['label'])}
                      </td>
                    </tr>
                  </table>
                  <h1 style="margin:16px 0 0;font-size:24px;line-height:1.25;font-weight:700;color:#071820;">
                    {_escape(heading)}
                  </h1>
                </td>
              </tr>
              <tr>
                <td bgcolor="#ffffff" style="padding:8px 28px 28px;background-color:#ffffff;font-family:Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;">
                  {greeting}
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
                    <tr>
                      <td bgcolor="#f7fbfc" style="padding:18px 18px 4px;border-radius:12px;border:1px solid #cfe4e9;background-color:#f7fbfc;">
                        {body_html}
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td style="padding:0 28px 28px;font-family:Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;">
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
                    <tr>
                      <td style="height:1px;line-height:1px;font-size:0;background:#cfe4e9;">&nbsp;</td>
                    </tr>
                    <tr>
                      <td style="padding-top:16px;font-size:12px;line-height:1.5;color:#3d5a66;">
                        Sent by <strong style="color:#07545c;">{_escape(brand)}</strong> via ISPCENTRIC.
                        If you were not expecting this message, you can ignore it.
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 4px 0;font-family:Segoe UI,Roboto,Helvetica Neue,Arial,sans-serif;font-size:11px;line-height:1.5;color:#5a7480;text-align:center;">
            This is an automated notification. Please do not reply to this email.
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>"""
