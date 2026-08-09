from mailjet_rest import Client
from config import MAILJET_API_KEY, MAILJET_API_SECRET, MAILJET_SENDER_EMAIL, OTP_EXPIRY_MINUTES, logger


def _build_otp_html(otp: str) -> str:
    """Build a styled HTML email for the OTP."""
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#131313;font-family:'Courier New',Courier,monospace;">
  <table role="presentation" width="100%" style="background-color:#131313;padding:40px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="480" style="background-color:#1a1a1a;border:1px solid #2a2a2a;border-top:3px solid #7bee5e;max-width:480px;width:100%;">
          <!-- Header -->
          <tr>
            <td style="padding:28px 32px 0 32px;">
              <span style="background:#7bee5e;color:#131313;font-weight:bold;padding:4px 10px;font-size:14px;font-family:'Courier New',Courier,monospace;">sudoers</span>
            </td>
          </tr> 
          <!-- Title -->
          <tr>
            <td style="padding:24px 32px 8px 32px;">
              <h1 style="margin:0;font-size:22px;color:#eceae5;font-family:'Courier New',Courier,monospace;font-weight:bold;">
                Verify your <span style="color:#7bee5e;">email</span>
              </h1>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:8px 32px 16px 32px;">
              <p style="margin:0 0 20px 0;color:#eceae5d8;font-size:14px;line-height:1.6;font-family:'Courier New',Courier,monospace;">
                Use the following OTP to complete your event submission:
              </p>
            </td>
          </tr>
          <!-- OTP Box -->
          <tr>
            <td align="center" style="padding:0 32px 24px 32px;">
              <table role="presentation" style="background:#131313;border:2px solid #7bee5e;border-radius:0;">
                <tr>
                  <td style="padding:16px 40px;text-align:center;">
                    <span style="font-size:32px;font-weight:bold;color:#7bee5e;letter-spacing:8px;font-family:'Courier New',Courier,monospace;">{otp}</span>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <!-- Expiry note -->
          <tr>
            <td style="padding:0 32px 24px 32px;">
              <p style="margin:0;color:#77ca62;font-size:12px;font-family:'Courier New',Courier,monospace;">
                Valid for {OTP_EXPIRY_MINUTES} minutes
              </p>
            </td>
          </tr>
          <!-- Divider -->
          <tr>
            <td style="padding:0 32px;">
              <hr style="border:none;border-top:1px solid #2a2a2a;margin:0;">
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding:16px 32px 24px 32px;">
              <p style="margin:0;color:#4b4b4b;font-size:11px;line-height:1.5;font-family:'Courier New',Courier,monospace;">
                If you did not request this OTP, please ignore this email.<br>
                This is an automated message from sudoers.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def send_otp_email(recipient: str, otp: str) -> None:
    """Send OTP email via Mailjet API — called from a background task."""
    try:
        mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_API_SECRET), version="v3.1")

        data = {
            "Messages": [
                {
                    "From": {
                        "Email": MAILJET_SENDER_EMAIL,
                        "Name": "sudoers",
                    },
                    "To": [
                        {
                            "Email": recipient,
                        }
                    ],
                    "Subject": f"Your OTP for Event Submission is {otp}",
                    "TextPart": (
                        f"Your OTP for event submission is: {otp}\n\n"
                        f"This OTP is valid for {OTP_EXPIRY_MINUTES} minutes.\n"
                        "If you did not request this, please ignore this email."
                    ),
                    "HTMLPart": _build_otp_html(otp),
                }
            ]
        }

        result = mailjet.send.create(data=data)

        if result.status_code == 200:
            logger.info("OTP email sent successfully to %s via Mailjet", recipient)
        else:
            logger.error(
                "Mailjet API error for %s: status=%d, body=%s",
                recipient,
                result.status_code,
                result.json(),
            )
    except Exception as e:
        logger.error("Failed to send OTP email to %s: %s", recipient, e)
