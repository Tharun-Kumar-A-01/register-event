import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import GMAIL_USER, GMAIL_APP_PASSWORD, OTP_EXPIRY_MINUTES, logger
import socket

def send_otp_email(recipient: str, otp: str) -> None:
    """Synchronous email sending — called from a background task."""
    try:
        msg = MIMEMultipart()
        msg["From"] = GMAIL_USER
        msg["To"] = recipient
        msg["Subject"] = "Your OTP for Event Submission"

        body = (
            f"Your OTP for event submission is: {otp}\n\n"
            f"This OTP is valid for {OTP_EXPIRY_MINUTES} minutes.\n"
            "If you did not request this, please ignore this email."
        )
        msg.attach(MIMEText(body, "plain"))

        smtp_host = socket.gethostbyname("smtp.gmail.com")
        
        with smtplib.SMTP(smtp_host, 587) as server:
            server.starttls()
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.sendmail(GMAIL_USER, recipient, msg.as_string())

        logger.info("OTP email sent successfully to %s", recipient)
    except Exception as e:
        logger.error("Failed to send OTP email to %s: %s", recipient, e)
