import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
import jwt
from rest_framework.exceptions import ValidationError
from dotenv import load_dotenv
import os

load_dotenv()


class SmtpMail:
    def send_reset_email(self, email: str, token: str):
        reset_link = f"http://localhost:3000/reset-password/{token}"
        subject = "Password Reset Request"
        body = f"""
        Hello,
        You requested a password reset. Click the link below to reset your password:
        {reset_link}
        If you did not request this, please ignore this email.
        Regards,
        Your App Team
        """
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = email
        msg["To"] = "krishika@gmail.com"
        try:
            with smtplib.SMTP(
                os.getenv("EMAIL_HOST"), os.getenv("EMAIL_PORT")
            ) as server:
                server.login(
                    os.getenv("EMAIL_HOST_USER"), os.getenv("EMAIL_HOST_PASSWORD")
                )
                server.sendmail(os.getenv("DEFAULT_FROM_EMAIL"), email, msg.as_string())
        except Exception as e:
            raise ValidationError("Failed to send email")

    def create_reset_token(self, email):
        expiration = datetime.now(timezone.utc) + timedelta(
            seconds=int(os.getenv("ACCESS_TOKEN_EXPIRE_TIME"))
        )
        to_encode = {"email": email, "exp": expiration.timestamp()}
        token = jwt.encode(
            to_encode, os.getenv("SECRET_KEY"), algorithm=os.getenv("ALGORITHM")
        )
        return token

    def verify_reset_token(self, token):
        try:
            payload = jwt.decode(
                token, key=os.getenv("SECRET_KEY"), algorithms=[os.getenv("ALGORITHM")]
            )
            email = payload["email"]
            if email is None:
                return None
            return email
        except jwt.ExpiredSignatureError:
            print("token expired")
            return None
        except jwt.PyJWTError:
            print("invalid token")
            return None
