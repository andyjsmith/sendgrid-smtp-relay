import os
import sys
import logging

import email.message
import email.policy
from email import message_from_bytes

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import Envelope, Session, SMTP

logger = logging.getLogger(__name__)


class MailHandler:
    def __init__(
        self,
        sg: SendGridAPIClient,
        domain_from_allowlist: list | None = None,
        domain_to_allowlist: list | None = None,
    ) -> None:
        self.sg = sg
        self.domain_from_allowlist = domain_from_allowlist
        self.domain_to_allowlist = domain_to_allowlist

    async def handle_MAIL(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        mail_options: list[str],
    ) -> str:
        """Handle from address"""

        # Check for valid from addresses
        if self.domain_from_allowlist is None:
            # No allowlist, so all domains are allowed
            envelope.mail_from = address
            envelope.mail_options.extend(mail_options)
            return "250 OK"

        # Check each domain in allowlist and see if destination address matches
        if (
            list(
                filter(lambda d: address.endswith("@" + d), self.domain_from_allowlist)
            )
            == []
        ):
            logger.warning(f"Rejected an email from {address}, not in allowlist")
            return f"550 not relaying to that domain: {address}"

        envelope.mail_from = address
        envelope.mail_options.extend(mail_options)
        return "250 OK"

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        """Handle each addressee"""

        # Check for valid destination addresses
        if self.domain_to_allowlist is None:
            # No allowlist, so all domains are allowed
            envelope.rcpt_tos.append(address)
            envelope.rcpt_options.extend(rcpt_options)
            return "250 OK"

        # Check each domain in allowlist and see if destination address matches
        if (
            list(filter(lambda d: address.endswith("@" + d), self.domain_to_allowlist))
            == []
        ):
            logger.warning(f"Rejected an email to {address}, not in allowlist")
            return f"550 not relaying to that domain: {address}"

        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(self, server: SMTP, session: Session, envelope: Envelope):
        """Handle each email"""

        parsed_message: email.message.MIMEPart = message_from_bytes(
            envelope.content, policy=email.policy.default
        )

        body_text = None
        body_html = None

        # Modified from https://stackoverflow.com/a/32840516/4922603
        if parsed_message.is_multipart():
            # Go through each part of the message to find body text and HTML
            for part in parsed_message.walk():
                ctype = part.get_content_type()
                cdispo = str(part.get("Content-Disposition"))

                # skip any text/plain (txt) attachments
                if "attachment" in cdispo:
                    continue

                if ctype == "text/plain":
                    body_text = part.get_payload(decode=True)
                elif ctype == "text/html":
                    body_html = part.get_payload(decode=True)
        # not multipart - i.e. plain text, no attachments, keeping fingers crossed
        else:
            if parsed_message.get_content_type().lower() == "text/html":
                body_html = parsed_message.get_payload(decode=True)
            else:
                body_text = parsed_message.get_payload(decode=True)

        if isinstance(body_html, bytes):
            body_html = body_html.decode("utf-8", errors="ignore")
        if isinstance(body_text, bytes):
            body_text = body_text.decode("utf-8", errors="ignore")

        # Create SendGrid message
        message = Mail(
            from_email=envelope.mail_from,
            to_emails=envelope.rcpt_tos,
            subject=parsed_message.get("Subject"),
            html_content=body_html,
            plain_text_content=body_text,
        )

        # Send the SendGrid message
        # try:
        #     response = self.sg.send(message)
        #     logger.debug("SendGrid response:")
        #     logger.debug(response.status_code)
        #     logger.debug(response.body)
        #     logger.debug(response.headers)
        # except Exception as e:
        #     logger.error(
        #         "Encountered an error when forwarding the message to SendGrid:"
        #     )
        #     logger.error(str(e))
        #     return "550 Encountered an error when forwarding the message to SendGrid"

        logger.info(
            f"Sent email from {envelope.mail_from} to {', '.join(envelope.rcpt_tos)}"
        )
        return "250 Message accepted for delivery"


def main() -> int:
    if os.environ.get("RUNNING_IN_DOCKER"):
        FORMAT = "[%(levelname)s] %(message)s"
    else:
        FORMAT = "%(asctime)s [%(levelname)s] %(message)s"

    logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d %H:%M:%S")

    # Get and set the log level
    LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
    try:
        logger.setLevel(LOGLEVEL)
    except ValueError:
        logger.critical(f"Unknown LOGLEVEL: {LOGLEVEL}")
        return 1

    # Get configuration environment variables
    sengrid_api_key = os.environ.get("SENDGRID_API_KEY")

    if not sengrid_api_key:
        logger.critical("You must set the SENDGRID_API_KEY environment variable")
        return 1

    port = os.environ.get("PORT", 25)
    hostname = os.environ.get("HOSTNAME", "127.0.0.1")

    domain_from_allowlist = os.environ.get("DOMAIN_FROM_ALLOWLIST")
    if domain_from_allowlist is not None:
        domain_from_allowlist = [d.strip() for d in domain_from_allowlist.split(",")]

    domain_to_allowlist = os.environ.get("DOMAIN_TO_ALLOWLIST")
    if domain_to_allowlist is not None:
        domain_to_allowlist = [d.strip() for d in domain_to_allowlist.split(",")]

    # Print config information
    logger.info("SendGrid SMTP Relay")
    logger.info(f"Listening on {hostname}:{port}")

    if domain_from_allowlist:
        logger.info("Allowed from domains:")
        for domain in domain_from_allowlist:
            logger.info(f"  - {domain}")
    else:
        logger.info("No to allowlist")

    if domain_to_allowlist:
        logger.info("Allowed to domains:")
        for domain in domain_to_allowlist:
            logger.info(f"  - {domain}")
    else:
        logger.info("No to allowlist")

    # Create the SendGrid client and SMTPd controller
    sg = SendGridAPIClient(sengrid_api_key)

    controller = Controller(
        MailHandler(
            sg,
            domain_from_allowlist=domain_from_allowlist,
            domain_to_allowlist=domain_to_allowlist,
        ),
        port=port,
        hostname=hostname,
    )

    # Run the SMTP server
    controller.start()
    logger.info("Controller started. Press ENTER to exit.")
    input()
    return 0


if __name__ == "__main__":
    sys.exit(main())
