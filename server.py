import asyncio
import email.message
import email.policy
import logging
import os
import signal
import sys
from email import message_from_bytes
from email.utils import parseaddr

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# Set up logger
FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(format=FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)


def handle_sigterm(*args):
    """Handle Docker SIGTERM like a SIGINT"""
    raise KeyboardInterrupt()


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

        logger.debug("Receiving new email")
        logger.debug(f"Setting FROM address: {address}")

        # Check for valid from addresses
        if self.domain_from_allowlist is not None:
            # Check each domain in allowlist and see if destination address matches
            if (
                list(
                    filter(
                        lambda d: address.endswith("@" + d), self.domain_from_allowlist
                    )
                )
                == []
            ):
                logger.warning(f"[rejected] Email from {address}, not in allowlist")
                return f"550 not relaying from that domain: {address}"

        envelope.mail_from = address  # type: ignore
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
        if self.domain_to_allowlist is not None:
            # Check each domain in allowlist and see if destination address matches
            if (
                list(
                    filter(
                        lambda d: address.endswith("@" + d), self.domain_to_allowlist
                    )
                )
                == []
            ):
                logger.warning(f"[rejected] Email to {address}, not in allowlist")
                return f"541 not relaying to that domain: {address}"

        logger.debug(f"Adding a TO address: {address}")
        envelope.rcpt_tos.append(address)
        envelope.rcpt_options.extend(rcpt_options)
        return "250 OK"

    async def handle_DATA(
        self, server: SMTP, session: Session, envelope: Envelope
    ) -> str:
        """Handle each email"""

        # Get the message content as bytes
        content: bytes = b""
        if isinstance(envelope.content, str):
            content = envelope.content.encode()
        if isinstance(envelope.content, bytes):
            content = envelope.content

        # Get the SMTP from and to addresses
        from_address: str = envelope.mail_from  # type: ignore
        to_addresses: list[str] = envelope.rcpt_tos  # type: ignore

        logger.debug("Message content:\n" + content.decode())

        parsed_message: email.message.Message = message_from_bytes(
            content, policy=email.policy.default
        )

        # Get the sender and recipient(s) from the MIME headers, which contains the name
        # Note, this only supports a singular From and To header
        from_mailboxes_raw: list[str] = parsed_message.get("From", "").split(",")
        to_mailboxes_raw: list[str] = parsed_message.get("To", "").split(",")

        if len(from_mailboxes_raw) != 1 or from_mailboxes_raw[0] == "":
            logger.warning("[rejected] MIME FROM address missing or multiple specified")
            return "550 message must have a singular From address"
        if len(to_mailboxes_raw) < 1:
            logger.warning("[rejected] MIME TO address missing")
            return "550 message must have at least one To address"

        # Make sure the MIME header from and to addresses equal the SMTP from and to addresses
        from_mailbox: tuple[str, str] = parseaddr(from_mailboxes_raw[0])
        if from_mailbox[1].strip() != from_address.strip():
            logger.warning("[rejected] SMTP and MIME FROM addresses do not match")
            return "550 message SMTP From addr does not match MIME From addr"

        to_mailboxes: list[tuple[str, str]] = list(map(parseaddr, to_mailboxes_raw))
        for _, addr in to_mailboxes:
            if addr.strip() not in to_addresses:
                logger.warning("[rejected] SMTP and MIME TO addresses do not match")
                return "550 message MIME To addr not included in SMTP To addrs"

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
            # address format is reversed from normal (i.e. addr, name)
            from_email=tuple(reversed(from_mailbox)),
            to_emails=list(map(lambda x: tuple(reversed(x)), to_mailboxes)),
            subject=parsed_message.get("Subject"),
            html_content=body_html,
            plain_text_content=body_text,
        )

        # Send the SendGrid message
        try:
            response = self.sg.send(message)
            logger.debug("SendGrid response:")
            logger.debug(response.status_code)
            logger.debug(response.body)
            logger.debug(response.headers)
        except Exception as e:
            logger.error(
                "Encountered an error when forwarding the message to SendGrid:"
            )
            logger.error(str(e))
            return "550 Encountered an error when forwarding the message to SendGrid"

        logger.info(f"Sent email from {from_address} to {', '.join(to_addresses)}")
        return "250 Message accepted for delivery"


def main() -> int:
    # Handle Docker SIGTERM like a SIGINT
    signal.signal(signal.SIGTERM, handle_sigterm)

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

    port = int(os.environ.get("PORT", "25"))
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
        logger.info("No from allowlist")

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
    logger.info("Server started")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")

    return 0


if __name__ == "__main__":
    sys.exit(main())
