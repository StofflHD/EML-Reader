//! Short explanations of common header fields (tooltips in the header view).

pub fn describe(name: &str) -> Option<&'static str> {
    let n = name.to_ascii_lowercase();
    Some(match n.as_str() {
        "from" => "Author of the message as shown to the reader. Can be forged freely – DMARC checks it against SPF/DKIM.",
        "sender" => "The mailbox that actually sent the message on behalf of the author (e.g. an assistant or a mailing service).",
        "reply-to" => "Where replies go. Fraudsters often set it to their own address.",
        "to" => "Main recipients.",
        "cc" => "Recipients of a copy.",
        "bcc" => "Hidden recipients (usually removed before delivery).",
        "subject" => "Subject line.",
        "date" => "Date and time the author's program says the message was written.",
        "message-id" => "Worldwide unique identifier, created by the sending program or server; its domain hints at the real sender system.",
        "in-reply-to" => "Message-ID of the message this one answers.",
        "references" => "Message-IDs of the conversation (thread).",
        "return-path" => "Envelope sender (MAIL FROM) recorded by the final server: bounces go there; SPF checks its domain.",
        "received" => "One hop of the delivery: each server adds a line on top (from where, by which server, when). Lower lines can be forged, the top lines come from your own provider.",
        "delivered-to" => "Mailbox the receiving server delivered the message to.",
        "x-original-to" => "Original recipient address before aliases/forwarding.",
        "envelope-to" => "Recipient address of the SMTP envelope.",
        "authentication-results" => "Results of the receiving server's checks: SPF (sending server allowed?), DKIM (signature valid?), DMARC (From domain aligned?).",
        "arc-authentication-results" => "Authentication results recorded by a forwarding server (ARC chain), preserved for the next server.",
        "arc-seal" => "ARC: seal of a forwarding server over the ARC fields; cv= tells whether the earlier chain was valid.",
        "arc-message-signature" => "ARC: DKIM-like signature of a forwarding server over the message.",
        "dkim-signature" => "Cryptographic signature of the sending domain (d=) over selected header fields and the body. Key in DNS at <selector>._domainkey.<domain>.",
        "domainkey-signature" => "Predecessor of DKIM (obsolete).",
        "received-spf" => "SPF result recorded by the receiving server: is the sending IP allowed for the envelope domain?",
        "mime-version" => "The message uses MIME (attachments, character sets).",
        "content-type" => "Format of the content (text/plain, text/html, multipart/… with parts).",
        "content-transfer-encoding" => "How the content is encoded for transport (base64, quoted-printable, 7bit, 8bit).",
        "content-disposition" => "Whether a part is shown inline or is an attachment, and its file name.",
        "content-id" => "Identifier of a part, referenced from HTML as cid:… (embedded images).",
        "user-agent" | "x-mailer" => "Program that created the message.",
        "x-priority" => "Priority set by the sender (1 = highest, 3 = normal, 5 = lowest).",
        "importance" | "priority" => "Priority set by the sender.",
        "x-msmail-priority" => "Outlook priority.",
        "organization" | "organisation" => "Organisation of the sender (free text).",
        "list-id" => "Identifier of the mailing list the message came from.",
        "list-unsubscribe" => "Address or web page to unsubscribe from a list/newsletter.",
        "list-unsubscribe-post" => "One-click unsubscribe (RFC 8058).",
        "list-post" | "list-help" | "list-subscribe" | "list-owner" | "list-archive" => "Mailing list information.",
        "precedence" => "bulk/list/junk: mass mail; auto-responders should not reply.",
        "auto-submitted" => "Generated automatically (auto-replied, auto-generated): no human sender.",
        "x-auto-response-suppress" => "Asks Exchange not to send automatic replies.",
        "feedback-id" => "Identifier for feedback loops of large senders (e.g. Gmail).",
        "x-spam-status" => "SpamAssassin result: Yes/No, score, threshold and the rules that fired.",
        "x-spam-score" | "x-spam-level" => "Spam score of the receiving server's filter (higher = more likely spam).",
        "x-spam-flag" => "YES when the spam filter classified the message as spam.",
        "x-spam-report" => "SpamAssassin details: points per rule.",
        "x-spamd-result" | "x-rspamd-result" => "Rspamd result: score / threshold and the symbols that fired with their points.",
        "x-rspamd-score" => "Rspamd score.",
        "x-rspamd-queue-id" | "x-rspamd-server" => "Rspamd internals.",
        "x-forefront-antispam-report" => "Microsoft 365 spam filter: country (CTRY), spam confidence level (SCL), verdict (SFV), category (CAT) …",
        "x-microsoft-antispam" => "Microsoft 365: bulk complaint level (BCL) and more.",
        "x-ms-exchange-organization-scl" => "Microsoft spam confidence level: −1 trusted, 0–1 not spam, 5–6 spam, 9 high confidence spam.",
        "x-ms-exchange-organization-authas" => "Exchange: anonymous (external) or internal sender.",
        "x-ms-exchange-crosstenant-originalarrivaltime" => "Time the message arrived at Microsoft 365.",
        "x-ms-has-attach" => "Outlook: the message has attachments.",
        "x-ms-tnef-correlator" => "Outlook rich text (TNEF) correlation.",
        "x-originating-ip" => "IP address of the computer that wrote the message (added by some webmailers).",
        "x-sender-ip" | "x-source-ip" => "IP address of the sending computer or server.",
        "x-google-dkim-signature" => "Google's internal DKIM signature.",
        "x-gm-message-state" | "x-google-smtp-source" => "Gmail internals.",
        "x-received" => "Internal hop of a provider (like Received).",
        "x-virus-scanned" => "The message was scanned for viruses (by the named scanner).",
        "x-originalarrivaltime" => "Exchange: time the message arrived.",
        "thread-topic" | "thread-index" => "Outlook conversation information.",
        "disposition-notification-to" | "return-receipt-to" => "The sender asks for a read receipt.",
        "x-campaign" | "x-campaignid" | "x-mc-user" | "x-mailgun-variables" | "x-sg-eid" | "x-ses-outgoing" => "Identifier of a newsletter or mass mailing service.",
        "x-report-abuse" | "x-abuse" => "Where to report abuse of this sender.",
        "tls-required" => "TLS-Required: No – the sender allows delivery without encryption (RFC 8689).",
        "autocrypt" => "Public OpenPGP key of the sender for encryption (Autocrypt).",
        "openpgp" => "Where to find the sender's OpenPGP key.",
        "keywords" => "Keywords of the message.",
        "comments" => "Comments of the author.",
        "resent-from" | "resent-to" | "resent-date" | "resent-message-id" | "resent-sender" => "The message was re-sent (forwarded as is) by someone.",
        "errors-to" => "Old field: where error reports should go.",
        "bounces-to" => "Where bounces should go.",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn known() {
        assert!(super::describe("DKIM-Signature")
            .unwrap()
            .contains("signature"));
        assert!(super::describe("X-Unknown").is_none());
    }
}
