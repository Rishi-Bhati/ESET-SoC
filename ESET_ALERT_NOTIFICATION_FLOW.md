# From ESET alert to notification email

*ESET PROTECT · SOC notification service*

This document explains what happens to an alert from the moment ESET PROTECT raises it until the notification email is sent. It describes only what is built in the system today. Each step is tagged with its current status, so you can see what has been tested and what still needs your confirmation.

**Status key**

| Tag | Meaning |
|---|---|
| ✅ **Built and tested** | Works end to end with sample alerts |
| ⏳ **Needs your input** | Built, waiting on a decision or test from you |
| ⏸️ **Not switched on** | Built, but not active yet |

---

## The sequence

### 1. ESET raises an alert and forwards it — ✅ Built and tested

When ESET PROTECT detects a threat, it sends the alert to our platform automatically. It can do this by webhook (the main method) or by syslog export.

> The connection has been tested: test webhooks sent from ESET PROTECT reached our platform, passed the access-token check and were processed through to the end.

### 2. The alert is received and recorded — ✅ Built and tested

- Webhook alerts must carry a secret access token. Requests without the correct token are rejected.
- Each accepted alert gets a tracking ID, for example `3e136fc7-a0b4-4dc1-…`, and is saved before any analysis starts.
- If the same alert (same alert ID and time) arrives again within one hour, the repeat is discarded so you don't receive duplicate notifications.

### 3. The key facts are extracted — ⏳ Needs your input

The platform pulls out what was detected, on which device, ESET's severity rating, the action ESET took, and whether the threat was handled or the device isolated. Anything the alert doesn't contain is marked "unknown" rather than guessed.

> ESET's test webhooks report an audit-log event in a different format from the one the platform currently reads, so their details came through as "unknown" and the risk level defaulted to MEDIUM (step 4). We are updating the platform to read ESET's actual format. One real detection alert from your tenant is needed to confirm the fields ESET sends for an actual threat.

### 4. Fixed rules set the risk level — ⏳ Needs your input

Risk levels: `LOW` · `MEDIUM` · `HIGH` · `CRITICAL`

The risk level comes from a fixed set of rules, never from the AI. The rules look at:

- ESET's severity rating, and whether the threat was handled or the device isolated
- whether the device is a server or domain controller
- signs of ransomware, or an ESET outbreak alert, which make it CRITICAL
- the same detection on 3 or more devices within one hour, which makes it CRITICAL

Once ESET's rating and handling status set the starting level, the other rules can only raise it. Every decision is recorded with the reason for it.

> This rule table is our proposal and needs your approval before go-live.

### 5. AI drafts the notification wording — ⏳ Needs your input

An AI service (OpenAI) writes the text of the notifications: a summary, the reason for the risk level, suggested first actions, and the email itself. It is given the risk level and asked to explain it. It cannot change it.

Before anything is sent to the AI service, usernames, email mailboxes and ESET's internal IDs are masked. Device names, IP addresses, URLs, domains and file hashes are sent as they are, because the analysis needs them.

> This step has been tested end to end with the live AI service on ESET's test webhooks. Where details were missing, the AI listed them as needing confirmation instead of guessing. The masking policy above is our proposal and needs your approval.

### 6. The draft is checked automatically — ✅ Built and tested

The AI's draft is blocked if it:

- states a different risk level from the one the rules set
- leaves a required section empty
- uses wording we prohibit, such as "infection confirmed" or "the environment is safe" (in English or Japanese)

If the draft is blocked, or the AI service fails, the alert is still recorded. You are not sent an AI-written email, and our team receives a standard notice with the alert facts so they can follow up by hand.

> These are automatic checks. No person reviews the draft before it is sent.

### 7. The emails are prepared — ✅ Built and tested

Up to four emails are prepared at the same time. The subject line of your notification always shows the risk level, for example `【HIGH】`.

| Email | For | Language | Contents |
|---|---|---|---|
| Client notification | You | Japanese | What was detected, current status, what we ask you to confirm |
| Review copy | C-Three Index | Japanese | Your notification plus the risk reasoning and open questions |
| Internal summary | Our team | Japanese | Summary, suggested first actions, tracking-ticket draft |
| Technical summary | Our engineers | English | Technical detail and the rules that set the risk level |

> Your notification and C-Three's copy are sent together. C-Three's copy is for information and follow-up; it is not an approval step before your email goes out.

### 8. The emails are sent — ✅ Built and tested

The emails are handed to our mail service, which confirms it has received each one. If that handoff fails, it is retried automatically (by default up to 3 attempts over about two minutes). Emails that still can't be handed off are kept in a failed-email list for our team to resend by hand.

> The handoff has been confirmed in our test environment with sample alerts. After the handoff, delivery to the inbox is handled by the mail service.

---

## Built but not yet switched on

### Threat-intelligence lookups — ⏸️ Not switched on

Between steps 3 and 4, the platform can check one item from the alert against public threat databases: a file hash, URL or IP address against VirusTotal, and an IP address against AbuseIPDB. A "malicious" or "suspicious" result would raise the risk level.

This is currently running in simulation only. It has no effect on the risk level or on the emails. Domain names are not checked. We will switch it on and test it before go-live.

---

## What we need from you

1. **Trigger one real detection** on a test device, for example by downloading the harmless EICAR test file, so we can confirm the fields ESET sends for an actual threat (step 3).
2. **Approve the risk rules** in step 4, or tell us what to change.
3. **Approve the masking policy** for data sent to the AI service (step 5).
4. **Decide whether your notification should wait for C-Three's approval** before it is sent. Today it does not (step 7).

---

*Status as of 2 October 2026. Based on the system as currently built and tested with sample alerts; the connection from ESET PROTECT has been tested with test webhooks, and reading ESET's actual alert format is being updated.*
