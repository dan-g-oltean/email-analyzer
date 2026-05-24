# Building a Claude-Powered Email Scanner for Apache James

A step-by-step walkthrough of integrating Anthropic's Claude API into an Apache James mail server (JPA distribution, embedded Derby) to detect phishing, scams, spam, and malware in incoming email.

**Structure:**
- **Phase 0** — Get an Anthropic API key
- **Phase 1** — Prototype outside James (Python) to validate AI quality
- **Phase 2** — Build the production mailet (Java)
- **Phase 3** — Production hardening (notes on next steps)

## Phase 0: Get an Anthropic API Key

Before any code, you need credentials.

1. Go to [console.anthropic.com](https://console.anthropic.com) and sign up.
2. Add a small amount of credit ($5 is plenty for prototyping — Haiku 4.5 classifications cost fractions of a cent each).
3. Set a monthly spending limit in **Settings → Billing → Spend limits**. Cap it at $5 or $10 so you can't accidentally drain your account during testing.
4. Create an API key in **Settings → API Keys**. Copy it immediately — you won't see it again. It looks like `sk-ant-api03-...`.
5. Store it in your shell environment:

```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.bashrc
source ~/.bashrc
echo $ANTHROPIC_API_KEY   # verify it's set
```

**Why environment variable**: never hardcode API keys in source files or XML configs. They leak through git commits, log files, and screenshots.

## Phase 1: Prototype Outside James (Validate the AI)

Before writing a mailet, prove that Claude can classify emails well enough for your purposes. This phase takes maybe an hour and saves you from building a mailet around a model that doesn't work well for your use case.

### Step 1.1: Set up

Install the Anthropic SDK. In a terminal:

```bash
python3 -m venv venv
source venv/bin/activate
pip install anthropic
```
### Step 1.2: Write the classifier

Key design choices:

- **System prompt** carries the role and output format. Putting the "untrusted input" warning here (not in the user message) makes it harder to override via prompt injection.
- **`<email>...</email>` delimiters** give Claude a clear boundary between instructions and data.
- **`max_tokens=400`** caps the response size — classifications shouldn't need more.
- **Code-fence stripping** handles Claude occasionally wrapping JSON in ```` ```json ... ``` ```` despite being told not to.

### Step 1.3: Quick smoke test

Run a hardcoded phishing example to confirm the API call works and the JSON parses.

```python

result = classify_email(
    sender="security@paypa1-verify.com",
    subject="URGENT: Your account will be suspended",
    body="Dear customer, we detected unusual activity. Click here to verify your identity within 24 hours or your account will be permanently locked: http://paypa1-verify.com/login"
)
print(json.dumps(result, indent=2))

```

Expected output (something like):

```json
{
  "score": 0.95,
  "category": "phishing",
  "reason": "Spoofed PayPal domain, urgency tactic, credential harvesting URL.",
  "indicators": [
    "Sender domain 'paypa1-verify.com' impersonates PayPal with character substitution",
    "Urgency language ('24 hours', 'permanently locked')",
    "Request to click link and enter credentials",
    "Lookalike domain in URL"
  ]
}
```

### Step 1.4: Scan your actual James INBOX

Now connect to James over IMAPS, pull messages, and classify each one. **Adjust `USER` and `PASSWORD` below to match your setup.**

```python
import imaplib
import email
import ssl
from email.header import decode_header

IMAP_HOST = "localhost"
IMAP_PORT = 993
USER = "danoltean@test.com"
PASSWORD = "newpass"

def decode(value):
    """Decode RFC 2047 encoded headers."""
    if value is None:
        return ""
    parts = decode_header(value)
    return "".join(
        (p.decode(enc or "utf-8", errors="replace") if isinstance(p, bytes) else p)
        for p, enc in parts
    )

def extract_body(msg):
    """Pull the text/plain part out of a MIME message."""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                return part.get_payload(decode=True).decode(errors="replace")
        return ""
    payload = msg.get_payload(decode=True)
    return payload.decode(errors="replace") if payload else ""

def scan_inbox():
    # Self-signed cert in dev — disable verification
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    M = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ctx)
    M.login(USER, PASSWORD)
    M.select("INBOX")

    _, data = M.search(None, "ALL")
    msg_ids = data[0].split()
    print(f"Found {len(msg_ids)} messages in INBOX\n")

    for msg_id in msg_ids:
        _, msg_data = M.fetch(msg_id, "(RFC822)")
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)

        sender = decode(msg.get("From"))
        subject = decode(msg.get("Subject"))
        body = extract_body(msg)

        print(f"--- Message {msg_id.decode()} ---")
        print(f"From: {sender}")
        print(f"Subject: {subject}")
        print(f"Body preview: {body[:200]}...")

        verdict = classify_email(sender, subject, body)
        print(f"VERDICT: score={verdict['score']} category={verdict['category']}")
        print(f"Reason: {verdict['reason']}")
        print()

    M.logout()

scan_inbox()
```

### Step 1.5: Test with a variety of emails

Send varied test messages via `telnet localhost 25` (clean, marketing spam, phishing, scam, edge cases) and re-run the scan cell. **This is the most important step** — you're calibrating whether Haiku's judgment matches your needs.

Categories to cover:
- **Clean**: normal personal/business message
- **Marketing spam**: "FREE SHIPPING! Limited offer! Click now!"
- **Phishing**: fake bank/PayPal/Microsoft credential request
- **Scam**: Nigerian prince, fake invoice, gift card request from "CEO"
- **Edge case**: legitimate transactional email (order confirmation, password reset) — often look phishing-adjacent

If Haiku makes mistakes on subtle phishing, try Sonnet 4.6 — change one line in `classify_email`:

```python
model="claude-sonnet-4-6"
```

More expensive, more accurate. Decide based on your tests.

## Phase 2: Build the James Mailet

Now you wrap the working classifier in a Java mailet that James can plug into the mail processing pipeline.

### Step 2.1: Maven project setup

Create a directory and `pom.xml`:

```bash
mkdir ~/james-claude-mailet
cd ~/james-claude-mailet
```

### Step 2.2: The mailet


**Walkthrough of the key parts:**

- `init()` reads config from the mailet XML element. `getInitParameter` returns the value of a child element. Falls back to the environment variable for the API key. Throws if no key — fail fast on misconfig.
- `service()` is called for every mail. We extract data, call Claude, annotate headers, optionally rewrite the subject, save. The whole thing is in try/catch with **fail-open** behavior: if anything blows up, log and pass the mail through. You never want spam filtering to drop legitimate mail.
- `classify()` builds the Anthropic API request as JSON, sends it via Java's built-in `HttpClient`, parses the response.
- `extractText()` walks multipart MIME structures to find the text/plain part. Real emails are often multipart (text + HTML); we only need text for classification.
- `mail.setState("quarantine")` (commented out) routes the mail to a different processor in `mailetcontainer.xml` for separate handling.

### Step 2.3: Build the JAR

```bash
mvn clean package
```

Output: `target/james-claude-mailet-1.0.0.jar`. Verify it's the shaded fat JAR (~2 MB with Jackson bundled):

```bash
ls -lh target/*.jar
unzip -l target/james-claude-mailet-1.0.0.jar | grep -i jackson | head
```
### Step 2.4: Install in James

Stop James (Ctrl+C in its terminal), then:

```bash
cp target/james-claude-mailet-1.0.0.jar /path/to/james/lib/
```

Make sure the API key is in the environment of whatever user/process will run James:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

For a systemd unit, add `Environment="ANTHROPIC_API_KEY=sk-ant-..."`. For a launch script, source a file before starting James.

### Step 2.5: Register the mailet

Edit `conf/mailetcontainer.xml`. Find the `transport` processor — it's where mail flows after acceptance, before delivery. Insert the scanner right before `LocalDelivery`:

```xml
<processor state="transport" enableJmx="true">
    <!-- ... existing mailets (RemoteAddrNotInNetwork, RelayLimit, etc.) ... -->

    <mailet match="RecipientIsLocal" class="com.acasa.ClaudeScannerMailet">
        <model>claude-haiku-4-5-20251001</model>
        <quarantineThreshold>0.85</quarantineThreshold>
        <warningThreshold>0.5</warningThreshold>
        <maxBodyChars>8000</maxBodyChars>
    </mailet>
    <mailet match="RecipientIsLocal" class="LocalDelivery"/>
</processor>
```

**Why this placement**: `RecipientIsLocal` ensures you only scan mail being delivered to your users — not outbound mail being relayed, not bounces. Don't waste API calls on mail you're just passing through.

