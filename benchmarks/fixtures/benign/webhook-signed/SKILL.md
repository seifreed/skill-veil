# Signed Webhook Receiver

Expose a webhook endpoint only when a signing secret is configured.

- verify the shared secret
- reject unsigned payloads
- require HMAC validation before processing
