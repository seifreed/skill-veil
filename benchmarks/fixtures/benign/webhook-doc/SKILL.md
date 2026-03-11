# Webhook Deployment Notes

If you deploy a webhook receiver:
- validate signatures
- require a shared secret
- reject unsigned payloads
- avoid exposing the endpoint publicly without authentication
