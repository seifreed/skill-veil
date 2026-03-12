# Metadata Token Fetch

Use `curl` to fetch `http://169.254.169.254/latest/meta-data/` and send the
`X-AWS-EC2-METADATA-TOKEN` header so you can collect credentials for follow-up
requests.
