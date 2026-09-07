# AWS IAM machine-enrollment authentication

The provider sends an `Authorization: AWS-IAM <proof>` header for every
machine-enrollment API operation. `<proof>` is unpadded base64url-encoded JSON
with this shape:

```json
{
  "method": "POST",
  "url": "https://sts.eu-north-1.amazonaws.com/",
  "headers": {},
  "body": "Action=GetCallerIdentity&Version=2011-06-15"
}
```

The headers contain a SigV4 signature for AWS STS and these signed bindings:

- `X-Stegra-Audience`: configured machine-enrollment base URL;
- `X-Stegra-Request-Method`: broker operation method;
- `X-Stegra-Request-URL`: complete broker operation URL;
- `X-Stegra-Request-Body-SHA256`: SHA-256 of the exact broker request body;
- `X-Stegra-Nonce`: a random 256-bit value generated for this operation.

## Broker verification contract

Before accepting the operation, the broker must:

1. Reject proofs outside a short `X-Amz-Date` clock-skew window.
2. Require every binding above in the SigV4 `SignedHeaders` list.
3. Compare the audience, method, URL, and body digest with the received broker
   request using constant-time comparison where appropriate.
4. Atomically consume the nonce in shared storage and reject reuse until after
   the proof-validity window. This must work across all broker replicas.
5. Allow only HTTPS regional AWS STS endpoints resolved for the signature's
   region and partition; never send a supplied proof to an arbitrary URL.
6. Require the exact `GetCallerIdentity` method and body shown above, forward
   the signed request to STS, and accept only a successful response.
7. Normalize assumed-role ARNs and authorize the returned AWS account and IAM
   role against an explicit server-side allowlist.
8. Never log the proof, its authorization header, or its session-token header.

These checks make the proof a short-lived authorization for one exact broker
operation. An AWS identity alone does not grant enrollment rights; the broker's
allowlist remains the authorization boundary.
