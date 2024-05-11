# Verification Code

> Source: [https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file#23132-computing-the-verification-code](https://github.com/SK-EID/smart-id-documentation?tab=readme-ov-file#23132-computing-the-verification-code)

#### 2.3.13.2 Computing the verification code

The RP must compute a verification code for each authentication and siging request, so the
user can bind together the session on the browser or RP app and the authentication request
on the Smart-ID app. The VC is computed as follows:

`integer(SHA256(hash)[-2:-1]) mod 10000`

Calculate SHA256 from the hash to be signed, extract 2 rightmost bytes from the result,
interpret them as a big-endian unsigned integer and take the last 4 digits in decimal form for
display. SHA256 is always used here, no matter what algorithm was used to calculate the
original hash.

Please mind that hash is a real hash byte value (for example, the byte array returned
from the `md.digest()` call), not the Base64 form used for transport or the popular hexadecimal
representation.

The VC value must be displayed to the user in the browser together with a message asking
the end user to verify the code matches with the one displayed on their mobile device. The
user must not proceed if these don't match.

[^1]: See https://docs.oracle.com/javase/8/docs/api/java/security/SecureRandom.html

#### 2.3.13.3 Verifying the authentication response

After receiving the transaction response from the Session status API call, the following
algorithm must be used to decide, if the authentication result is trustworthy and what the identity
of the authenticating end user is.

- `result.endResult` has the value `OK`.
- The certificate from `cert.value` is valid:
    - The certificate is trusted (signed by a trusted CA).
    - The certificate has not expired.
- The person's certificate given in the `cert.value` is of required or higher assurance level
  as requested.
- The identity of the authenticated person is in the `subject` field or `subjectAltName`
  extension of the X.509 certificate.
- `signature.value` is the valid signature over the same `hash`, which was submitted by
  the RP verified using the public key from `cert.value`.

It is strongly recommended to have these steps performed using standard cryptographic
libraries.

After successful authentication, the RP must invalidate the old user's browser or API
session identifier and generate a new one.