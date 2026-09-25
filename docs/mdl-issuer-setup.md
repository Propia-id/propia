# Becoming an mDL issuer

How a workspace gets to the point where it can issue `org.iso.18013.5.1.mDL`, and
how to stand up the certificate authority the flow expects when there isn't a real
one — on a laptop, in a demo environment, or in a pilot that has to work end to end
before any external body has looked at it.

Everything here is done through the issuer console. The only shell work is playing
the part of the issuing authority, which is a role no part of Sovra performs.

## Why this is a separate setup at all

An SD-JWT credential names its issuer by Sovra address, and a verifier resolves that
address against the registry. A conformant mDL carries no such address — the
certificate chain in `x5chain` is the *only* way a reader can attribute it. So a
workspace can issue under an ISO docType exactly when it holds a Document Signer
Certificate that chains to a root Sovra's verifiers accept, which is what
`Sovra.Mdl.can_issue_iso_doc_types?/1` reports and what the schema wizard gates the
ISO driving licence option on.

That means two different people are involved:

| Role | Does | Where |
|---|---|---|
| **Platform admin** (`user.is_admin`) | Admits the IACA root to the trust list | **Trust anchors** (`/trust-anchors`) |
| **Workspace admin** | Generates the signer key, requests certification, registers the certificate | **Settings → Driving licence** (`/settings?tab=mdl`) |
| **The issuing authority** | Signs the certification request | Outside Sovra entirely |

Admitting a root cannot be delegated to the certificate: anyone can self-sign a root
naming any country and authority they like, and the result is structurally
indistinguishable from a real one. In the wider ecosystem the same call is made by
AAMVA's Digital Trust Service or the EU trust list.

## The flow

### 1. Document signer key — workspace admin

**Settings → Driving licence → Create signing key.** A P-256 key, deliberately not the
workspace's general signing key: ISO expects a document signer to rotate on its own
schedule (Annex B caps its certificate at 457 days), and reusing the general key
would tie a format that needs no certificate to a certificate's lifecycle. Dev and
test keep it in the database key store; production generates it in KMS and never
exports it.

### 2. Certification request — workspace admin

**Settings → Driving licence → Ask your authority for a certificate.** Fill in:

- **Country** — ISO 3166-1 alpha-2, and it must match the issuing authority's. Annex
  B requires the signer's country to equal its root's, so getting this wrong produces
  a request no authority can certify.
- **Common name** — how this signer is named in the certificate.
- **State/province**, **organization** — optional. State is only constrained when the
  root declares one.

You get a PKCS#10 PEM. Nothing is stored: it is rebuilt from the key every time, so
there is no stored copy that can drift from the key it names. Send it to your issuing
authority.

### 3. Document signer certificate — platform admin, then workspace admin

The authority returns a certificate, and its IACA root must be admitted before the
certificate can be registered. Until then step 3 says so rather than showing an empty
select.

1. **Platform admin → Trust anchors** → paste the root PEM → admit.
2. **Workspace admin → Settings → Driving licence → step 3** → pick the root → paste the
   certificate → register.

Registration re-checks everything, because it is the last moment anyone is looking:
the certificate parses, chains to the admitted root, passes the Annex B profile, and
— the one check that is about correctness rather than conformance — certifies *this
workspace's* key. A valid chain certifying somebody else's key would pass every
profile rule and produce credentials whose `x5chain` asserts a binding the signature
does not have.

Step 3 then flips to done, a **Ready** card appears, and **Schemas → New → mDoc →
ISO driving licence** enables Continue.

## Standing up an authority with openssl

For development, demos and pilots, where there is no real CA. The certificates below
are checked against the same `Sovra.X509.Certificate` profile as any other, so this
exercises the real flow rather than bypassing it — but a root you minted yourself is
a root you are trusting yourself, and it belongs nowhere a verifier you care about is
reading the trust list.

Save the PEM from step 2 as `csr.pem`, then:

```bash
C=ES   # must equal the country you entered in step 2

cat > iaca.cnf <<EOF
[req]
distinguished_name = dn
prompt = no
x509_extensions = iaca
[dn]
C = $C
CN = Dev IACA
[iaca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF

cat > dsc.cnf <<EOF
[dsc]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,1.0.18013.5.1.2
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# The root. Admit iaca.pem on Trust anchors.
openssl ecparam -name prime256v1 -genkey -noout -out iaca.key
openssl req -x509 -new -key iaca.key -sha256 -days 3650 -config iaca.cnf -out iaca.pem

# The signer, certified from the console's own request. Register dsc.pem in step 3.
openssl x509 -req -in csr.pem -CA iaca.pem -CAkey iaca.key -CAcreateserial \
  -days 400 -sha256 -extfile dsc.cnf -extensions dsc -out dsc.pem
```

Every line earns its place against `backend/lib/sovra/x509/certificate.ex`:

| Setting | Rule it satisfies |
|---|---|
| `prime256v1` | the parser accepts only a 65-byte uncompressed P-256 point |
| root `CA:TRUE,pathlen:0` | `pathLenConstraint` must be 0 or absent |
| root `keyCertSign,cRLSign` | both are required of an IACA |
| root `C` + `CN` | an IACA must name a country and a common name |
| root self-signed | `validate_iaca/2` rejects anything else |
| DSC `CA:FALSE` | a document signer may not be a CA |
| DSC `digitalSignature` **alone** | key usage is compared as an exact list — adding `keyEncipherment` fails |
| DSC EKU `1.0.18013.5.1.2` | `id-mdlDS`. Critical is fine: the chain validator whitelists that one OID, since OTP would otherwise reject it as an unknown critical extension |
| `-days 400` | inside Annex B's 457-day ceiling |
| DSC country = root country | subject agreement. Add `ST` to the DSC only when the root declares one |
| the CSR reused as-is | the certificate inherits the request's public key, which is how it ends up certifying the workspace's key |

Nothing caps an IACA's lifetime, so `-days 3650` is only a convention. Keep
`iaca.key` if you intend to certify more signers under the same root — the root is
admitted by certificate, and a second root means a second admission.

### Automating it

`SovraTest.MdlCertificates` (in `backend/test/support/mdl_certificates.ex`) is the
same authority in Elixir: `iaca/1` mints a root, `document_signer/3` certifies a key
under it, and `provision_document_signer/2` runs the whole registration flow for a
workspace. It is pure `:public_key`, so a `mix run` script can
`Code.require_file/1` it outside the test environment — `mix sovra.mdl_certificate_fixture`
does exactly that.

## Starting over

There is no endpoint that clears a signer: `mdl_signer_changeset/2` requires the
fields it casts, and `withdraw_issuing_authority/1` refuses while any workspace still
chains to the root — the alternative is a workspace that keeps issuing credentials no
verifier of ours accepts, surfacing as an unexplained `unknown_issuer` rather than as
the withdrawal it actually is. On a dev database, delete the signing keys first, clear
the workspaces second, and the roots third:

```elixir
# mix run, dev only
import Ecto.Query
alias Sovra.{Crypto.Key, Repo, Mdl.IssuingAuthority, Workspaces.Workspace}

# `mdl_signing_key_id` is the only handle to the key material, so the keys go
# before the columns naming them. Nulling first leaves them orphaned.
from(w in Workspace,
  where: not is_nil(w.mdl_signing_key_id),
  select: w.mdl_signing_key_id
)
|> Repo.all()
|> Enum.each(&Key.delete_key/1)

Repo.update_all(
  from(w in Workspace, where: not is_nil(w.mdl_signing_key_id)),
  set: [
    mdl_signer_certificate: nil,
    mdl_issuing_authority_id: nil,
    mdl_signing_key_id: nil,
    mdl_signing_public_key_x: nil,
    mdl_signing_public_key_y: nil
  ]
)

Repo.delete_all(IssuingAuthority)
```

`Key.delete_key/1` goes to whichever store is configured, and the two behave
differently. `DatabaseKeyStore` — dev and test — deletes the row, and the private key
is gone the moment the call returns. `KmsKeyStore` posts to the signer service, which
calls `ScheduleKeyDeletion` with a seven-day pending window: the key still exists but
signs nothing, and until the window closes `CancelKeyDeletion` in the AWS console puts
it back. Either way the call is idempotent — a key id the store has never heard of
returns `:ok`.

Deleting the key is what makes starting over honest. The certificate its authority
issued names a public key, so a key left behind is a live signer for a workspace that
no longer admits to having one, and the next `Create signing key` mints a second key
the old certificate does not certify.

Only delete the key you meant to: `mdl_signing_key_id` is the document signer, and a
workspace's `signing_key_id` — the SD-JWT key behind every other credential it has
ever issued — is a different column. In KMS the document signer is the one aliased
`alias/sovra/<env>/app/workspace-<workspace id>-mdl-ds`.

Schemas already created under `org.iso.18013.5.1.mDL` survive this and will fail to
issue until a signer is registered again.

## When registration is refused

Failures name the rule rather than saying "invalid certificate", because you are
holding a certificate and need to know which field to go back to your authority
about. `iaca_profile.*` comes from admitting a root, `dsc_profile.*` from registering
a signer, and `dsc_profile.chain.*` from path validation itself.

| Reason | What to change |
|---|---|
| `iaca_profile.not_self_signed` | the root must be self-signed — you pasted an intermediate |
| `iaca_profile.basic_constraints` | `CA:TRUE` with `pathlen` 0 or absent |
| `iaca_profile.key_usage` | both `keyCertSign` and `cRLSign` |
| `dsc_profile.key_usage` | `digitalSignature` and nothing else |
| `dsc_profile.missing_mdl_eku` | add EKU `1.0.18013.5.1.2` |
| `dsc_profile.validity_too_long` | 457 days or fewer |
| `dsc_profile.country_mismatch` | the signer's `C` must equal the root's |
| `dsc_profile.state_mismatch` | the root declares a state, so the signer must declare the same one |
| `dsc_profile.is_a_ca` | `CA:FALSE`, or no `basicConstraints` at all |
| `dsc_profile.chain.*` | the certificate was not issued by the root you selected |
| `dsc_profile.certifies_another_key` | the chain is fine but the certificate names a different public key — certify the current request, not an older one |
| `iaca_profile.expired`, `dsc_profile.not_yet_valid` | the validity window does not contain now |
