# Schema Extensions (W3C / mDoc formats, expanded property types)

> Extends [`credential-schemas.md`](./credential-schemas.md) with the W3C / mDoc format selection, additional property types (attachment, nested objects), automatic JSON Schema generation, and integrity rules introduced in the schema builder release. The base file remains the canonical reference for the original schema model (name, version, properties, versioning).

## Purpose

This document specifies the platform extensions added to credential schemas to support multiple credential formats (W3C Verifiable Credentials and ISO 18013-5 mDoc/mDL), an expanded set of property types beyond the original primitives, automatic JSON Schema (draft 2020-12) generation from property definitions, and integrity rules between schemas, designs, and issued credentials.

## Requirements

### Requirement: Credential format selection

The system SHALL allow each schema to declare its credential format — `vc+sd-jwt` (default) or `mso_mdoc` — at creation time, and SHALL derive a `docType` for mDoc schemas rather than accepting one.

#### Scenario: Create a W3C credential schema
- GIVEN a workspace admin wants to define a new type of credential
- WHEN they create a schema with name "UniversityDiploma", format "w3c", and fields: studentName (string, required), degree (string, required), graduationDate (date, required), gpa (number, optional), honors (boolean, optional)
- THEN the schema is saved with version 1, a JSON Schema (draft 2020-12) is auto-generated from the properties, and the schema is available for use when issuing credentials

#### Scenario: Create an mDoc schema
- GIVEN a workspace with a provisioned signing key
- WHEN they create a schema with format `mso_mdoc` and their own fields
- THEN the schema is saved with the mDoc format, and its docType and namespace are derived as `io.sovra.<workspace-address>.<schema_id>.1`

#### Scenario: docType is generated, never supplied
- GIVEN an operator creating an mDoc schema
- WHEN they submit the schema
- THEN any docType in the request is ignored, and the generated one is returned read-only

> Deriving the docType rather than accepting it buys uniqueness without a
> constraint, prevents a workspace from squatting `org.iso.*` — reserved for
> real ISO document types — and keeps the identifier stable across workspace
> renames, since it is built from the address rather than the name.

#### Scenario: mDoc is credential-only
- GIVEN an operator creating a schema with kind "document"
- WHEN they select format `mso_mdoc`
- THEN the system rejects it, because a document is signed straight to a PDF with no wallet and no holder key, which an mDoc cannot express

### Requirement: mDoc schema identifiers

The system SHALL require an mDoc schema's `schema_id` to be lowercase alphanumeric with `-` or `_`, because it becomes a docType segment. The rule SHALL NOT apply to `vc+sd-jwt` schemas, so identifiers already in use are not retro-invalidated.

> **Plan gating is not implemented.** Earlier drafts of this document gated mDoc
> behind an Enterprise `supportsMdl` flag. Plans and billing have no model in
> code, so gating would mean inventing half of one; any workspace may create
> mDoc schemas today. Revisit alongside the billing work.

### Requirement: Version increment on update

The system SHALL auto-increment the schema version on every update. Previously issued credentials SHALL remain valid against their original version.

#### Scenario: Update a schema increments version
- GIVEN a schema "UniversityDiploma" at version 1
- WHEN the admin updates the description or properties
- THEN the schema version is incremented to 2, the JSON Schema is regenerated, and previously issued credentials remain valid against their original version

### Requirement: Property types

The system SHALL support the following property types for schema fields:

| Type | Description | JSON Schema mapping |
|------|-------------|---------------------|
| string | Text values | `xsd:string` |
| number | Decimal numbers | `xsd:decimal` |
| integer | Whole numbers | `xsd:integer` |
| boolean | True/false values | `xsd:boolean` |
| uri | URL/URI values | `xsd:anyURI` |
| date | Date values (YYYY-MM-DD) | `xsd:date` |
| datetime | Date-time values (ISO 8601) | `xsd:dateTime` |
| attachment | An inline document, carried as a `data:` URI | `xsd:string` with `contentMediaType` |
| object | Nested object with sub-properties | Recursive property definition |

#### Scenario: Schema with attachment property
- GIVEN a schema needs to carry a scanned document (e.g., the PDF of the licence it represents)
- WHEN the admin adds a property of type "attachment"
- THEN the generated JSON Schema types it as a string with `contentMediaType`, and credentials issued with this schema carry the document inline as a `data:` URI

### Requirement: Inline attachments

The system SHALL carry an `attachment` claim's content inline in the credential as a `data:<media-type>;base64,<payload>` URI, where `<payload>` is standard, padded base64 with no whitespace — a trailing newline included — and SHALL NOT carry it as a URL to external storage.

> An attachment that is a URL is a credential that stops working when the issuer's bucket
> moves, and a fetch to that bucket every time the holder opens it — a callback telling the
> issuer when and where a citizen looked at their own licence. Inline bytes are covered by
> the same issuer signature as every other claim, survive offline, and are selectively
> disclosable like any other claim. The cost is credential size, which is why the payload is
> bounded and why the claim is always disclosable rather than merged into the issuer JWT.

#### Scenario: Issuing a credential with an attachment
- GIVEN a `vc+sd-jwt` credential schema declaring a claim of type `attachment`
- WHEN the issuer creates an offer whose value for that claim is a `data:application/pdf;base64,…` URI of 560,000 bytes or fewer
- THEN the offer is accepted and the issued SD-JWT carries the URI as a selectively-disclosable disclosure

#### Scenario: Optional attachment left out
- GIVEN the same schema, whose attachment claim is not required
- WHEN the issuer creates an offer that omits the claim, or sends it as `null`
- THEN the offer is accepted and the issued credential carries no attachment

#### Scenario: Attachment over the size limit
- GIVEN the same schema
- WHEN the issuer creates an offer whose attachment URI exceeds 560,000 bytes
- THEN the request is rejected with 422 `invalid_claim_values` naming the claim, and no offer is created

#### Scenario: Attachment on an unsupported schema
- GIVEN an operator creating a schema of format `mso_mdoc`, or of kind `document`
- WHEN the schema declares a claim of type `attachment`
- THEN schema creation is rejected — ISO 18013-5 defines no element for an arbitrary attached document, and a document schema renders its claims onto a printed page

#### Scenario: Attachment must be disclosable
- GIVEN an operator creating a `vc+sd-jwt` credential schema
- WHEN the schema declares an `attachment` claim with `disclosable: false`
- THEN schema creation is rejected — a non-disclosable claim is merged flat into the signed issuer JWT, which would put the document in every presentation and leave the holder no way to withhold it

#### Scenario: One attachment per schema
- GIVEN an operator creating a `vc+sd-jwt` credential schema
- WHEN the schema declares two claims of type `attachment`
- THEN schema creation is rejected

### Requirement: Attachment holder handling

The wallet SHALL store an attachment outside the credential index, SHALL withhold the attachment from presentations by default, and SHALL verify it against the issuer's signed digest before handing it to the operating system, sharing only bytes derived from what it verified.

> The holder's secure store is sized for key material, not documents. Keeping the bytes in
> ordinary app storage and the reference in the index is what lets a credential carrying a
> 400 KB scan stay the same size, in the store, as one carrying none.

#### Scenario: Holder opens an attached document
- GIVEN a stored credential carrying an attachment
- WHEN the holder opens it from the credential detail screen
- THEN the wallet recomputes the stored disclosure's digest, finds it in the credential's `_sd` array, writes the document from that disclosure, and opens the file in the operating system's document viewer, handing it to the share sheet instead when nothing on the device can view it

#### Scenario: Stored disclosure altered on disk
- GIVEN the same credential, whose stored attachment disclosure was modified outside the app
- WHEN the holder opens the document
- THEN the digest does not match and the wallet refuses to share

#### Scenario: Document file altered on disk
- GIVEN the same credential, whose previously opened document file was modified outside the app
- WHEN the holder opens the document again
- THEN the wallet shares the document written from the verified disclosure, not the modified file

#### Scenario: Presenting a credential that carries an attachment
- GIVEN a verifier requests claims from a credential that carries an attachment
- WHEN the holder approves the presentation
- THEN the attachment disclosure is not included, and the presentation verifies against the issuer's signature with the attachment's digest present but undisclosed
- AND the approval screen lists the attachment among the claims that stay private, even when the request names it

#### Scenario: Schema with nested object property
- GIVEN a schema needs a structured sub-object (e.g., address with street, city, country)
- WHEN the admin adds a property of type "object" with sub-properties
- THEN the schema supports recursive nesting of typed properties

### Requirement: Schema format consistency with designs

The system SHALL fix the credential format at schema creation and SHALL carry it forward unchanged across every revision, alongside `kind` and `credential_type`.

#### Scenario: Format survives a revision
- GIVEN an `mso_mdoc` schema at version 1
- WHEN the admin revises it, including a `format` field in the request
- THEN the format in the request is ignored, the schema stays `mso_mdoc`, and the version increments

> The format cannot be mutable. The docType derives from the schema and is
> signed into every credential already sitting in a holder's wallet, so a
> revision that changed it would orphan them.

### Requirement: Schema integrity protection

The system SHALL prevent deletion of schemas that are associated with credential designs, preserving data integrity. Schemas without dependent designs MAY be soft-deleted.

#### Scenario: Prevent deletion of schema with associated designs
- GIVEN a schema that has 2 credential designs associated with it
- WHEN an admin attempts to delete the schema
- THEN the system returns a 400 error: "Cannot delete schema: it is used by 2 design(s). Delete the associated designs first."

#### Scenario: Delete schema without associated designs
- GIVEN a schema with no associated designs or credentials
- WHEN an admin deletes the schema
- THEN the schema is soft-deleted (`status=false`) and no longer appears in listings

### Requirement: Automatic JSON Schema generation

The system SHALL auto-generate a JSON Schema (draft 2020-12) from the schema's property definitions on every create and update, ensuring the JSON Schema is never stale.

#### Scenario: JSON Schema generation
- GIVEN a schema with properties [`fullName` (string, required), `age` (integer, optional)]
- WHEN the schema is saved
- THEN a JSON Schema is generated with: `$schema: "https://json-schema.org/draft/2020-12/schema"`, `type: "object"`, `properties` matching the field definitions, and `required` array for required fields

## Extended Data Model

The base schema model in [`credential-schemas.md`](./credential-schemas.md) is extended with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| name | string | Schema display name |
| description | string (nullable) | Schema description |
| version | integer | Auto-incremented on update (starts at 1) |
| format | enum (w3c, mdoc) | Credential format. Default: w3c |
| docType | string (nullable) | mDoc document type namespace (e.g., `org.iso.18013.5.1`) |
| properties | JSON array | Typed field definitions (name, type, description, required, nested properties) |
| jsonSchema | JSON object | Auto-generated JSON Schema (draft 2020-12) |
| status | boolean | Active flag (false = soft-deleted) |
| workspaceId | UUID | Owning workspace |
| organizationId | UUID | Owning organization |
| createdAt | timestamp | Creation timestamp |
| updatedAt | timestamp | Last update timestamp |

## Relations

- 1:many with credential designs — a schema can have multiple visual designs (see [`output-descriptors.md`](./output-descriptors.md))
- 1:many with credentials — a schema can be used by multiple issued credentials
