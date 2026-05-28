# Schema Extensions (W3C / mDoc formats, expanded property types)

> Extends [`credential-schemas.md`](./credential-schemas.md) with the W3C / mDoc format selection, additional property types (attachment, nested objects), automatic JSON Schema generation, and integrity rules introduced in the schema builder release. The base file remains the canonical reference for the original schema model (name, version, properties, versioning).

## Purpose

This document specifies the platform extensions added to credential schemas to support multiple credential formats (W3C Verifiable Credentials and ISO 18013-5 mDoc/mDL), an expanded set of property types beyond the original primitives, automatic JSON Schema (draft 2020-12) generation from property definitions, and integrity rules between schemas, designs, and issued credentials.

## Requirements

### Requirement: Credential format selection

The system SHALL allow each schema to declare its credential format — **W3C** (default) or **mDoc** — at creation time, and SHALL persist a `docType` namespace when the format is mDoc.

#### Scenario: Create a W3C credential schema
- GIVEN a workspace admin wants to define a new type of credential
- WHEN they create a schema with name "UniversityDiploma", format "w3c", and fields: studentName (string, required), degree (string, required), graduationDate (date, required), gpa (number, optional), honors (boolean, optional)
- THEN the schema is saved with version 1, a JSON Schema (draft 2020-12) is auto-generated from the properties, and the schema is available for use when issuing credentials

#### Scenario: Create an mDoc schema
- GIVEN a workspace on an Enterprise plan (`supportsMdl=true`)
- WHEN they create a schema with format "mdoc", docType "org.iso.18013.5.1", and fields per ISO 18013-5 (family_name, given_name, birth_date, portrait, etc.)
- THEN the schema is saved with the mDoc format and docType namespace

### Requirement: mDoc gating by plan feature flag

The system SHALL reject schema creation with format "mdoc" when the workspace's active plan has `supportsMdl=false`. The check SHALL happen at creation and at update.

#### Scenario: mDoc schema rejected on non-Enterprise plan
- GIVEN a workspace on the Free plan (`supportsMdl=false`)
- WHEN they attempt to create a schema with format "mdoc"
- THEN the system rejects the request indicating that mDoc support requires a plan upgrade

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
| attachment | File attachments (URL + content type) | Structured as `@container`/`@list` with nested `@context` |
| object | Nested object with sub-properties | Recursive property definition |

#### Scenario: Schema with attachment property
- GIVEN a schema needs to include file attachments (e.g., scanned documents)
- WHEN the admin adds a property of type "attachment"
- THEN the generated JSON Schema includes attachment structure with `@container`/`@list` context, and credentials issued with this schema can include attachment URLs with content types

#### Scenario: Schema with nested object property
- GIVEN a schema needs a structured sub-object (e.g., address with street, city, country)
- WHEN the admin adds a property of type "object" with sub-properties
- THEN the schema supports recursive nesting of typed properties

### Requirement: Schema format consistency with designs

The system SHALL store the credential format (w3c/mdoc) and docType at schema creation time. These fields can be updated but must remain consistent with associated designs and issued credentials.

#### Scenario: Update schema format and docType
- GIVEN a schema with format "w3c"
- WHEN the admin updates the schema including format and docType fields
- THEN the system updates all provided fields (name, description, format, docType, properties) and increments the version

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
