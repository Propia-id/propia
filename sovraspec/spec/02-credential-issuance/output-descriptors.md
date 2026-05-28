# Output Descriptors (W3C credential rendering)

> Extends [`credential-designs.md`](./credential-designs.md) with the W3C Output Descriptor structure, image upload sanitization, design-schema binding, and plan-limit enforcement introduced in the design builder release. The base file remains the canonical reference for the original visual design model (background color, text color, logo, displayed fields).

## Purpose

This document specifies how credential designs are stored and rendered using the W3C credential rendering specification (Output Descriptors). Each design wraps an Output Descriptor that defines the front and back layout (title, subtitle, description, properties, background, text, hero, thumbnail), the binding to a schema, image upload handling, and the lifecycle constraints introduced in the design builder release.

## Requirements

### Requirement: Design creation with Output Descriptor

The system SHALL allow creation of credential designs with full Output Descriptor configuration, bound to a schema.

#### Scenario: Create a credential design
- GIVEN a workspace has a schema "UniversityDiploma"
- WHEN the admin creates a design specifying:
  - Name: "University Diploma Design"
  - Schema: UniversityDiploma
  - Front side: title "University Diploma", subtitle "{studentName}", background color #1a365d, text color #ffffff, hero image (background), thumbnail image (logo)
  - Back side: displayed properties with paths, labels, and fallback values
- THEN the design is saved with the full Output Descriptor structure and linked to the schema

#### Scenario: Create design with inline schema creation
- GIVEN a user is creating a design and needs a new schema
- WHEN they create a schema from within the design editor
- THEN the schema is created first, and the design is bound to it

### Requirement: Output Descriptor structure

The system SHALL store designs as Output Descriptors following the W3C credential rendering specification.

The Output Descriptor structure SHALL include:

**Display:**
- `title` — Credential title (text + fallback)
- `subtitle` — Credential subtitle (text + fallback)
- `description` — Credential description (text)
- `properties` — Array of displayed fields, each with:
  - `path` — JSONPath to the credential field (e.g., `$.credentialSubject.fullName`)
  - `label` — Display label
  - `fallback` — Default value if field is missing
  - `schema` — Property type metadata (type, format, contentMediaType for attachments)

**Styles:**
- `background.color` — Card background color (hex)
- `text.color` — Text color (hex)
- `hero.uri` — Background/header image URL
- `hero.alt` — Hero image alt text
- `thumbnail.uri` — Logo/icon image URL
- `thumbnail.alt` — Thumbnail alt text

#### Scenario: Design with attachment properties
- GIVEN a schema has an attachment-type property (e.g., diploma scan)
- WHEN the admin adds this property to the design's display properties
- THEN the property schema includes `type: "attachment"` with appropriate content type metadata

### Requirement: Design image uploads

The system SHALL support image uploads for hero (background) and thumbnail (logo) images, storing them in cloud storage with sanitized filenames.

#### Scenario: Upload design image
- GIVEN an admin is configuring a design's hero image
- WHEN they upload an image file
- THEN the file is uploaded to cloud storage with a sanitized filename (special characters replaced with underscores), and the resulting URL is stored in the design

#### Scenario: Upload image with special characters in filename
- GIVEN an admin uploads a file named "Screenshot 2026-05-07 at 7.43.32 PM.png"
- WHEN the upload is processed
- THEN the filename is sanitized to "Screenshot_2026-05-07_at_7.43.32_PM.png" before storage

### Requirement: Design update and deletion

The system SHALL allow updating and deleting designs with appropriate constraints.

#### Scenario: Update design colors
- GIVEN a credential design exists
- WHEN the admin updates the background color
- THEN the Output Descriptor is updated; newly issued credentials reflect the new design

#### Scenario: Delete a design
- GIVEN a credential design with no issued credentials
- WHEN the admin deletes the design
- THEN the design is removed

### Requirement: Design-schema binding

Each design SHALL be bound to exactly one schema. The schema cannot be changed after the design is created.

#### Scenario: Schema locked on design creation
- GIVEN a design bound to schema "UniversityDiploma"
- WHEN the admin edits the design
- THEN the schema selector is disabled; only display and style properties can be modified

### Requirement: Plan limit enforcement

Design creation SHALL be subject to the workspace's plan limit for `maxCredentialDesigns`.

#### Scenario: Design limit reached
- GIVEN a workspace on the Free plan (`maxCredentialDesigns=2`) with 2 designs
- WHEN the admin attempts to create a third design
- THEN the system rejects with 403 and the current/limit counts

## Data Model

| Field | Type | Description |
|-------|------|-------------|
| id | UUID | Primary key |
| name | string | Design display name |
| schemaId | UUID | Bound schema (immutable after creation) |
| outputDescriptor | JSON | Full Output Descriptor (display + styles) |
| status | boolean | Active flag |
| workspaceId | UUID | Owning workspace |
| organizationId | UUID | Owning organization |
| createdAt | timestamp | Creation timestamp |
| updatedAt | timestamp | Last update timestamp |

## Output Descriptor JSON Structure

```json
{
  "id": "design_<uuid>",
  "schema": "https://api.sovra.io/public/schemas/<schemaId>",
  "display": {
    "title": { "text": "University Diploma" },
    "subtitle": { "text": "Daniel Quinteros" },
    "description": { "text": "Bachelor of Science" },
    "properties": [
      {
        "path": ["$.credentialSubject.fullName"],
        "label": "Full Name",
        "fallback": "Unknown",
        "schema": { "type": "string" }
      }
    ]
  },
  "styles": {
    "background": { "color": "#1a365d" },
    "text": { "color": "#ffffff" },
    "hero": { "uri": "https://storage.example.com/hero.png", "alt": "Header" },
    "thumbnail": { "uri": "https://storage.example.com/logo.png", "alt": "Logo" }
  }
}
```
