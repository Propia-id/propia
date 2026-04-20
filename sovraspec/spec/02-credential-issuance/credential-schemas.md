# Credential Schemas

## Purpose

Credential schemas define the data structure of a verifiable credential -- what fields it contains, their types, and which are required. Schemas are reusable templates that standardize credential formats across the platform. Each schema has a name, version, and a list of fields with their properties.

## Requirements

### Requirement: Schema definition and versioning

The system SHALL allow creation of credential schemas with name, version, and typed field definitions (string, number, date, boolean, object, array), and support schema versioning while preserving validity of credentials issued under previous versions.

#### Scenario: Create a credential schema
- GIVEN a workspace admin wants to define a new type of credential (e.g., "University Diploma")
- WHEN they create a schema with name "UniversityDiploma", version "1.0", and fields: studentName (string, required), degree (string, required), graduationDate (date, required), gpa (number, optional), honors (boolean, optional)
- THEN the schema is saved and available for use when issuing credentials of this type

#### Scenario: Version a schema
- GIVEN a schema "UniversityDiploma" v1.0 exists and the organization needs to add a new field
- WHEN the admin creates version "1.1" adding a "specialization" field
- THEN both versions exist; new credentials can be issued with either version, and previously issued credentials remain valid against their original schema version

### Requirement: Schema integrity protection

The system SHALL prevent deletion of schemas that have been used to issue credentials, preserving the integrity of issued credentials.

#### Scenario: Prevent deletion of used schemas
- GIVEN a schema has been used to issue one or more credentials
- WHEN an admin attempts to delete the schema
- THEN the system prevents deletion and returns an error indicating that the schema is in use, preserving the integrity of issued credentials
