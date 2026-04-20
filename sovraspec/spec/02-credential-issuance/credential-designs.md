# Credential Designs

## Purpose

Visual credential designs define how a credential appears to holders and verifiers. Each design specifies the front and back layout including images, text colors, background colors, and which schema fields are displayed. Designs are associated with a credential schema and control the credential's visual representation in wallets.

## Requirements

### Requirement: Visual design creation and management

The system SHALL allow creation, update, preview, and deletion of credential designs with configurable front and back layouts including background color, text color, logo image, issuer name, credential title, and displayed fields.

#### Scenario: Create a credential design
- GIVEN a workspace has a schema "UniversityDiploma" and wants to define how it looks in the holder's wallet
- WHEN the admin creates a design specifying: front background color (#1a365d), text color (#ffffff), university logo, title "University Diploma", displayed fields (studentName, degree, graduationDate); back with additional fields (gpa, honors)
- THEN the design is saved and linked to the schema; all credentials issued with this schema will use this visual representation

#### Scenario: Update credential design colors
- GIVEN a credential design exists for "UniversityDiploma"
- WHEN the admin updates the background color to match new university branding
- THEN the design is updated; newly issued credentials reflect the new design, and existing credentials in wallets update their visual appearance on next sync

#### Scenario: Preview a credential design
- GIVEN an admin is configuring a new credential design
- WHEN they request a preview with sample data
- THEN the system renders a visual preview showing how the credential will appear with the configured layout, colors, images, and sample field values
