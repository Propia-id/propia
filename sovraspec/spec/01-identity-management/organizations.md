# Organizations

## Purpose

Organizations represent the top-level entities on the platform. They group users and workspaces. Each organization has its own branding (name, logo, website) and can contain multiple users and multiple workspaces (issuers).

## Requirements

### Requirement: Organization lifecycle management

The system SHALL allow creation, update, and deactivation of organizations with branding attributes including name, logo, and website.

#### Scenario: Create an organization
- GIVEN an authenticated user who wants to set up their organization on the platform
- WHEN they provide the organization name, logo URL, and website
- THEN a new organization is created and the user is associated as its owner/admin

#### Scenario: Update organization branding
- GIVEN an organization admin who needs to update the organization's public information
- WHEN they update the organization's name, logo, or website
- THEN the changes are saved and reflected wherever the organization's branding is displayed (e.g., credential designs, wallet entity listings)

### Requirement: Organization member visibility

The system SHALL provide organization admins with a complete view of all users and their roles within the organization.

#### Scenario: List organization members
- GIVEN an organization admin who wants to see all users in their organization
- WHEN they request the list of organization users
- THEN the system returns all users associated with that organization, including their roles and status
