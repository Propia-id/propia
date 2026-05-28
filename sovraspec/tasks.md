# Pending Tasks and Future Improvements

## Credential Issuance
- [ ] Support batch issuance (issue the same credential to multiple holders at once)
- [ ] Deferred credential issuance (issue credentials that require asynchronous approval)
- [ ] Credential refresh/renewal flow (re-issue an updated credential before expiration)

## Credential Verification
- [ ] Cross-device verification (verifier on one device, holder on another without QR)
- [ ] Offline verification (verify credential signatures without network connectivity)
- [ ] Verification templates (reusable presentation request configurations)

## Credential Lifecycle
- [ ] Automatic expiration handling (scheduled job to transition expired credentials)
- [ ] Bulk status change (suspend/revoke multiple credentials at once)
- [ ] Status change notifications to holders (notify when their credential status changes)

## Wallet
- [ ] Cloud backup and recovery of wallet contents
- [ ] Multi-device wallet sync
- [ ] Credential sharing between wallets (delegated presentations)
- [ ] In-wallet credential revocation check scheduling

## Webhook Events
- [ ] Configurable retry policies per workspace (number of attempts, backoff strategy)
- [ ] Event filtering (workspaces subscribe only to specific event types)
- [ ] Dead letter queue for permanently failed deliveries

## Security
- [ ] Key rotation for workspace signing keys
- [ ] Hardware security module (HSM) integration for key storage
- [ ] Audit log export for compliance

## Standards
- [ ] SD-JWT VC issuance and verification (beyond storage)
- [ ] OID4VP Draft 24 alignment
- [ ] DIF Presentation Exchange v3 support
- [ ] Trust framework integration (trust lists, trusted issuer registries)

## Product Experience (section 09)
- [ ] Per-user mode preference that follows the user across workspaces
- [ ] Mode-aware onboarding tour (different paths for Normal vs Developer)
- [ ] Schema templates (start from a pre-filled diploma, ID card, ticket, etc.)
- [ ] Design templates (visual presets per industry) and design duplication
- [ ] Resume issuance wizard from local draft at step 3 (table data)
- [ ] CSV template auto-mapping when column names match schema fields
- [ ] Bulk distribution by email (issue + send invitation in one step)
- [ ] Verification templates (reusable presentation requests) and result export
- [ ] Delivery-log viewer with manual replay of failed webhook deliveries
- [ ] Self-service downgrade flow with confirmation
- [ ] Per-resource usage alerts (email at 80% / 100% of plan limit)
