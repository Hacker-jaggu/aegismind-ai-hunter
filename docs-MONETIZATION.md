# Ethical monetization plan

Revenue is not guaranteed. Do not claim guaranteed bug discovery, bounty payouts, or fully automated OWASP Top 10 coverage.

## Practical revenue paths
1. **Paid learning pack:** original Bengali/English installation guides, authorized-lab worksheets, report templates, and sanitized sample reports.
2. **Paid professional support:** scoped installation, configuration, report interpretation, and training. Define deliverables and do not promise bounty acceptance.
3. **Future Pro add-on:** after the core is stable, consider a dashboard, team report history, branded PDF reports, scheduled authorized assessments, and CI integrations. Keep API keys customer-owned; do not collect target credentials by default.
4. **Digital product sales:** bundle the workbook, templates, setup guide, and update access.
5. **Affiliate links:** only for tools genuinely tested; clearly disclose commissions and never let them influence findings.

## Bangladesh payout checks
- Gumroad's official payout guide lists Bangladesh for local BDT bank payouts. It states a USD 100 standard payout threshold; verify current account-specific requirements before relying on this: https://gumroad.com/help/article/13-getting-paid
- Payhip requires a supported payment processor. Check Account > Settings > Payment Details for options available to your country; provider fees may also apply: https://help.payhip.com/article/396-resolve-payment-issues-as-a-seller
- Bangladesh is not currently listed in GitHub Sponsors' supported payout regions. Do not rely on GitHub Sponsors payouts unless the official list changes: https://docs.github.com/en/sponsors/getting-started-with-github-sponsors/about-github-sponsors

## Suggested product ladder
- Free: CLI, sample report, safe-scope checklist.
- Low-cost: Bengali bug-bounty workflow workbook and report templates.
- Mid-tier: setup guide and sanitized walkthrough.
- Higher tier: time-boxed installation/training/support with explicit scope.

## Trust requirements before charging
- Select a license only after verifying ownership and dependency terms.
- Publish a security policy, supported-version policy, coverage matrix, and changelog.
- Add integration tests, reproducible releases, dependency checks, and SBOM.
- Keep AI claims advisory; deterministic evidence controls finding status.
- Never send customer targets, secrets, cookies, response bodies, or private reports to an AI provider without informed consent.
- Add actual store/payment links only after creating and verifying the seller account and payout route.
