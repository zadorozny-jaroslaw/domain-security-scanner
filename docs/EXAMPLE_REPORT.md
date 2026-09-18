# Example report

The repository includes an example report generated against the maintainer-controlled test host:

```text
wordpress01.zadorozny.pl
```

- [Full example PDF](example-report.pdf)
- [Page 1 preview](example-report-page-1.png)

The example demonstrates the color-coded score, priorities, "why it matters" explanations, domain/mail separation, CMS detection, TLS checks, and technical appendix.

## Maintaining the example

Regenerate the example after a user-visible PDF/report-layout change so the public documentation reflects the current reporter behavior. Use only a maintainer-controlled or otherwise explicitly authorized target.

When refreshing the example:

1. run the current release candidate against the authorized example host;
2. replace `docs/example-report.pdf`;
3. replace `docs/example-report-page-1.png` with a preview rendered from page 1 of the same PDF;
4. inspect the files for secrets, customer data, private addresses, or other information that should not be committed;
5. confirm the README links and preview still render correctly.

The findings themselves may change over time as DNS, TLS, CMS versions, and other public configuration change. The example is intended to demonstrate report structure and presentation rather than provide a permanent assessment of the test host.

The report is intentionally included as a realistic example. Do not use third-party/customer reports as public documentation unless you have explicit permission to publish the contained hostnames, addresses, findings, and metadata.
