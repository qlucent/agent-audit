/** Named TS checks a rule may reference with `check:`. Later tasks add entries. */
export const KNOWN_CHECKS: string[] = [
  'money-no-cap', 'money-no-approval', 'purchase-without-consent', 'unscoped-record-access',
  'identity-admin-action', 'destructive-no-approval', 'unclassified-action',
  'external-send-sensitive', 'code-exec-action', 'bulk-export', 'broad-oauth-scope', 'iam-wildcard', 'no-manifest',
];
