import type { Check } from '../types.ts';
import { moneyNoApproval, moneyNoCap, purchaseWithoutConsent } from './money.ts';
import { unscopedRecordAccess } from './records.ts';
import { identityAdminAction } from './identity.ts';
import { destructiveNoApproval, unclassifiedAction } from './destructive.ts';
import { externalSendSensitive } from './exfil.ts';
import { codeExecAction } from './code.ts';
import { bulkExport } from './bulk.ts';
import { broadOauthScope } from './oauth.ts';
import { iamWildcardCheck } from './iam.ts';
import { noManifest } from './manifest-presence.ts';

export const checks: Record<string, Check> = {
  'money-no-cap': moneyNoCap,
  'money-no-approval': moneyNoApproval,
  'purchase-without-consent': purchaseWithoutConsent,
  'unscoped-record-access': unscopedRecordAccess,
  'identity-admin-action': identityAdminAction,
  'destructive-no-approval': destructiveNoApproval,
  'unclassified-action': unclassifiedAction,
  'external-send-sensitive': externalSendSensitive,
  'code-exec-action': codeExecAction,
  'bulk-export': bulkExport,
  'broad-oauth-scope': broadOauthScope,
  'iam-wildcard': iamWildcardCheck,
  'no-manifest': noManifest,
};
