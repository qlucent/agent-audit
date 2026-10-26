import type { Check } from '../types.ts';
import { moneyNoApproval, moneyNoCap, purchaseWithoutConsent } from './money.ts';
import { unscopedRecordAccess } from './records.ts';
import { identityAdminAction } from './identity.ts';
import { destructiveNoApproval, unclassifiedAction } from './destructive.ts';

export const checks: Record<string, Check> = {
  'money-no-cap': moneyNoCap,
  'money-no-approval': moneyNoApproval,
  'purchase-without-consent': purchaseWithoutConsent,
  'unscoped-record-access': unscopedRecordAccess,
  'identity-admin-action': identityAdminAction,
  'destructive-no-approval': destructiveNoApproval,
  'unclassified-action': unclassifiedAction,
};
