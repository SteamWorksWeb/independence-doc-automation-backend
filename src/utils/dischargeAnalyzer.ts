import type { DischargeSnapshot } from '@prisma/client';

export type DischargeAnalysisStatus =
  | 'HIGH_PROBABILITY'
  | 'BORDERLINE'
  | 'LOW_PROBABILITY'
  | 'PENDING';

export interface DischargeAnalysisResult {
  isDischargeable: boolean;
  status: string;
}

function money(value: number | null | undefined): number {
  return Number.isFinite(value) ? value ?? 0 : 0;
}

export function calculateDischargeProbability(
  snapshot: DischargeSnapshot,
): DischargeAnalysisResult {
  const totalIncome =
    money(snapshot.monthlyTakeHomePay) +
    money(snapshot.additionalIncome);

  const totalExpenses =
    money(snapshot.rentExpense) +
    money(snapshot.medicalExpense) +
    money(snapshot.utilitiesExpense) +
    money(snapshot.homeMaintenanceExpense) +
    money(snapshot.carInsuranceExpense) +
    money(snapshot.gasExpense) +
    money(snapshot.dependentCareExpenses);

  const disposableIncome = totalIncome - totalExpenses;
  const passProng1 = disposableIncome <= 100;

  const passProng2 =
    Boolean(snapshot.is65OrOlder) ||
    Boolean(snapshot.hasDisability) ||
    Boolean(snapshot.unemployed5PlusYears) ||
    Boolean(snapshot.schoolClosed);

  const passProng3 =
    Boolean(snapshot.appliedForIDR) ||
    Boolean(snapshot.madePriorPayments) ||
    Boolean(snapshot.contactedServicer);

  if (passProng1 && passProng2 && passProng3) {
    return { isDischargeable: true, status: 'HIGH_PROBABILITY' };
  }

  if (passProng1 && passProng3 && !passProng2) {
    return { isDischargeable: false, status: 'BORDERLINE' };
  }

  return { isDischargeable: false, status: 'LOW_PROBABILITY' };
}
