export const IRS_EXPENSE_THRESHOLDS = {
  rentExpense: 1500,
  medicalExpense: 200,
  utilitiesExpense: 350,
  homeMaintenanceExpense: 100,
  carInsuranceExpense: 150,
  gasExpense: 250,
} as const;

const DOCUMENT_REQUIREMENTS: Record<keyof typeof IRS_EXPENSE_THRESHOLDS, string> = {
  rentExpense: 'Proof of Rent/Mortgage (e.g., Lease Agreement)',
  medicalExpense: 'Proof of Out-of-Pocket Medical Expenses',
  utilitiesExpense: 'Proof of Utility Bills',
  homeMaintenanceExpense: 'Proof of Home Maintenance Costs',
  carInsuranceExpense: 'Proof of Auto Insurance Premium',
  gasExpense: 'Proof of Fuel/Commuting Costs',
};

export type IrsExpenseKey = keyof typeof IRS_EXPENSE_THRESHOLDS;

export function evaluateExpenses(expenses: Record<string, number>): string[] {
  return (Object.keys(IRS_EXPENSE_THRESHOLDS) as IrsExpenseKey[]).flatMap((key) => {
    const amount = expenses[key] ?? 0;
    return amount > IRS_EXPENSE_THRESHOLDS[key] ? [DOCUMENT_REQUIREMENTS[key]] : [];
  });
}
