export type Plan = {
  id: "small" | "medium" | "large";
  name: string;
  maxAssets: number;
  maxUsers: number;
  scansPerMonth: number;
  tokensPerMonth: number;
  apiRequestsPerMonth: number;
  support: string;
};

export const plans: Plan[] = [
  {
    id: "small",
    name: "Pequeña",
    maxAssets: 50,
    maxUsers: 10,
    scansPerMonth: 4,
    tokensPerMonth: 100_000,
    apiRequestsPerMonth: 2_500,
    support: "Correo electrónico",
  },
  {
    id: "medium",
    name: "Mediana",
    maxAssets: 500,
    maxUsers: 100,
    scansPerMonth: 30,
    tokensPerMonth: 1_000_000,
    apiRequestsPerMonth: 25_000,
    support: "Prioritario",
  },
  {
    id: "large",
    name: "Grande",
    maxAssets: 5_000,
    maxUsers: 1_000,
    scansPerMonth: 100,
    tokensPerMonth: 10_000_000,
    apiRequestsPerMonth: 250_000,
    support: "Dedicado",
  },
];

export function getPlan(planId: string): Plan | undefined {
  return plans.find((plan) => plan.id === planId);
}
