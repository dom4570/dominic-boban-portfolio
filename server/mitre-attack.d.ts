export type MitreTechnique = {
  id: string;
  tactic: string;
  technique: string;
};

export function getMitreTechniqueCatalog(): Promise<MitreTechnique[]>;

export function resolveMitreTechniques(ids: string[]): Promise<MitreTechnique[]>;
