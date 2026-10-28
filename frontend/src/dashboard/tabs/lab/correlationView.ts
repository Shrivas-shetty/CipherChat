import type { ImageLabRecord } from "../../api";

export type CorrelationDirection = "h" | "v" | "d";
export const directionFields = (dir: CorrelationDirection): (keyof ImageLabRecord)[] => {
  const prefix = dir === "h" ? "corr_" : `corr_${dir}_`;
  return (["pt_r", "pt_g", "pt_b", "pt_avg", "ct_r", "ct_g", "ct_b", "ct_avg"] as const).map((suffix) => `${prefix}${suffix}` as keyof ImageLabRecord);
};
export function correlationAverages(records: ImageLabRecord[], dir: CorrelationDirection): (number | null)[] {
  return directionFields(dir).map((field) => {
    const values = records.map((row) => row[field] as number | null).filter((v): v is number => v !== null);
    return values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
  });
}
export function prePhaseRecords(records: ImageLabRecord[], dir: Exclude<CorrelationDirection, "h">): number {
  const fields = directionFields(dir);
  return records.filter((record) => (dir === "v" ? record.height > 1 : record.height > 1 && record.width > 1)
    && fields.every((field) => record[field] === null)).length;
}
