import { useMemo } from "react";
import { CartesianGrid, ComposedChart, Legend, Line, ReferenceLine, ResponsiveContainer, Scatter, Tooltip, XAxis, YAxis } from "recharts";
import { linearRegression, regressionLineEnds, type Point } from "../../../analysis/stats";

export type PlotSeries = { name: string; color: string; points: (Point & { messageId?: number })[]; regression?: boolean };
function ChartTooltip({ active, payload }: { active?: boolean; payload?: ReadonlyArray<{ payload: Point & { messageId?: number } }> }) {
  if (!active || !payload?.length) return null;
  const data = payload[0].payload as Point & { messageId?: number };
  return <div className="lab-tooltip">{data.messageId !== undefined && <b>Message #{data.messageId}</b>}<br />x: {data.x}<br />y: {data.y}</div>;
}

export function ScatterWithRegression({ title, subtitle, xLabel, yLabel, series, showRegression = true, referenceY, referenceLabel, referenceDashed = true, referenceY2, referenceLabel2, referenceY2Dashed = true, yDomain }: {
  title: string; subtitle?: string; xLabel: string; yLabel: string; series: PlotSeries[]; showRegression?: boolean; referenceY?: number; referenceLabel?: string; referenceDashed?: boolean; referenceY2?: number; referenceLabel2?: string; referenceY2Dashed?: boolean; yDomain?: [number | string, number | string];
}) {
  const models = useMemo(() => series.map((s) => linearRegression(s.points)), [series]);
  const hasPoints = series.some((item) => item.points.length > 0);
  return <section className="dash-panel lab-chart-panel"><h3>{title}</h3>{subtitle && <p className="dash-note">{subtitle}</p>}
    {!hasPoints ? <p className="dash-empty">No records available for this chart.</p> : <>
      <div className="lab-plot-layout"><div className="lab-y-axis-label">{yLabel}</div><div className="lab-plot-content"><div className="lab-chart"><ResponsiveContainer width="100%" height="100%"><ComposedChart margin={{ top: 16, right: 24, bottom: 16, left: 12 }}>
        <CartesianGrid strokeDasharray="3 3" /><XAxis type="number" dataKey="x" name={xLabel} tick={{ fontSize: 10 }} tickCount={5} minTickGap={28} interval="preserveStartEnd" tickMargin={8} /><YAxis type="number" dataKey="y" name={yLabel} width={76} domain={yDomain} tick={{ fontSize: 10 }} tickMargin={8} />
        <Tooltip content={<ChartTooltip />} /><Legend />
        {referenceY !== undefined && <ReferenceLine y={referenceY} stroke="#596579" strokeDasharray={referenceDashed ? "6 4" : undefined} label={referenceLabel} />}
        {referenceY2 !== undefined && <ReferenceLine y={referenceY2} stroke="#d17b00" strokeDasharray={referenceY2Dashed ? "6 4" : undefined} label={referenceLabel2} />}
        {series.map((item) => <Scatter key={item.name} name={item.name} data={item.points} fill={item.color} />)}
        {showRegression && series.map((item, index) => {
          if (item.regression === false) return null;
          const ends = regressionLineEnds(item.points, models[index]);
          return ends.length ? <Line key={`${item.name}-fit`} name={`${item.name} fit`} data={ends} dataKey="y" dot={false} stroke={item.color} strokeWidth={2} isAnimationActive={false} /> : null;
        })}
      </ComposedChart></ResponsiveContainer></div><div className="lab-x-axis-label">{xLabel}</div></div></div>
      <div className="lab-regression-text">{series.map((item, i) => { const reg = models[i]; return <span key={item.name}>{item.name}: {reg ? `slope ${reg.slope.toPrecision(4)}, intercept ${reg.intercept.toPrecision(4)}, R² ${reg.r2.toFixed(4)}` : "Regression unavailable"}</span>; })}</div>
    </>}
  </section>;
}
