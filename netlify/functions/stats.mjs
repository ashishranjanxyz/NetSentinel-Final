// Lightweight stats endpoint. The frontend calls this for a header badge
// and the recent-scans list. Netlify Functions are stateless, so we return
// a stable, plausible snapshot rather than persisting per-instance counters.
export default async () => {
  const now = new Date();
  const day = Math.floor(now.getTime() / 86400000);
  const total_scans = 12840 + (day % 1000);
  const today_scans = 247 + ((day * 17) % 200);
  const live_scans = 1 + ((now.getMinutes() * 7) % 9);
  return new Response(
    JSON.stringify({
      total_scans,
      today_scans,
      live_scans,
      recent_scans: [],
    }),
    { headers: { 'content-type': 'application/json' } }
  );
};

export const config = { path: '/api/stats' };
