import type { DB } from "./db.ts";
import { randomUUID } from "node:crypto";

export interface App {
  id: string;
  name: string;
  category: string | null;
  vendor: string | null;
  risk: string;
  data_residency: string | null;
  sso_enabled: number;
  approval_required: number;
  upstream_url: string | null;
}

export function registerApp(
  db: DB,
  app: Omit<App, "id"> & { id?: string },
): App {
  const id = app.id ?? randomUUID();
  db.prepare(
    `INSERT INTO apps (id,name,category,vendor,risk,data_residency,sso_enabled,approval_required,upstream_url)
     VALUES (?,?,?,?,?,?,?,?,?)`,
  ).run(
    id,
    app.name,
    app.category ?? null,
    app.vendor ?? null,
    app.risk ?? "medium",
    app.data_residency ?? null,
    app.sso_enabled ?? 1,
    app.approval_required ?? 1,
    app.upstream_url ?? null,
  );
  return getApp(db, id)!;
}

export function getApp(db: DB, id: string): App | undefined {
  return db.prepare(`SELECT * FROM apps WHERE id = ?`).get(id) as
    | App
    | undefined;
}

export function listApps(db: DB): App[] {
  return db.prepare(`SELECT * FROM apps ORDER BY name`).all() as App[];
}

// allowedRegions enforces data-residency: an app is usable only if its
// residency is in the set of regions the deployment permits.
export function residencyAllowed(
  app: App,
  allowedRegions: string[],
): boolean {
  if (!app.data_residency) return true; // unknown residency -> not blocked here
  return allowedRegions.includes(app.data_residency);
}
