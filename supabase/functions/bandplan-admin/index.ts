import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": Deno.env.get("ADMIN_CORS_ORIGIN") || "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json; charset=utf-8",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: corsHeaders });

const requiredEnv = (key: string) => {
  const value = Deno.env.get(key);
  if (!value) throw new Error(`Missing Edge Function secret: ${key}`);
  return value;
};

type TableInfo = {
  name: string;
  columns: { name: string; type: string; nullable: boolean; default: string | null; ordinal: number }[];
  primaryKey: string[];
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  try {
    const url = requiredEnv("SUPABASE_URL");
    const anonKey = requiredEnv("SUPABASE_ANON_KEY");
    const serviceKey = requiredEnv("SUPABASE_SERVICE_ROLE_KEY");
    const authorization = req.headers.get("Authorization");
    if (!authorization?.startsWith("Bearer ")) return json({ error: "Требуется вход администратора." }, 401);

    // WHY: validate the JWT with Supabase Auth before using any privileged client.
    const authClient = createClient(url, anonKey, {
      global: { headers: { Authorization: authorization } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: authData, error: authError } = await authClient.auth.getUser();
    if (authError || !authData.user?.email) return json({ error: "Недействительная сессия. Войдите снова." }, 401);

    const allowlist = (Deno.env.get("ADMIN_EMAILS") || "")
      .split(",").map((v) => v.trim().toLowerCase()).filter(Boolean);
    if (!allowlist.includes(authData.user.email.toLowerCase())) {
      return json({ error: "У этого аккаунта нет прав администратора. Добавьте email в ADMIN_EMAILS." }, 403);
    }

    const db = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
    const body = await req.json().catch(() => ({}));
    const action = String(body.action || "");
    const { data: info, error: infoError } = await db.rpc("bandplan_admin_table_info");
    if (infoError) throw new Error("Не удалось получить схему public. Примените миграцию панели: " + infoError.message);
    const tables = (info || []) as TableInfo[];
    const tableFor = (name: unknown): TableInfo => {
      const found = tables.find((t) => t.name === name);
      if (!found) throw new Error("Таблица не разрешена или не найдена: " + String(name));
      return found;
    };
    const keyFor = (table: TableInfo, row: Record<string, unknown>) => {
      if (!table.primaryKey?.length) throw new Error("У таблицы нет первичного ключа; безопасное редактирование отключено.");
      const key: Record<string, unknown> = {};
      for (const col of table.primaryKey) {
        if (row[col] === undefined || row[col] === null) throw new Error("Не найден ключ записи: " + col);
        key[col] = row[col];
      }
      return key;
    };
    const matchKey = (query: any, key: Record<string, unknown>) => {
      let q = query;
      for (const [column, value] of Object.entries(key)) q = q.eq(column, value);
      return q;
    };

    if (action === "tables" || action === "overview") {
      const summaries = await Promise.all(tables.map(async (table) => {
        const { count, error } = await db.from(table.name).select("*", { count: "exact", head: true });
        return { name: table.name, rowCount: error ? null : count, columns: table.columns, primaryKey: table.primaryKey };
      }));
      if (action === "tables") return json({ tables: summaries });
      const countRows = async (names: string[]) => {
        const target = summaries.find((t) => names.includes(t.name));
        return target?.rowCount ?? 0;
      };
      const { count: recycleCount } = await db.from("bandplan_admin_recycle_bin").select("*", { count: "exact", head: true }).is("restored_at", null);
      return json({
        profiles: await countRows(["profiles", "bandplan_accounts", "accounts"]),
        groups: await countRows(["groups", "bandplan_groups"]),
        songs: await countRows(["songs", "bandplan_songs"]),
        events: await countRows(["events", "bandplan_events"]),
        tableCount: tables.length,
        tables: summaries,
        recycleCount: recycleCount ?? 0,
      });
    }

    if (action === "auth_users") {
      const page = Math.max(1, Number(body.page) || 1);
      const { data, error } = await db.auth.admin.listUsers({ page, perPage: 100 });
      if (error) throw error;
      return json({ users: data.users.map((u) => ({
        id: u.id, email: u.email, created_at: u.created_at, last_sign_in_at: u.last_sign_in_at,
        email_confirmed_at: u.email_confirmed_at, banned_until: u.banned_until,
      })) });
    }

    if (action === "rows") {
      const table = tableFor(body.table);
      const limit = Math.min(500, Math.max(1, Number(body.limit) || 100));
      const { data, error } = await db.from(table.name).select("*").limit(limit);
      if (error) throw error;
      return json({ rows: data || [], columns: table.columns.map((c) => c.name), primaryKey: table.primaryKey, limit });
    }

    if (action === "insert") {
      const table = tableFor(body.table);
      const row = body.row;
      if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("Некорректные данные записи.");
      const allowed = new Set(table.columns.map((c) => c.name));
      const defaults = new Set(table.columns.filter((col) => col.default).map((col) => col.name));
      const clean = Object.fromEntries(Object.entries(row).filter(([key, value]) => allowed.has(key) && !(value === null && defaults.has(key))));
      const { data, error } = await db.from(table.name).insert(clean).select("*").single();
      if (error) throw error;
      return json({ row: data });
    }

    if (action === "update") {
      const table = tableFor(body.table);
      const row = body.row;
      const original = body.primaryKey;
      if (!row || typeof row !== "object" || !original || typeof original !== "object") throw new Error("Не хватает данных записи.");
      const key = keyFor(table, original);
      const allowed = new Set(table.columns.map((c) => c.name));
      const clean = Object.fromEntries(Object.entries(row).filter(([k]) => allowed.has(k) && !table.primaryKey.includes(k)));
      const { data, error } = await matchKey(db.from(table.name).update(clean), key).select("*").single();
      if (error) throw error;
      return json({ row: data });
    }

    if (action === "soft_delete") {
      const table = tableFor(body.table);
      const row = body.row;
      if (!row || typeof row !== "object") throw new Error("Не указана запись.");
      const key = keyFor(table, row);
      // WHY: snapshot first, then delete; if the delete fails the recycle-bin row is rolled back.
      const { data: target, error: snapshotError } = await matchKey(db.from(table.name).select("*"), key).maybeSingle();
      if (snapshotError) throw snapshotError;
      if (!target) throw new Error("Запись не найдена; обновите таблицу.");
      const { data: archived, error: archiveError } = await db.from("bandplan_admin_recycle_bin").insert({
        table_name: table.name, primary_key: key, row_data: target, deleted_by: authData.user.email,
      }).select("id").single();
      if (archiveError) throw archiveError;
      const { error: deleteError } = await matchKey(db.from(table.name).delete(), key);
      if (deleteError) {
        await db.from("bandplan_admin_recycle_bin").delete().eq("id", archived.id);
        throw new Error("Удаление отменено: " + deleteError.message);
      }
      return json({ ok: true, recycleId: archived.id });
    }

    if (action === "recycle_bin") {
      const { data, error } = await db.from("bandplan_admin_recycle_bin")
        .select("id,table_name,primary_key,deleted_at,deleted_by,restored_at,restored_by")
        .order("deleted_at", { ascending: false }).limit(500);
      if (error) throw error;
      return json({ items: data || [] });
    }

    if (action === "restore") {
      const { data: item, error: findError } = await db.from("bandplan_admin_recycle_bin")
        .select("*").eq("id", body.id).is("restored_at", null).single();
      if (findError) throw findError;
      const table = tableFor(item.table_name);
      const { data: restored, error: restoreError } = await db.from(table.name).insert(item.row_data).select("*").single();
      if (restoreError) throw new Error("Не удалось восстановить запись. Возможно, её ключ уже занят или отсутствует связанная запись: " + restoreError.message);
      const { error: markError } = await db.from("bandplan_admin_recycle_bin").update({
        restored_at: new Date().toISOString(), restored_by: authData.user.email,
      }).eq("id", item.id);
      if (markError) throw markError;
      return json({ ok: true, row: restored });
    }

    return json({ error: "Неизвестное действие: " + action }, 400);
  } catch (error) {
    console.error("bandplan-admin error", error);
    return json({ error: error instanceof Error ? error.message : "Внутренняя ошибка панели." }, 400);
  }
});
