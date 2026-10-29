-- BandPlan admin console support.
-- WHY: preserve full row JSON before deleting so a user can restore records without editing SQL.
create table if not exists public.bandplan_admin_recycle_bin (
  id uuid primary key default gen_random_uuid(),
  table_name text not null,
  primary_key jsonb not null,
  row_data jsonb not null,
  deleted_at timestamptz not null default now(),
  deleted_by text not null,
  restored_at timestamptz,
  restored_by text
);

create index if not exists bandplan_admin_recycle_bin_deleted_at_idx
  on public.bandplan_admin_recycle_bin (deleted_at desc);
create index if not exists bandplan_admin_recycle_bin_table_name_idx
  on public.bandplan_admin_recycle_bin (table_name);

alter table public.bandplan_admin_recycle_bin enable row level security;
-- Deliberately do not add anon/authenticated policies. The Edge Function uses service_role
-- after checking the authenticated user's email against ADMIN_EMAILS.

create or replace function public.bandplan_admin_table_info()
returns jsonb
language sql
security definer
set search_path = pg_catalog, public
as $$
  select coalesce(jsonb_agg(
    jsonb_build_object(
      'name', t.table_name,
      'columns', coalesce((
        select jsonb_agg(jsonb_build_object(
          'name', c.column_name,
          'type', c.data_type,
          'nullable', c.is_nullable = 'YES',
          'default', c.column_default,
          'ordinal', c.ordinal_position
        ) order by c.ordinal_position)
        from information_schema.columns c
        where c.table_schema = 'public' and c.table_name = t.table_name
      ), '[]'::jsonb),
      'primaryKey', coalesce((
        select jsonb_agg(kcu.column_name order by kcu.ordinal_position)
        from information_schema.table_constraints tc
        join information_schema.key_column_usage kcu
          on tc.constraint_name = kcu.constraint_name
          and tc.constraint_schema = kcu.constraint_schema
        where tc.table_schema = 'public'
          and tc.table_name = t.table_name
          and tc.constraint_type = 'PRIMARY KEY'
      ), '[]'::jsonb)
    ) order by t.table_name
  ), '[]'::jsonb)
  from information_schema.tables t
  where t.table_schema = 'public'
    and t.table_type = 'BASE TABLE'
    and t.table_name <> 'bandplan_admin_recycle_bin';
$$;

revoke all on function public.bandplan_admin_table_info() from public, anon, authenticated;
grant execute on function public.bandplan_admin_table_info() to service_role;
grant select, insert, update, delete on public.bandplan_admin_recycle_bin to service_role;
