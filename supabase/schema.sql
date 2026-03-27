-- Supabase schema for shared smart-contract datasets and user submissions.

create extension if not exists pgcrypto;

create table if not exists public.contracts (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    source_code text not null,
    labels jsonb not null default '[]'::jsonb,
    source text not null,
    compiler_version text,
    split text,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_contracts_source on public.contracts(source);
create index if not exists idx_contracts_name on public.contracts(name);

create table if not exists public.vulnerability_types (
    name text primary key,
    description text not null,
    swc_id text,
    severity_default text not null default 'medium',
    example_vulnerable text not null default '',
    example_fixed text not null default '',
    detection_keywords jsonb not null default '[]'::jsonb,
    cwe_id text,
    updated_at timestamptz not null default now()
);

create table if not exists public.flagged_contract_submissions (
    id uuid primary key default gen_random_uuid(),
    reporter_name text not null,
    reporter_email text not null,
    contract_name text not null,
    contract_address text,
    chain_name text,
    tx_hash text,
    severity_claim text not null,
    suspected_vulnerability jsonb not null default '[]'::jsonb,
    supporting_evidence text not null,
    suggested_fix text,
    source_code text not null,
    status text not null default 'pending',
    reviewer_notes text,
    reviewed_at timestamptz,
    created_at timestamptz not null default now(),
    constraint chk_submission_status
        check (status in ('pending', 'under_review', 'approved', 'rejected', 'needs_info'))
);

create index if not exists idx_flagged_status on public.flagged_contract_submissions(status);
create index if not exists idx_flagged_created_at on public.flagged_contract_submissions(created_at desc);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

drop trigger if exists trg_contracts_updated_at on public.contracts;
create trigger trg_contracts_updated_at
before update on public.contracts
for each row execute function public.set_updated_at();

alter table public.contracts enable row level security;
alter table public.flagged_contract_submissions enable row level security;
alter table public.vulnerability_types enable row level security;

-- Public read for shared dataset
drop policy if exists contracts_read_all on public.contracts;
create policy contracts_read_all
on public.contracts
for select
to anon, authenticated
using (true);

-- Authenticated users can insert/update shared contracts (for controlled ingestion tools)
drop policy if exists contracts_write_authenticated on public.contracts;
create policy contracts_write_authenticated
on public.contracts
for all
to authenticated
using (true)
with check (true);

-- Public read for shared vulnerability catalog
drop policy if exists vulnerabilities_read_all on public.vulnerability_types;
create policy vulnerabilities_read_all
on public.vulnerability_types
for select
to anon, authenticated
using (true);

-- Authenticated users can maintain vulnerability catalog
drop policy if exists vulnerabilities_write_authenticated on public.vulnerability_types;
create policy vulnerabilities_write_authenticated
on public.vulnerability_types
for all
to authenticated
using (true)
with check (true);

-- Authenticated users submit vulnerable contract flags
drop policy if exists flagged_insert_authenticated on public.flagged_contract_submissions;
create policy flagged_insert_authenticated
on public.flagged_contract_submissions
for insert
to authenticated
with check (true);

-- Authenticated users can read pending queue (review dashboards)
drop policy if exists flagged_read_authenticated on public.flagged_contract_submissions;
create policy flagged_read_authenticated
on public.flagged_contract_submissions
for select
to authenticated
using (true);

-- Optional: allow reviewers to update statuses using authenticated role.
drop policy if exists flagged_update_authenticated on public.flagged_contract_submissions;
create policy flagged_update_authenticated
on public.flagged_contract_submissions
for update
to authenticated
using (true)
with check (true);
