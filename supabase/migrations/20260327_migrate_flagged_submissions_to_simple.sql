-- One-time migration: convert public.flagged_contract_submissions
-- from legacy form fields to simplified vulnerability submission fields.
-- Safe to run multiple times.

begin;

-- 0) Drop legacy status constraint first.
-- Existing rows may already contain 'pending_review', which is invalid under
-- the legacy constraint ('pending', 'under_review', ...). Any UPDATE would fail
-- unless we remove the old constraint before backfill/normalization.
alter table if exists public.flagged_contract_submissions
  drop constraint if exists chk_submission_status;

-- 1) Ensure simplified columns exist.
alter table if exists public.flagged_contract_submissions
    add column if not exists description text,
    add column if not exists example_vulnerable text,
    add column if not exists attack_steps jsonb not null default '[]'::jsonb;

-- 2) Backfill simplified fields from legacy columns when needed.
update public.flagged_contract_submissions
set description = coalesce(description, supporting_evidence)
where description is null
  and exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'flagged_contract_submissions'
      and column_name = 'supporting_evidence'
  );

update public.flagged_contract_submissions
set example_vulnerable = coalesce(example_vulnerable, source_code)
where example_vulnerable is null
  and exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'flagged_contract_submissions'
      and column_name = 'source_code'
  );

update public.flagged_contract_submissions
set attack_steps = case
    when attack_steps = '[]'::jsonb then coalesce(suspected_vulnerability, '[]'::jsonb)
    else attack_steps
end
where exists (
    select 1
    from information_schema.columns
    where table_schema = 'public'
      and table_name = 'flagged_contract_submissions'
      and column_name = 'suspected_vulnerability'
  );

-- 3) Normalize legacy statuses to new status vocabulary.
update public.flagged_contract_submissions
set status = 'pending_review'
where status = 'pending';

update public.flagged_contract_submissions
set status = 'pending_review'
where status is null;

-- 4) Fill any remaining null required values before applying NOT NULL.
update public.flagged_contract_submissions
set description = coalesce(description, '')
where description is null;

update public.flagged_contract_submissions
set example_vulnerable = coalesce(example_vulnerable, '')
where example_vulnerable is null;

update public.flagged_contract_submissions
set attack_steps = coalesce(attack_steps, '[]'::jsonb)
where attack_steps is null;

-- 5) Add status check constraint for new status set.
alter table if exists public.flagged_contract_submissions
    add constraint chk_submission_status
    check (status in ('pending_review', 'under_review', 'approved', 'rejected', 'needs_info'));

-- 6) Enforce simplified required columns.
alter table if exists public.flagged_contract_submissions
    alter column description set not null,
    alter column example_vulnerable set not null,
    alter column attack_steps set not null,
    alter column status set default 'pending_review';

-- 7) Drop legacy columns if they still exist.
alter table if exists public.flagged_contract_submissions
    drop column if exists reporter_name,
    drop column if exists reporter_email,
    drop column if exists contract_name,
    drop column if exists contract_address,
    drop column if exists chain_name,
    drop column if exists tx_hash,
    drop column if exists severity_claim,
    drop column if exists suspected_vulnerability,
    drop column if exists supporting_evidence,
    drop column if exists suggested_fix,
    drop column if exists source_code;

commit;
