-- 코잡스 친바 — 공유 보드 스키마
-- Supabase 대시보드 › SQL Editor 에 통째로 붙여넣고 한 번 실행하세요.
--
-- 설계 요약
--   workspace : 팀(코잡스) 하나당 한 줄. key 는 추측 불가능한 128비트 비밀값이고
--               공유 링크에 들어갑니다. 링크를 아는 사람 = 편집할 수 있는 사람.
--   board     : 워크스페이스 안에서 "한 달에 한 줄". period 는 '2026-09' 형식.
--               locked 로 그 달 편성을 확정(잠금)할 수 있습니다.
--
-- 보안 모델
--   두 테이블 모두 RLS 를 켜고 정책을 하나도 만들지 않습니다 = 클라이언트의
--   테이블 직접 접근은 전면 차단. 아래 security definer 함수로만 읽고 씁니다.
--   함수는 매번 workspace key 를 확인하므로, key 를 모르면 아무것도 못 합니다.
--   (anon key 는 공개 사이트에 노출되지만, 그것만으로는 열람이 불가능합니다.)

create extension if not exists pgcrypto;

-- ---------- 테이블 ----------
create table if not exists public.workspace (
  key        text primary key,
  name       text not null default '코잡스 친바',
  created_at timestamptz not null default now()
);

create table if not exists public.board (
  workspace  text not null references public.workspace(key) on delete cascade,
  period     text not null check (period ~ '^[0-9]{4}-[0-9]{2}$'),
  payload    jsonb not null default '{}'::jsonb,
  locked     boolean not null default false,
  rev        bigint not null default 1,
  updated_at timestamptz not null default now(),
  updated_by text not null default '',
  primary key (workspace, period)
);

-- ---------- 직접 접근 차단 ----------
alter table public.workspace enable row level security;
alter table public.board     enable row level security;
revoke all on public.workspace from anon, authenticated;
revoke all on public.board     from anon, authenticated;

-- ---------- 읽기 ----------
-- 그 워크스페이스에 있는 달 목록 (payload 는 빼고 가볍게)
create or replace function public.board_list(ws text)
returns table (period text, locked boolean, rev bigint, updated_at timestamptz, updated_by text)
language sql security definer set search_path = public as $$
  select b.period, b.locked, b.rev, b.updated_at, b.updated_by
  from board b
  where b.workspace = ws and exists (select 1 from workspace w where w.key = ws)
  order by b.period desc;
$$;

-- 한 달 보드 전체
create or replace function public.board_get(ws text, p text)
returns table (period text, payload jsonb, locked boolean, rev bigint, updated_at timestamptz, updated_by text)
language sql security definer set search_path = public as $$
  select b.period, b.payload, b.locked, b.rev, b.updated_at, b.updated_by
  from board b
  where b.workspace = ws and b.period = p
    and exists (select 1 from workspace w where w.key = ws);
$$;

-- 변경 감지용 초경량 폴링 (payload 를 보내지 않음 → 트래픽 거의 0)
create or replace function public.board_rev(ws text, p text)
returns table (rev bigint, locked boolean, updated_at timestamptz, updated_by text)
language sql security definer set search_path = public as $$
  select b.rev, b.locked, b.updated_at, b.updated_by
  from board b
  where b.workspace = ws and b.period = p
    and exists (select 1 from workspace w where w.key = ws);
$$;

-- ---------- 쓰기 ----------
-- base_rev = 내가 불러온 시점의 rev. 그 사이 남이 저장했으면 conflict 로 거절한다
-- (덮어쓰기 사고 방지). 잠긴 달은 locked 로 거절.
create or replace function public.board_save(ws text, p text, body jsonb, who text, base_rev bigint)
returns table (ok boolean, rev bigint, conflict boolean, locked boolean)
language plpgsql security definer set search_path = public as $$
declare cur record;
begin
  if not exists (select 1 from workspace w where w.key = ws) then
    raise exception 'unknown workspace';
  end if;

  select * into cur from board b where b.workspace = ws and b.period = p;

  if not found then
    insert into board(workspace, period, payload, updated_by) values (ws, p, body, who);
    return query select true, 1::bigint, false, false;
    return;
  end if;

  if cur.locked then
    return query select false, cur.rev, false, true;
    return;
  end if;

  if base_rev is not null and base_rev <> cur.rev then
    return query select false, cur.rev, true, false;
    return;
  end if;

  update board set payload = body, updated_by = who, updated_at = now(), rev = cur.rev + 1
   where workspace = ws and period = p;
  return query select true, cur.rev + 1, false, false;
end; $$;

-- 그 달 확정/해제
create or replace function public.board_lock(ws text, p text, want boolean)
returns boolean
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from workspace w where w.key = ws) then
    raise exception 'unknown workspace';
  end if;
  update board set locked = want, updated_at = now() where workspace = ws and period = p;
  return want;
end; $$;

-- ---------- 권한: 함수 실행만 허용 ----------
revoke all on function public.board_list(text)                               from public;
revoke all on function public.board_get(text,text)                           from public;
revoke all on function public.board_rev(text,text)                           from public;
revoke all on function public.board_save(text,text,jsonb,text,bigint)        from public;
revoke all on function public.board_lock(text,text,boolean)                  from public;

grant execute on function public.board_list(text)                            to anon, authenticated;
grant execute on function public.board_get(text,text)                        to anon, authenticated;
grant execute on function public.board_rev(text,text)                        to anon, authenticated;
grant execute on function public.board_save(text,text,jsonb,text,bigint)     to anon, authenticated;
grant execute on function public.board_lock(text,text,boolean)               to anon, authenticated;
i 