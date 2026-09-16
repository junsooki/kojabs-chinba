-- 딱 한 번만 실행하세요. 출력되는 key 가 공유 링크에 들어갈 비밀값입니다.
-- 이 값을 아는 사람은 누구나 편집할 수 있으니, 팀 채팅 등 닫힌 곳에만 공유하세요.
-- 잃어버리면 아래 select 로 다시 확인할 수 있습니다.
insert into public.workspace (key, name)
values (encode(gen_random_bytes(16), 'hex'), '코잡스 친바')
returning key;

-- 나중에 다시 확인할 때:
--   select key, name, created_at from public.workspace;
