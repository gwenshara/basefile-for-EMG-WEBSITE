-- Run ONCE in Supabase: SQL Editor > + New query > paste ALL > Run. Safe to run again.
-- "Copy link" now makes a NEW link every time and deletes the previous one for that list,
-- so Discord (which remembers old links) always shows the fresh preview.
-- Needs supabase-setup-39.sql run first.

drop function if exists public.share_list(text, jsonb, text);

create or replace function public.share_list(p_kind text, p_items jsonb, p_image text, p_fresh boolean default false) returns text
language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); un text; c text; tot numeric;
begin
  if me is null then raise exception 'Log in first.'; end if;
  if p_kind not in ('wishlist','favorites') then raise exception 'Unknown list.'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) not between 1 and 400 then raise exception 'Your list is empty.'; end if;
  if p_image is null or left(p_image, 23) <> 'data:image/jpeg;base64,' or char_length(p_image) > 900000 then raise exception 'The preview image is not valid.'; end if;
  select username into un from public.profiles where id = me;
  if un is null then raise exception 'Profile not found.'; end if;
  select coalesce(sum(coalesce((e->>'v')::numeric, 0) * greatest(coalesce((e->>'q')::numeric, 1), 1)), 0) into tot from jsonb_array_elements(p_items) e;
  if p_fresh then
    delete from public.list_shares where user_id = me and kind = p_kind;   -- the old link stops working
  end if;
  select code into c from public.list_shares where user_id = me and kind = p_kind;
  if c is null then
    loop
      c := substr(md5(random()::text || clock_timestamp()::text || me::text), 1, 8);
      exit when not exists (select 1 from public.list_shares where code = c);
    end loop;
  end if;
  insert into public.list_shares(code, user_id, username, kind, items, total, image, updated_at)
    values (c, me, un, p_kind, p_items, tot, p_image, now())
  on conflict (user_id, kind) do update
    set items = excluded.items, total = excluded.total, image = excluded.image, username = excluded.username, updated_at = now();
  return c;
end $$;
revoke all on function public.share_list(text, jsonb, text, boolean) from public, anon;
grant execute on function public.share_list(text, jsonb, text, boolean) to authenticated;

notify pgrst, 'reload schema';
