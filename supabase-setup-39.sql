-- Run ONCE in Supabase: SQL Editor > + New query > paste ALL > Run. Safe to run again.
-- Share links for "My Lists": a member can copy a link to their Wishlist or Favorites.
-- The link opens list.html and (with the Cloudflare Worker) shows a Discord preview image of the list.

create table if not exists public.list_shares(
  code text primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  username text not null,
  kind text not null check (kind in ('wishlist','favorites')),
  items jsonb not null,
  total numeric not null default 0,
  image text,
  updated_at timestamptz not null default now(),
  unique (user_id, kind)
);
alter table public.list_shares enable row level security;
revoke all on public.list_shares from anon, authenticated;   -- nobody reads the table directly, only the functions below

create or replace function public.share_list(p_kind text, p_items jsonb, p_image text) returns text
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
revoke all on function public.share_list(text, jsonb, text) from public, anon;
grant execute on function public.share_list(text, jsonb, text) to authenticated;

-- public: anyone with the link can read the list (but not the owner's id)
create or replace function public.get_list_share(p_code text) returns jsonb
language sql stable security definer set search_path = public as $$
  select jsonb_build_object('username', username, 'kind', kind, 'items', items, 'total', total,
                            'updated', extract(epoch from updated_at)::bigint)
  from public.list_shares where code = lower(btrim(p_code))
$$;
create or replace function public.get_list_image(p_code text) returns text
language sql stable security definer set search_path = public as $$
  select image from public.list_shares where code = lower(btrim(p_code))
$$;
revoke all on function public.get_list_share(text) from public;
revoke all on function public.get_list_image(text) from public;
grant execute on function public.get_list_share(text) to anon, authenticated;
grant execute on function public.get_list_image(text) to anon, authenticated;

notify pgrst, 'reload schema';
