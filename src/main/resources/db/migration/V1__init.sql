create table if not exists app_user (
	id uuid primary key,
	email text not null unique,
	created_at timestamptz not null default now()
);
