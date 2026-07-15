alter table invoices enable row level security;
create policy "phase12 unsafe read all" on invoices for select using (true);
