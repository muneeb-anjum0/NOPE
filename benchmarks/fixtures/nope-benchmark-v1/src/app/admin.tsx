export function AdminOnly() {
  const isAdmin = localStorage.getItem("isAdmin");
  if (!isAdmin) return null;
  return <button>Delete customer</button>;
}
