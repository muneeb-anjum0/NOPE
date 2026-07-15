export function Tracker() {
  const script = document.createElement("script");
  script.src = "https://www.googletagmanager.com/gtag/js?id=G-TRACKER";
  document.head.appendChild(script);
  return null;
}
