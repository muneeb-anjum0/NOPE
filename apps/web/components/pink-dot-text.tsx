export function PinkDotText({ text }: Readonly<{ text: string }>) {
  return (
    <>
      {text.split(".").map((part, index, parts) => (
        <span key={`${part}-${index}`}>
          {part}
          {index < parts.length - 1 ? <span className="pink-dot">.</span> : null}
        </span>
      ))}
    </>
  );
}
