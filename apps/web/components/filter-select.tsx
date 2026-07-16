"use client";

import { useRef, useState } from "react";

type Option = {
  label: string;
  value: string;
};

export function FilterSelect({
  name,
  label,
  options,
  defaultValue = "",
}: Readonly<{
  name: string;
  label: string;
  options: Option[];
  defaultValue?: string;
}>) {
  const [value, setValue] = useState(defaultValue);
  const detailsRef = useRef<HTMLDetailsElement | null>(null);
  const selected = options.find((option) => option.value === value)?.label ?? label;

  return (
    <details className="filter-menu" ref={detailsRef}>
      <summary>
        <span>{selected}</span>
      </summary>
      <input name={name} type="hidden" value={value} />
      <div className="filter-menu-list">
        <button
          className={value === "" ? "selected" : ""}
          type="button"
          onClick={() => {
            setValue("");
            if (detailsRef.current) detailsRef.current.open = false;
          }}
        >
          {label}
        </button>
        {options.map((option) => (
          <button
            className={value === option.value ? "selected" : ""}
            key={option.value}
            type="button"
            onClick={() => {
              setValue(option.value);
              if (detailsRef.current) detailsRef.current.open = false;
            }}
          >
            {option.label}
          </button>
        ))}
      </div>
    </details>
  );
}
