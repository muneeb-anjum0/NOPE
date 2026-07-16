"use client";

import { useEffect } from "react";

const SKIP_TAGS = new Set(["SCRIPT", "STYLE", "TEXTAREA", "INPUT", "SELECT", "OPTION", "CODE", "PRE"]);
const TOKEN_PATTERN = /(NOPE\.|\d+|[/%])/g;

function decorateTextNode(node: Text) {
  const text = node.nodeValue ?? "";
  if (!TOKEN_PATTERN.test(text)) return;
  TOKEN_PATTERN.lastIndex = 0;

  const fragment = document.createDocumentFragment();
  let cursor = 0;

  for (const match of text.matchAll(TOKEN_PATTERN)) {
    const token = match[0];
    const index = match.index ?? 0;
    if (index > cursor) fragment.append(text.slice(cursor, index));

    if (token === "NOPE.") {
      fragment.append("NOPE");
      const dot = document.createElement("span");
      dot.className = "brand-hot";
      dot.textContent = ".";
      fragment.append(dot);
    } else {
      const accent = document.createElement("span");
      accent.className = "brand-hot";
      accent.textContent = token;
      fragment.append(accent);
    }

    cursor = index + token.length;
  }

  if (cursor < text.length) fragment.append(text.slice(cursor));
  node.parentNode?.replaceChild(fragment, node);
}

function decorate(root: ParentNode) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent || parent.closest("[data-brand-skip], .brand-hot, .brand-i")) return NodeFilter.FILTER_REJECT;
      if (SKIP_TAGS.has(parent.tagName)) return NodeFilter.FILTER_REJECT;
      if (!node.nodeValue?.trim()) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  const nodes: Text[] = [];
  while (walker.nextNode()) nodes.push(walker.currentNode as Text);
  nodes.forEach(decorateTextNode);
}

export function BrandTextEffects() {
  useEffect(() => {
    const root = document.body;
    decorate(root);
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.TEXT_NODE) {
            decorateTextNode(node as Text);
          } else if (node.nodeType === Node.ELEMENT_NODE) {
            decorate(node as Element);
          }
        });
      }
    });
    observer.observe(root, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, []);

  return null;
}
