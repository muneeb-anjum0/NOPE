"use client";

import { useEffect, useState } from "react";

type ConnectorPath = {
  paths: string[];
  width: number;
  height: number;
};

const anchorPairs = [
  [".map-node-entry .attack-anchor-bottom.is-connected", ".map-node-db .attack-anchor-left.is-connected"],
  [".map-node-file .attack-anchor-bottom.is-connected", ".map-node-risk .attack-anchor-right.is-connected"],
] as const;

export default function AttackMapConnector() {
  const [connector, setConnector] = useState<ConnectorPath | null>(null);

  useEffect(() => {
    const map = document.querySelector<HTMLElement>(".landing-map");
    const anchors = anchorPairs.map(([startSelector, endSelector]) => ({
      start: document.querySelector<HTMLElement>(startSelector),
      end: document.querySelector<HTMLElement>(endSelector),
    }));

    if (!map || anchors.some(({ start, end }) => !start || !end)) return undefined;

    let frame = 0;

    const updatePath = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const mapRect = map.getBoundingClientRect();
        const paths = anchors.map(({ start, end }) => {
          const startRect = start!.getBoundingClientRect();
          const endRect = end!.getBoundingClientRect();
          const startX = startRect.left + startRect.width / 2 - mapRect.left;
          const startY = startRect.top + startRect.height / 2 - mapRect.top;
          const endX = endRect.left + endRect.width / 2 - mapRect.left;
          const endY = endRect.top + endRect.height / 2 - mapRect.top;

          return `M ${startX} ${startY} V ${endY} H ${endX}`;
        });

        setConnector({ paths, width: mapRect.width, height: mapRect.height });
      });
    };

    updatePath();

    const observer = new ResizeObserver(updatePath);
    observer.observe(map);
    anchors.forEach(({ start, end }) => {
      observer.observe(start!);
      observer.observe(end!);
    });
    window.addEventListener("resize", updatePath);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener("resize", updatePath);
    };
  }, []);

  if (!connector) return null;

  return (
    <svg className="map-live-connector" width={connector.width} height={connector.height} viewBox={`0 0 ${connector.width} ${connector.height}`} aria-hidden="true">
      {connector.paths.map((path) => (
        <path d={path} key={path} />
      ))}
    </svg>
  );
}
