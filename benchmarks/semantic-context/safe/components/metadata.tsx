"use client";
export const metadata = { site: process.env.NEXT_PUBLIC_SITE_URL, jsonLd: "https://site.example", robots: "/robots.txt", sitemap: "/sitemap.xml" };
export async function previewClient() { return fetch("/api/preview"); }
