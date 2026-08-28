import type { MetadataRoute } from "next";

import { APP_URL } from "@/lib/constants";

const SITE_UPDATED = "2026-08-28";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    { url: APP_URL, lastModified: SITE_UPDATED, changeFrequency: "monthly", priority: 1 },
    {
      url: `${APP_URL}/indirect-prompt-injection`,
      lastModified: SITE_UPDATED,
      changeFrequency: "monthly",
      priority: 0.8,
    },
    {
      url: `${APP_URL}/blocked`,
      lastModified: SITE_UPDATED,
      changeFrequency: "monthly",
      priority: 0.6,
    },
    {
      url: `${APP_URL}/privacy`,
      lastModified: SITE_UPDATED,
      changeFrequency: "yearly",
      priority: 0.5,
    },
    {
      url: `${APP_URL}/terms`,
      lastModified: SITE_UPDATED,
      changeFrequency: "yearly",
      priority: 0.5,
    },
  ];
}
