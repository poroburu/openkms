import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  site: 'https://poroburu.github.io',
  base: '/openkms',
  vite: {
    plugins: [tailwindcss()],
  },
  integrations: [
    starlight({
      title: 'openKMS',
      description: 'YubiHSM2-backed transaction signer for Cosmos and Solana.',
      favicon: '/favicon.svg',
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/poroburu/openkms',
        },
      ],
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', slug: 'overview' },
            { label: 'Quick Start', slug: 'guides/quick-start' },
            { label: 'Security Model', slug: 'concepts/security-model' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { label: 'Configuration', slug: 'guides/configuration' },
            { label: 'Policy Authoring', slug: 'guides/policy-authoring' },
            { label: 'Openclaw Integration', slug: 'guides/openclaw-integration' },
            { label: 'Deployment', slug: 'operations/deployment' },
            { label: 'Backup and Restore', slug: 'operations/backup-restore' },
            { label: 'Testing and Automation', slug: 'operations/testing' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'HTTP API', slug: 'reference/http-api' },
            {
              label: 'OpenAPI spec',
              link: 'https://github.com/poroburu/openkms/blob/main/openapi/openkms.v1.json',
            },
            { label: 'Architecture', slug: 'reference/architecture' },
          ],
        },
      ],
    }),
  ],
});
