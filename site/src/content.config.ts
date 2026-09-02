import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

const collections = {
  docs: defineCollection({
    loader: docsLoader({
      generateId: ({ entry }) => entry.replace(/^en\//, '').replace(/\.(?:md|mdx)$/, ''),
    }),
    schema: docsSchema(),
  }),
};

export { collections };
