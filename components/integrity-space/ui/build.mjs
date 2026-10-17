import { build } from 'esbuild';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
await mkdir('src/integrity_space/assets', {recursive: true});
for (const mode of ['lab', 'workbench']) {
  const output = await build({entryPoints: [`ui/${mode}.js`], bundle: true, write: false, format: 'iife', target: ['es2022'], minify: true, legalComments: 'inline'});
  const template = await readFile(`ui/${mode}.html`, 'utf8');
  await writeFile(`src/integrity_space/assets/${mode}.html`, template.replace('/* APP_BUNDLE */', () => output.outputFiles[0].text.replaceAll('</script', '<\\/script')));
}
