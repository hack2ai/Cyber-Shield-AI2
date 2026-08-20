import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const root = process.cwd();
const extensionDirs = ['extension', 'public/extension'];

for (const directory of extensionDirs) {
  const dir = path.join(root, directory);
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

  if (manifest.manifest_version !== 3) throw new Error(`${directory}: manifest_version must be 3`);
  if (manifest.action?.default_popup !== 'popup.html') throw new Error(`${directory}: popup.html must be the action popup`);
  if (manifest.host_permissions?.includes('<all_urls>')) throw new Error(`${directory}: wildcard host permission is not allowed`);
  if (manifest.icons || manifest.action?.default_icon) {
    throw new Error(`${directory}: manifest references icon assets that are not packaged`);
  }

  for (const relativePath of [manifest.action.default_popup, 'popup.js', 'popup.css', 'README.md']) {
    if (!fs.existsSync(path.join(dir, relativePath))) {
      throw new Error(`${directory}: missing ${relativePath}`);
    }
  }
}

console.log('Extension packaging smoke test passed.');
