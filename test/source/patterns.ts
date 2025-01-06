/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */
import * as path from 'path';
import { readFileSync, readdirSync, statSync } from 'fs';

/**
 * This test looks for petterns in the source code, as well as in the built product to look for issues.
 */

let errsFound = 0;

const getAllFilesInDir = (dir: string, filePattern: RegExp): string[] => {
  const all: string[] = [];
  const filesInDir = readdirSync(dir);
  for (const fileInDir of filesInDir) {
    const filePath = path.join(dir, fileInDir);
    const stat = statSync(filePath);
    if (stat.isDirectory()) {
      all.push(...getAllFilesInDir(filePath, filePattern));
    } else if (filePattern.test(filePath)) {
      all.push(filePath);
    }
  }
  return all;
};

const hasXssComment = (line: string) => {
  return /\/[\/\*] xss-(known-source|direct|escaped|safe-factory|safe-value|sanitized|none|reinsert|dangerous-function)/.test(line);
};

const hasErrHandledComment = (line: string) => {
  return /\/[\/\*] error-handled/.test(line);
};

const validateTypeScriptLine = (line: string, location: string) => {
  if (line.match(/\.(innerHTML|outerHTML) ?= ?/g) && !hasXssComment(line)) {
    console.error(`unchecked xss in ${location}:\n${line}\n`);
    errsFound++;
  }
  if (line.match(/\.(html|append|prepend|replaceWith|insertBefore|insertAfter|before|after)\([^)]/g) && !hasXssComment(line)) {
    console.error(`unchecked xss in ${location}:\n${line}\n`);
    errsFound++;
  }
  if (line.match(/DANGEROUS/gi) && !hasXssComment(line) && !line.includes(' is dangerous ')) {
    console.error(`unchecked xss in ${location}:\n${line}\n`);
    errsFound++;
  }
  if (line.match(/setInterval|setTimeout/g) && !hasErrHandledComment(line)) {
    console.error(`errors not handled in ${location} (make sure to use Catch.setHandledTimeout or Catch.setHandledInterval):\n${line}\n`);
    errsFound++;
  }
  if (line.match(/^ {2}(public |private |protected |async )*((?!constructor)[a-z][a-zA-Z0-9]+)\([^;]+[^>] \{$/g)) {
    console.error(`wrongly using class method, which can cause binding loss (use fat arrow method properties instead) #1:\n${line}\n`);
    errsFound++;
  }
  if (line.match(/^ {2}(public |private |protected |static )+?[a-z][a-zA-Z0-9]+ = (async )?\(.+\)(: .+)? => .+;$/g)) {
    console.error(
      `don't use single-line "method = (arg) => result" class methods, give them a method body and a return statement "method = (arg) => { return result; }":\n${line}\n`
    );
    errsFound++;
  }
  if (line.match(/^ {2}(public |private |protected |async )*((?!constructor)[a-z][a-zA-Z0-9]+)\([^)]*\) \{$/g)) {
    console.error(`wrongly using class method, which can cause binding loss (use fat arrow method properties instead) #2:\n${line}\n`);
    errsFound++;
  }
};

/**
 * lint problems in TS files - the type of issues that we don't have a linter for
 */
for (const srcFilePath of getAllFilesInDir('./extension', /\.ts$/)) {
  const lines = readFileSync(srcFilePath).toString().split('\n');
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    validateTypeScriptLine(lines[lineIndex], `${srcFilePath}:${lineIndex + 1}`);
  }
}

/**
 * check for problems in manifest file (because dynamically generated)
 * https://github.com/FlowCrypt/flowcrypt-browser/issues/2934
 */

const expectedPermissions: chrome.runtime.ManifestPermissions[] = ['alarms', 'scripting', 'storage', 'tabs', 'unlimitedStorage'];
const expectedConsumerHostPermissions = ['https://*.google.com/*', 'https://www.googleapis.com/*', 'https://flowcrypt.com/*'];
const expectedEnterpriseHostPermissions = ['https://*.google.com/*', 'https://*.googleapis.com/*', 'https://flowcrypt.com/*'];
for (const buildType of ['chrome-consumer', 'chrome-enterprise', 'thunderbird-consumer', 'firefox-consumer']) {
  const manifest = JSON.parse(readFileSync(`./build/${buildType}/manifest.json`).toString()) as chrome.runtime.Manifest;
  const isManifestV3Build = buildType.includes('chrome') || buildType.includes('firefox');
  const expectedHostPermissions = buildType.includes('consumer') ? expectedConsumerHostPermissions : expectedEnterpriseHostPermissions;
  for (const expectedHostPermission of expectedHostPermissions) {
    if (isManifestV3Build && !manifest.host_permissions.includes(expectedHostPermission)) {
      console.error(`Missing host permission '${expectedHostPermission}' in ${buildType}/manifest.json`);
      errsFound++;
    }
  }
  for (const expectedPermission of expectedPermissions) {
    if (!manifest.permissions?.includes(expectedPermission)) {
      if (!(expectedPermission === 'unlimitedStorage' && (buildType === 'firefox-consumer' || buildType === 'thunderbird-consumer'))) {
        console.error(`Missing permission '${expectedPermission}' in ${buildType}/manifest.json`);
        errsFound++;
      }
    }
  }
  if (buildType === 'thunderbird-consumer') {
    if (manifest.manifest_version !== 2) {
      console.error(`${buildType} - The manifest version is not 2`);
      errsFound++;
    }
    if (!Array.isArray(manifest.web_accessible_resources)) {
      console.error(`${buildType} - The web_accessible_resources should be an array`);
      errsFound++;
    }
    if (typeof manifest.content_security_policy !== 'string') {
      console.error(`${buildType} - The content_security_policy should be a string`);
      errsFound++;
    }
    const thunderbirdExpectedPermissions = ['compose', 'downloads', 'downloads.open', 'messagesRead', 'messagesUpdate', 'messagesModify', 'accountsRead'];
    const buildHostPermissions = isManifestV3Build ? manifest.host_permissions : manifest.permissions;
    for (const expectedHostPermission of thunderbirdExpectedPermissions) {
      if (!buildHostPermissions?.includes(expectedHostPermission)) {
        console.error(`${buildType} - Missing permission ${expectedHostPermission} in ${buildType}/manifest.json`);
        errsFound++;
      }
    }
  }
  const extensionContentScript = manifest.content_scripts?.find(cs => cs.matches?.includes('https://mail.google.com/*'));
  if (!extensionContentScript?.css?.length || !extensionContentScript.js?.length) {
    console.error(`Missing content_scripts declaration for the extension in ${buildType}/manifest.json`);
    errsFound++;
  }
}

if (errsFound) {
  console.error(`patterns.ts: Found ${errsFound} unhandled patterns, exiting\n`);
  process.exit(1);
}
