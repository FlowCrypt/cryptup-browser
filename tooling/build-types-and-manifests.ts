/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */
import { readFileSync, writeFileSync } from 'fs';
import { execSync as exec } from 'child_process';

// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="../node_modules/@types/chrome/index.d.ts" />

/**
 * This file was originally two files: one that edited manifests, and one that copied build folders and edited mock versions
 * These steps somewhat overlap, so the two scripts were joined into one below. However, work was not yet done to assimilate them.
 */

/**
 * first, modify appropriate manifests
 */

const DIR = './build';
const version: string = (JSON.parse(readFileSync('./package.json').toString()) as { version: string }).version;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const addManifest = (toBuildType: string, transform: (manifest: chrome.runtime.Manifest) => void, fromBuildType = 'generic-extension-wip') => {
  const manifest = JSON.parse(readFileSync(`${DIR}/${fromBuildType}/manifest.json`).toString()) as chrome.runtime.ManifestV3;
  transform(manifest);
  writeFileSync(`${DIR}/${toBuildType}/manifest.json`, JSON.stringify(manifest, undefined, 2));
};

addManifest('chrome-consumer', manifest => {
  manifest.version = version;
});

addManifest('firefox-consumer', manifest => {
  manifest.version = version;
  // We decide to use manifest v2 for firefox and below codes are to make v3 manifest to v2
  // Read more here: https://github.com/FlowCrypt/flowcrypt-browser/pull/5651#issuecomment-2029591323
  manifest.manifest_version = 2;
  const manifestV3 = manifest as chrome.runtime.ManifestV3;
  manifest.web_accessible_resources = manifestV3.web_accessible_resources?.[0].resources;
  manifest.content_security_policy = manifestV3.content_security_policy?.extension_pages;
  manifest.permissions = [...(manifestV3.permissions ?? []), ...(manifestV3.host_permissions ?? [])];
  delete manifest.host_permissions;
  manifest.browser_action = manifestV3.action;
  delete manifest.action;
  manifest.browser_specific_settings = {
    gecko: {
      id: 'firefox@cryptup.io',
      update_url: 'https://flowcrypt.com/api/update/firefox', // eslint-disable-line @typescript-eslint/naming-convention
      strict_min_version: '60.0', // eslint-disable-line @typescript-eslint/naming-convention
    },
  };
  manifest.background = {
    ...manifest.background,
    scripts: ['/js/service_worker/background.js'],
  };
  // eslint-disable-next-line @typescript-eslint/naming-convention, @typescript-eslint/no-unused-vars
  const { service_worker, ...newManifest } = manifest.background as chrome.runtime.ManifestV3;
  manifest = newManifest;
  manifest.permissions = manifest.permissions?.filter((p: string) => p !== 'unlimitedStorage');
  delete manifest.minimum_chrome_version;
});

addManifest(
  'thunderbird-consumer',
  manifest => {
    const manifestV3 = manifest as browser._manifest.WebExtensionManifest;
    (manifest.browser_action as browser._manifest.ActionManifest).default_title = 'FlowCrypt';
    manifest.name = 'FlowCrypt Encryption for Thunderbird';
    manifest.description = 'Simple end-to-end encryption to secure email and attachments on Thunderbird';
    manifest.permissions = [...(manifestV3.permissions ?? []), 'compose', 'messagesRead'];
    manifest.compose_action = {
      default_title: 'Secure Compose', // eslint-disable-line @typescript-eslint/naming-convention
      default_icon: '/img/logo/flowcrypt-logo-64-64.png', // eslint-disable-line @typescript-eslint/naming-convention
    };
    manifest.message_display_action = {
      default_title: 'Secure Compose', // eslint-disable-line @typescript-eslint/naming-convention
      default_icon: '/img/logo/flowcrypt-logo-64-64.png', // eslint-disable-line @typescript-eslint/naming-convention
    };
    (manifest.browser_specific_settings as browser._manifest.FirefoxSpecificProperties).strict_min_version = '102.0';
  },
  'firefox-consumer'
);

addManifest('chrome-enterprise', manifest => {
  manifest.version = version;
  manifest.name = 'FlowCrypt for Enterprise';
  manifest.description = 'FlowCrypt Chrome Extension for Enterprise clients (stable)';
  // careful - changing this will likely cause all extensions to be disabled in their user's browsers
  manifest.permissions = ['alarms', 'scripting', 'storage', 'tabs', 'unlimitedStorage'];
  manifest.host_permissions = [
    'https://*.google.com/*',
    // customer enterprise environments use people,gmail,oauth2 subdomains of googleapis.com
    // instead of the generic www.googleapis.com subdomain as used by consumer extension
    // consumer extension could eventually start using subdomains as well,
    // but is blocked on CORS dues to either of these two options:
    //   - CORS issue on /upload Google endpoint
    //        https://partnerissuetracker.corp.google.com/issues/157312473#comment17
    //   - working around the CORS issue by adding *.googleapis.com which
    //        disables installed extensions / asks user to re-enable
    'https://*.googleapis.com/*',
    'https://flowcrypt.com/*',
  ];
  for (const csDef of manifest.content_scripts ?? []) {
    csDef.matches = csDef.matches?.filter(host => host === 'https://mail.google.com/*' || host === 'https://www.google.com/robots.txt*');
  }
  manifest.content_scripts = (manifest.content_scripts ?? []).filter(csDef => csDef.matches?.length); // remove empty defs
  if (!manifest.content_scripts.length) {
    throw new Error('Content script defs ended up empty in enterprise manifest');
  }
});

/**
 * second, build copy and edit enterprise and mock versions
 */

const CHROME_CONSUMER = 'chrome-consumer';
const CHROME_ENTERPRISE = 'chrome-enterprise';
const MOCK_HOST: { [buildType: string]: string } = {
  'chrome-consumer': 'https://localhost:8001',
  'chrome-enterprise': 'https://google.mock.localhost:8001',
};

const buildDir = (buildType: string) => `./build/${buildType}`;

const edit = (filepath: string, editor: (content: string) => string) => {
  writeFileSync(filepath, editor(readFileSync(filepath, { encoding: 'utf-8' })));
};

const updateEnterpriseBuild = () => {
  const replaceConstsInEnterpriseBuild: { pattern: RegExp; replacement: string }[] = [
    {
      pattern: /const FLAVOR = 'consumer';/g,
      replacement: `const FLAVOR = 'enterprise';`,
    },
    {
      // for now we use www.googleapis.com on consumer until CORS resolved to use gmail.googleapis.com
      // (on enterprise we already use gmail.googleapis.com)
      pattern: /const GMAIL_GOOGLE_API_HOST = '[^']+';/g,
      replacement: `const GMAIL_GOOGLE_API_HOST = 'https://gmail.googleapis.com';`,
    },
  ];
  const constFilepaths = [`${buildDir(CHROME_ENTERPRISE)}/js/common/core/const.js`, `${buildDir(CHROME_ENTERPRISE)}/js/content_scripts/webmail_bundle.js`];
  for (const constFilepath of constFilepaths) {
    edit(constFilepath, (code: string) => {
      for (const item of replaceConstsInEnterpriseBuild) {
        if (!item.pattern.test(code)) {
          throw new Error(`Expecting to find '${item.pattern.source}' in ${constFilepath}`);
        }
        code = code.replace(item.pattern, item.replacement);
      }
      return code;
    });
  }
};

const makeMockBuild = (sourceBuildType: string) => {
  const mockBuildType = `${sourceBuildType}-mock`;
  const mockGmailPageHost = 'gmail.localhost:8001';
  const mockGmailPage = `https://${mockGmailPageHost}`;
  exec(`cp -r ${buildDir(sourceBuildType)} ${buildDir(mockBuildType)}`);
  const editor = (code: string) => {
    return code
      .replace(
        /const (OAUTH_GOOGLE_API_HOST|GMAIL_GOOGLE_API_HOST|PEOPLE_GOOGLE_API_HOST|GOOGLE_OAUTH_SCREEN_HOST) = [^;]+;/g,
        `const $1 = '${MOCK_HOST[sourceBuildType]}';`
      )
      .replace(/const (BACKEND_API_HOST) = [^;]+;/g, `const $1 = 'https://localhost:8001/api/';`)
      .replace(/const (ATTESTER_API_HOST) = [^;]+;/g, `const $1 = 'https://localhost:8001/attester/';`)
      .replace(/const (KEYS_OPENPGP_ORG_API_HOST) = [^;]+;/g, `const $1 = 'https://localhost:8001/keys-openpgp-org/';`)
      .replace(/const (SHARED_TENANT_API_HOST) = [^;]+;/g, `const $1 = 'https://localhost:8001/shared-tenant-fes';`)
      .replace(/const (WKD_API_HOST) = '';/g, `const $1 = 'https://localhost:8001';`);
  };
  edit(`${buildDir(mockBuildType)}/js/common/core/const.js`, editor);
  edit(`${buildDir(mockBuildType)}/js/common/platform/catch.js`, editor);
  edit(`${buildDir(mockBuildType)}/js/content_scripts/webmail_bundle.js`, editor);
  edit(`${buildDir(mockBuildType)}/manifest.json`, code =>
    code
      .replace(/https:\/\/mail\.google\.com/g, mockGmailPage)
      .replace(/https:\/\/www\.google\.com/g, 'https://google.localhost:8001')
      .replace(/https:\/\/\*\.google.com\/\*/, 'https://google.localhost/*')
  );
};

const makeLocalFesBuild = (sourceBuildType: string) => {
  const localFesBuildType = `${sourceBuildType}-local-fes`;
  exec(`cp -r ${buildDir(sourceBuildType)} ${buildDir(localFesBuildType)}`);
  edit(`${buildDir(localFesBuildType)}/js/common/api/account-servers/external-service.js`, code =>
    code.replace('https://fes.${this.domain}', 'http://localhost:32667')
  );
};

const makeContentScriptTestsBuild = (sourceBuildType: string) => {
  const testCode = readFileSync('./test/source/tests/content-script-test.js').toString();
  const testBuildType = sourceBuildType.endsWith('-mock')
    ? sourceBuildType.slice(0, -5) + '-content-script-tests-mock'
    : sourceBuildType + '-content-script-tests';
  exec(`cp -r ${buildDir(sourceBuildType)} ${buildDir(testBuildType)}`);
  edit(`${buildDir(testBuildType)}/js/content_scripts/webmail_bundle.js`, code =>
    code.replace(/\/\* ----- [^\r\n]*\/content_scripts\/webmail\/.*}\)\(\);/s, `${testCode}\r\n\r\n})();`)
  );
};

updateEnterpriseBuild();
makeMockBuild(CHROME_CONSUMER);
makeMockBuild(CHROME_ENTERPRISE);
makeLocalFesBuild(CHROME_ENTERPRISE);
makeContentScriptTestsBuild('chrome-consumer-mock');
// makeContentScriptTestsBuild('firefox-consumer'); // for manual testing of content script in Firefox
