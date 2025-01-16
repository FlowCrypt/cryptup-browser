/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import test, { Implementation } from 'ava';
import { exec } from 'child_process';
import { promisify } from 'util';

import { BrowserHandle, BrowserPool } from './browser';
import { AvaContext, TestContext, getDebugHtmlAtts, minutes, standaloneTestTimeout } from './tests/tooling';
import { Util, getParsedCliParams } from './util';

import { mkdirSync, realpathSync } from 'fs';
import { writeFile } from 'fs/promises';
import { TestUrls } from './browser/test-urls';
import { startAllApisMock } from './mock/all-apis-mock';
import { reportedErrors } from './mock/fes/shared-tenant-fes-endpoints';
import { defineComposeTests } from './tests/compose';
import { defineContentScriptTests } from './tests/content-script';
import { defineDecryptTests } from './tests/decrypt';
import { defineElementTests } from './tests/elements';
import { defineFlakyTests } from './tests/flaky';
import { defineGmailTests } from './tests/gmail';
import { defineSettingsTests } from './tests/settings';
import { defineSetupTests } from './tests/setup';
import { defineUnitBrowserTests } from './tests/unit-browser';
import { defineUnitNodeTests } from './tests/unit-node';

export const { testVariant, testGroup, oneIfNotPooled, buildDir, isMock } = getParsedCliParams();
export const internalTestState = { expectIntentionalErrReport: false }; // updated when a particular test that causes an error is run
const DEBUG_BROWSER_LOG = false; // set to true to print / export information from browser
const DEBUG_MOCK_LOG = false; // set to true to print mock server logs

process.setMaxListeners(0);

/* eslint-disable @typescript-eslint/naming-convention */
const consts = {
  // higher concurrency can cause 429 google errs when composing
  TIMEOUT_SHORT: minutes(1),
  TIMEOUT_EACH_RETRY: minutes(4),
  TIMEOUT_ALL_RETRIES: minutes(55), // this has to suffer waiting for semaphore between retries, thus almost the same as below
  TIMEOUT_OVERALL: minutes(60),
  ATTEMPTS: testGroup === 'STANDARD-GROUP' ? oneIfNotPooled(3) : process.argv.includes('--retry=false') ? 1 : 3,
  POOL_SIZE: oneIfNotPooled(isMock ? 20 : 3),
  PROMISE_TIMEOUT_OVERALL: undefined as unknown as Promise<never>, // will be set right below
  IS_LOCAL_DEBUG: process.argv.includes('--debug') ? true : false, // run locally by developer, not in ci
};

/* eslint-enable @typescript-eslint/naming-convention */
console.info('consts: ', JSON.stringify(consts), '\n');
consts.PROMISE_TIMEOUT_OVERALL = new Promise((resolve, reject) => setTimeout(() => reject(new Error(`TIMEOUT_OVERALL`)), consts.TIMEOUT_OVERALL));

export type Consts = typeof consts;
export type CommonAcct = 'compatibility' | 'compose' | 'ci.tests.gmail';

const asyncExec = promisify(exec);
const browserPool = new BrowserPool(consts.POOL_SIZE, 'browserPool', buildDir, isMock, undefined, undefined, consts.IS_LOCAL_DEBUG);

const registerCompletionHandler = () => {
  // eslint-disable-next-line @typescript-eslint/no-implied-eval
  const dynamicImport = new Function('specifier', 'return import(specifier)');

  dynamicImport('ava').then((module: { registerCompletionHandler: (handler: () => void) => void }) => {
    const { registerCompletionHandler } = module;
    registerCompletionHandler(() => {
      process.exit(0);
    });
  });
};

test.before(() => {
  registerCompletionHandler();
});

test.beforeEach('set timeout', async t => {
  t.timeout(consts.TIMEOUT_EACH_RETRY);
});

const testWithBrowser = (
  cb: (t: AvaContext, browser: BrowserHandle) => Promise<void>,
  flag?: 'FAILING',
  timeout = consts.TIMEOUT_EACH_RETRY
): Implementation<unknown[]> => {
  return async (t: AvaContext) => {
    const mockApi = isMock ? await startMockApiAndCopyBuild(t) : undefined;
    if (isMock) {
      t.context.mockApi = mockApi;
    } else {
      t.context.urls = new TestUrls(await browserPool.getExtensionId(t));
    }
    try {
      await browserPool.withNewBrowserTimeoutAndRetry(
        async (t, browser) => {
          const start = Date.now();
          await cb(t, browser);
          if (DEBUG_BROWSER_LOG) {
            await saveBrowserLog(t, browser);
          }
          t.log(`run time: ${Math.ceil((Date.now() - start) / 1000)}s`);
        },
        t,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        { ...consts, TIMEOUT_EACH_RETRY: timeout },
        flag
      );

      t.pass();
    } finally {
      await mockApi?.close();
    }
  };
};

const startMockApiAndCopyBuild = async (t: AvaContext) => {
  const mockApiLogs: string[] = [];
  t.context.mockApiLogs = mockApiLogs;
  const mockApi = await startAllApisMock(line => {
    if (DEBUG_MOCK_LOG) {
      console.log(line);
    }
    mockApiLogs.push(line);
  }).catch((e: unknown) => {
    console.error(e);
    process.exit(1);
  });
  const address = mockApi.server.address();
  if (typeof address === 'object' && address) {
    const result = await asyncExec(`sh ./scripts/config-mock-build.sh ${buildDir} ${address.port}`);
    t.context.extensionDir = result.stdout;
    t.context.urls = new TestUrls(await browserPool.getExtensionId(t), address.port);
  } else {
    t.log('Failed to get mock build address');
  }
  return mockApi;
};

const saveBrowserLog = async (t: AvaContext, browser: BrowserHandle) => {
  try {
    const page = await browser.newPage(t, t.context.urls?.extension('chrome/dev/ci_unit_test.htm'));
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-explicit-any
    const items = (await page.target.evaluate(() => (window as any).Debug.readDatabase())) as {
      input: unknown;
      output: unknown;
    }[];
    for (let i = 0; i < items.length; i++) {
      const item = items[i];
      const input = JSON.stringify(item.input);
      const output = JSON.stringify(item.output, undefined, 2);
      const file = `./test/tmp/${t.title}-${i}.txt`;
      await writeFile(file, `in: ${input}\n\nout: ${output}`);
      t.log(`browser debug written to file: ${file}`);
    }
  } catch (e) {
    t.log(`Error reading debug messages: ${e}`);
  }
};

export type TestWithBrowser = typeof testWithBrowser;

test.after.always('evaluate Catch.reportErr errors', async t => {
  if (!isMock || testGroup !== 'STANDARD-GROUP') {
    // can only collect reported errs when running with a mocked api
    t.pass();
    return;
  }
  // todo - here we filter out an error that would otherwise be useful
  // in one test we are testing an error scenario
  // our S/MIME implementation is still early so it throws "reportable" errors like this during tests
  const usefulErrors = reportedErrors
    .filter(e => e.message !== 'Too few bytes to read ASN.1 value.')
    // below for test "get.updating.key@key-manager-choose-passphrase-forbid-storing.flowcrypt.test - automatic update of key found on key manager"
    //   and for test "setup [using key manager] - notify users when their keys expire soon"
    .filter(
      e =>
        e.message !== 'Some keys could not be parsed' &&
        !e.message.match(/Bad Request: 400 when GET-ing https:\/\/.*localhost:\d+\/flowcrypt-email-key-manager/g)
    )
    // below for test "decrypt - failure retrieving chunk download - next request will try anew"
    .filter(
      e =>
        !/400 when GET-ing https:\/\/.*localhost:\d+\/gmail\/v1\/users\/me\/messages\/1885ded59a2b5a8d\/attachments\/ANGjdJ_0g7PGqJSjI8-Wjd5o8HcVnAHxIk-H210TAxxwf/.test(
          e.message
        )
    )
    // below for test "user4@standardsubdomainfes.localhost:8001 - PWD encrypted message with FES web portal - a send fails with gateway update error"
    .filter(e => !e.message.includes('Test error'))
    // below for test "no.fes@example.com - skip FES on consumer, show friendly message on enterprise"
    .filter(e => !e.trace.includes('-1 when GET-ing https://fes.example.com'))
    // todo - ideally mock tests would never call this. But we do tests with human@flowcrypt.com so it's calling here
    .filter(e => !e.trace.includes('-1 when GET-ing https://openpgpkey.flowcrypt.com'))
    // below for test "allows to retry public key search when attester returns error"
    .filter(
      e => !/Error: Internal Server Error: 500 when GET-ing https:\/\/localhost:\d+\/attester\/pub\/attester\.return\.error@flowcrypt\.test/.exec(e.message)
    );
  const foundExpectedErr = usefulErrors.find(re => re.message === `intentional error for debugging`);
  const foundUnwantedErrs = usefulErrors.filter(
    re =>
      re.message !== `intentional error for debugging` &&
      !re.message.includes('traversal forbidden') &&
      !re.message.includes('The string to be decoded is not correctly encoded')
  );
  if (testVariant === 'CONSUMER-MOCK' && internalTestState.expectIntentionalErrReport && !foundExpectedErr) {
    // on consumer flavor app, we submit errors to flowcrypt.com backend
    t.fail(`Catch.reportErr errors: missing intentional error report on consumer flavor`);
    return;
  }
  if (testVariant === 'ENTERPRISE-MOCK' && reportedErrors.length) {
    // on enterprise flavor app, we don't submit any errors anywhere yet
    t.fail(`Catch.reportErr errors: should not report any error on enterprise app`);
    return;
  }
  if (foundUnwantedErrs.length) {
    for (const e of foundUnwantedErrs) {
      console.info(`----- mockBackendData Catch.reportErr -----\nname: ${e.name}\nmessage: ${e.message}\nurl: ${e.url}\ntrace: ${e.trace}`);
    }
    t.fail(`Catch.reportErr errors: ${foundUnwantedErrs.length}`);
  } else {
    t.pass();
  }
});

test.afterEach.always('finalize', async t => {
  console.info(`${t.passed ? 'passed' : 'FAILED'} test, ${t.title}`);
  const failRnd = Util.lousyRandom();
  const debugHtmlAttachments = getDebugHtmlAtts(t.title, t.context as TestContext);
  if (debugHtmlAttachments.length) {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-expect-error
    standaloneTestTimeout(t, consts.TIMEOUT_SHORT, t.title);
    const debugArtifactDir = realpathSync(`${__dirname}/..`) + '/debugArtifacts';
    try {
      mkdirSync(debugArtifactDir);
    } catch (error) {
      if ((error as { code: string }).code !== 'EEXIST') throw error;
    }
    for (let i = 0; i < debugHtmlAttachments.length; i++) {
      // const subject = `${testId} ${i + 1}/${debugHtmlAttachments.length}`;
      const fileName = `debugHtmlAttachment-${testVariant}-${failRnd}-${i}.html`;
      const filePath = `${debugArtifactDir}/${fileName}`;
      console.info(`Writing debug file ${fileName}`);
      await writeFile(filePath, debugHtmlAttachments[i]);
      try {
        await asyncExec(`artifact push job ${filePath}`);
      } catch {
        // probably local environment without semaphore CLI tooling
      }
    }
  } else if (!t.passed) {
    console.info(`No debug artifacts created for this failure`);
  }
  t.pass();
});

if (testGroup === 'UNIT-TESTS') {
  defineUnitNodeTests(testVariant);
  defineUnitBrowserTests(testVariant, testWithBrowser);
} else if (testGroup === 'FLAKY-GROUP') {
  defineFlakyTests(testVariant, testWithBrowser);
} else if (testGroup === 'CONTENT-SCRIPT-TESTS') {
  defineContentScriptTests(testWithBrowser);
} else {
  defineSetupTests(testVariant, testWithBrowser);
  defineComposeTests(testVariant, testWithBrowser);
  defineDecryptTests(testVariant, testWithBrowser);
  defineGmailTests(testVariant, testWithBrowser);
  defineSettingsTests(testVariant, testWithBrowser);
  defineElementTests(testVariant, testWithBrowser);
}
