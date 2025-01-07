/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import * as fs from 'fs';
import test from 'ava';

import { Config, Util } from './../util';
import { TestWithBrowser, internalTestState } from './../test';

import { BrowserRecipe } from './tooling/browser-recipe';
import { InboxPageRecipe } from './page-recipe/inbox-page-recipe';
import { SettingsPageRecipe } from './page-recipe/settings-page-recipe';
import { TestVariant } from './../util';
import { expect } from 'chai';
import { SetupPageRecipe } from './page-recipe/setup-page-recipe';
import { testConstants } from './tooling/consts';
import { PageRecipe } from './page-recipe/abstract-page-recipe';
import { OauthPageRecipe } from './page-recipe/oauth-page-recipe';
import { KeyInfoWithIdentity, KeyUtil, PubkeyInfoWithLastCheck } from '../core/crypto/key';
import { Buf } from '../core/buf';
import { GoogleData } from '../mock/google/google-data';
import Parse from './../util/parse';
import { OpenPGPKey } from '../core/crypto/pgp/openpgp-key';
import { BrowserHandle, ControllablePage } from '../browser';
import { AvaContext } from './tooling';
import { ConfigurationProvider, HttpClientErr, Status } from '../mock/lib/api';
import { somePubkey, testMatchPubKey } from '../mock/attester/attester-key-constants';
import { Dict, emailKeyIndex } from '../core/common';
import { twoKeys1, twoKeys2 } from '../mock/key-manager/key-manager-constants';
import { getKeyManagerAutogenRules } from '../mock/fes/fes-constants';
import { FesClientConfiguration } from '../mock/fes/shared-tenant-fes-endpoints';
import { flowcryptCompatibilityAliasList } from '../mock/google/google-endpoints';

export const defineSettingsTests = (testVariant: TestVariant, testWithBrowser: TestWithBrowser) => {
  if (testVariant !== 'CONSUMER-LIVE-GMAIL') {
    test(
      'settings - my own emails show as contacts',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility', {
          google: { acctAliases: flowcryptCompatibilityAliasList },
        });
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const comtactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await comtactsFrame.waitAll('@page-contacts');
        await Util.sleep(1);
        expect(await comtactsFrame.read('@page-contacts')).to.contain(acct);
        expect(await comtactsFrame.read('@page-contacts')).to.contain('flowcryptcompatibility@gmail.com');
        await SettingsPageRecipe.closeDialog(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
      })
    );
    test(
      'settings - attester shows my emails',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility', {
          google: { acctAliases: flowcryptCompatibilityAliasList },
        });
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const attesterFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-attester-page', ['keyserver.htm', 'placement=settings']);
        await attesterFrame.waitAll('@page-attester');
        await Util.sleep(1);
        await attesterFrame.waitTillGone('@spinner');
        await attesterFrame.waitForContent('@page-attester', acct);
        await attesterFrame.waitForContent('@page-attester', 'flowcryptcompatibility@gmail.com');
        await SettingsPageRecipe.closeDialog(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
      })
    );
    test(
      'settings - attester diagnostics page shows mismatch information correctly',
      testWithBrowser(async (t, browser) => {
        const email = 'test.match.attester.key@gmail.com';
        const mismatchEmail = 'test.mismatch.attester.key@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {
              [email]: {
                pubkey: testMatchPubKey,
              },
              [mismatchEmail]: {
                pubkey: somePubkey,
              },
            },
          },
          google: {
            aliases: {
              [email]: [
                {
                  sendAsEmail: mismatchEmail,
                  displayName: 'Test mismatch',
                  replyToAddress: mismatchEmail,
                  signature: '',
                  isDefault: false,
                  isPrimary: false,
                  treatAsAlias: false,
                  verificationStatus: 'accepted',
                },
              ],
            },
          },
        });
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, email);
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'test.match.attester.key',
          { submitPubkey: false, usedPgpBefore: true },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const attesterFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-attester-page', ['keyserver.htm', 'placement=settings']);
        await attesterFrame.waitAll('@page-attester');
        await attesterFrame.waitTillGone('@spinner');
        await attesterFrame.waitForContent(`@attester-${email.replace(/[^a-z0-9]+/g, '')}-pubkey-result`, 'Submitted correctly, can receive encrypted email.');
        await attesterFrame.waitForContent(
          `@attester-${mismatchEmail.replace(/[^a-z0-9]+/g, '')}-pubkey-result`,
          'Wrong public key recorded. Your incoming email may be unreadable when encrypted.'
        );
      })
    );
    test(
      'settings - verify key presense 1pp1',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acctEmail);
        await SettingsPageRecipe.verifyMyKeyPage(settingsPage, 'flowcrypt.compatibility.1pp1', 'button');
      })
    );
    test(
      'settings - test pass phrase',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acctEmail);
        await SettingsPageRecipe.passphraseTest(settingsPage, Config.key('flowcrypt.wrong.passphrase').passphrase, false);
        await SettingsPageRecipe.passphraseTest(settingsPage, Config.key('flowcrypt.compatibility.1pp1').passphrase, true);
      })
    );
    test(
      'settings - clarify passphrase prompt text',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acctEmail);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');

        const fingerprint = (await settingsPage.read('.good'))!.split(' ').join('');
        const longid = OpenPGPKey.fingerprintToLongid(fingerprint);
        const baseUrl = `chrome/elements/passphrase.htm?acctEmail=${acctEmail}&longids=${longid}&parentTabId=`;
        let passphrasePage = await browser.newPage(t, baseUrl.concat('&type=sign'));
        await passphrasePage.waitForSelTestState('ready');
        expect(await passphrasePage.read('@passphrase-text')).to.equal('Enter FlowCrypt pass phrase to sign email');
        await passphrasePage.close();
        passphrasePage = await browser.newPage(t, baseUrl.concat('&type=message'));
        await passphrasePage.waitForSelTestState('ready');
        expect(await passphrasePage.read('@passphrase-text')).to.equal('Enter FlowCrypt pass phrase to read encrypted email');
        await passphrasePage.close();
        passphrasePage = await browser.newPage(t, baseUrl.concat('&type=draft'));
        await passphrasePage.waitForSelTestState('ready');
        expect(await passphrasePage.read('@passphrase-text')).to.equal('Enter FlowCrypt pass phrase to load a draft');
        await passphrasePage.close();
        passphrasePage = await browser.newPage(t, baseUrl.concat('&type=attachment'));
        await passphrasePage.waitForSelTestState('ready');
        expect(await passphrasePage.read('@passphrase-text')).to.equal('Enter FlowCrypt pass phrase to decrypt a file');
        await passphrasePage.close();
        passphrasePage = await browser.newPage(t, baseUrl.concat('&type=quote'));
        await passphrasePage.waitForSelTestState('ready');
        expect(await passphrasePage.read('@passphrase-text')).to.equal('Enter FlowCrypt pass phrase to load quoted content');
        await passphrasePage.close();
        passphrasePage = await browser.newPage(t, baseUrl.concat('&type=backup'));
        await passphrasePage.waitForSelTestState('ready');
        expect(await passphrasePage.read('@passphrase-text')).to.equal('Enter FlowCrypt pass phrase to back up');
        await passphrasePage.close();
      })
    );
    test.todo('settings - verify 2pp1 key presense');
    // await tests.settings_my_key_tests(settingsPage, 'flowcrypt.compatibility.2pp1', 'link');
    test(
      'settings - feedback form',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await settingsPage.waitAndClick('@action-open-modules-help');
        await settingsPage.waitAll('@dialog');
        const helpFrame = await settingsPage.getFrame(['help.htm']);
        await helpFrame.waitAndType('@input-feedback-message', 'automated puppeteer test: help form from settings footer');
        await helpFrame.waitAndClick('@action-feedback-send');
        await helpFrame.waitAndRespondToModal('info', 'confirm', 'Message sent!');
      })
    );
    test(
      'settings - view contact public key',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility', {
          google: { acctAliases: flowcryptCompatibilityAliasList },
        });
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await Util.sleep(1);
        await contactsFrame.waitAndClick('@action-show-email-flowcryptcompatibilitygmailcom(flowcrypt.compatibility)');
        await Util.sleep(1);
        const contacts = await contactsFrame.read('@page-contacts');
        expect(contacts).to.contain('5520 CACE 2CB6 1EA7 13E5 B005 7FDE 6855 48AE A788');
        expect(contacts).to.contain('E8F0 517B A6D7 DAB6 081C 96E4 ADAC 279C 9509 3207');
        await contactsFrame.waitAndClick('@action-show-pubkey-5520CACE2CB61EA713E5B0057FDE685548AEA788-openpgp', {
          confirmGone: true,
        });
        const contacts1 = await contactsFrame.read('@page-contacts');
        expect(contacts1).to.contain('7FDE 6855 48AE A788');
        expect(contacts1).to.contain('flowcrypt.compatibility@gmail.com');
        expect(contacts1).to.contain('-----BEGIN PGP PUBLIC KEY BLOCK-----');
        await contactsFrame.waitAndClick('@action-back-to-contact-list', { confirmGone: true });
        await Util.sleep(1);
        expect(await contactsFrame.read('@page-contacts')).to.contain('flowcrypt.compatibility@gmail.com');
        expect(await contactsFrame.read('@page-contacts')).to.contain('flowcryptcompatibility@gmail.com');
        await SettingsPageRecipe.closeDialog(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
      })
    );
    test(
      'settings - update contact public key',
      testWithBrowser(async (t, browser) => {
        const acct = 'ci.tests.gmail@flowcrypt.test';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const recipientEmail = 'has.older.key.on.attester@recipient.com';
        // add a newer expired key manually
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await contactsFrame.waitAndClick('@action-show-import-public-keys-form', { confirmGone: true });
        await contactsFrame.waitAndType('@input-bulk-public-keys', testConstants.oldHasOlderKeyOnAttester);
        await contactsFrame.waitAndClick('@action-show-parsed-public-keys', { confirmGone: true });
        await contactsFrame.waitAll('iframe');
        const pubkeyFrame = await contactsFrame.getFrame(['pgp_pubkey.htm']);
        await pubkeyFrame.waitForContent('@action-add-contact', 'IMPORT EXPIRED KEY');
        await pubkeyFrame.waitAndClick('@action-add-contact');
        await pubkeyFrame.waitForContent('@container-pgp-pubkey', `${recipientEmail} added`);
        await contactsFrame.waitAndClick('@action-back-to-contact-list', { confirmGone: true });
        await contactsFrame.waitAndClick(`@action-show-email-${recipientEmail.replace(/[^a-z0-9]+/g, '')}`);
        await SettingsPageRecipe.checkContactKey(contactsFrame, 'OPENPGP', 'EXPIRED', '8EC7 8F04 3CEB 0224 98AF D477 1E62 ED6D 15A2 5921');
        await contactsFrame.waitAndClick(`@action-show-pubkey-8EC78F043CEB022498AFD4771E62ED6D15A25921-openpgp`, {
          confirmGone: true,
        });
        await contactsFrame.waitForContent('@container-pubkey-details', 'Fingerprint: 8EC7 8F04 3CEB 0224 98AF D477 1E62 ED6D 15A2 5921');
        await contactsFrame.waitForContent('@container-pubkey-details', 'Created on: Thu Jul 16 2020 09:56:40');
        await contactsFrame.waitForContent('@container-pubkey-details', 'Expiration: Thu Jul 16 2020 09:56:42');
        await contactsFrame.waitForContent('@container-pubkey-details', 'Expired: yes');
        await contactsFrame.waitAndClick('@action-back-to-contact-list', { confirmGone: true });
        await contactsFrame.waitAndClick(`@action-show-email-${recipientEmail.replace(/[^a-z0-9]+/g, '')}`);
        await contactsFrame.waitAndClick('@action-change-pubkey-8EC78F043CEB022498AFD4771E62ED6D15A25921-openpgp', {
          confirmGone: true,
        });
        await contactsFrame.waitAndType('@input-public-key', testConstants.newHasOlderKeyOnAttester);
        await contactsFrame.waitAndClick('@action-save-public-key', { confirmGone: true });
        await contactsFrame.waitAndClick(`@action-show-email-${recipientEmail.replace(/[^a-z0-9]+/g, '')}`);
        await contactsFrame.waitForContent('@page-contacts', '8EC7 8F04 3CEB 0224 98AF D477 1E62 ED6D 15A2 5921');
        await SettingsPageRecipe.checkContactKey(contactsFrame, 'OPENPGP', 'EXPIRED', '8EC7 8F04 3CEB 0224 98AF D477 1E62 ED6D 15A2 5921');
        await contactsFrame.waitAndClick(`@action-show-pubkey-8EC78F043CEB022498AFD4771E62ED6D15A25921-openpgp`, {
          confirmGone: true,
        });
        await contactsFrame.waitForContent('@container-pubkey-details', 'Fingerprint: 8EC7 8F04 3CEB 0224 98AF D477 1E62 ED6D 15A2 5921');
        await contactsFrame.waitForContent('@container-pubkey-details', 'Created on: Thu Jul 16 2020 09:56:40');
        await contactsFrame.waitForContent('@container-pubkey-details', 'Expiration: Thu Jul 16 2020 09:57:40');
        await contactsFrame.waitForContent('@container-pubkey-details', 'Expired: yes');
      })
    );
    test(
      'settings - import different public key for same the contact',
      testWithBrowser(async (t, browser) => {
        const acct = 'ci.tests.gmail@flowcrypt.test';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await contactsFrame.waitAndClick('@action-show-import-public-keys-form', { confirmGone: true });
        await contactsFrame.waitAndType('@input-bulk-public-keys', testConstants.user1FirstPubKey);
        await contactsFrame.waitAndClick('@action-show-parsed-public-keys', { confirmGone: true });
        await contactsFrame.waitAll('iframe');
        const pubkeyFrame = await contactsFrame.getFrame(['pgp_pubkey.htm']);
        await pubkeyFrame.waitForInputValue('@input-email', 'user1@example.com');
        await pubkeyFrame.waitForContent('@action-add-contact', 'IMPORT KEY');
        await pubkeyFrame.waitAndClick('@action-add-contact');
        await contactsFrame.waitAndClick('@action-back-to-contact-list');
        await contactsFrame.waitAndClick('@action-show-import-public-keys-form', { confirmGone: true });
        await contactsFrame.waitAndType('@input-bulk-public-keys', testConstants.user1SecondPubKey);
        await contactsFrame.waitAndClick('@action-show-parsed-public-keys', { confirmGone: true });
        await contactsFrame.waitAll('iframe');
        const pubkeyFrame2 = await contactsFrame.getFrame(['pgp_pubkey.htm']);
        await pubkeyFrame2.waitForInputValue('@input-email', 'user1@example.com');
        await pubkeyFrame2.waitForContent('@action-add-contact', 'IMPORT KEY');
      })
    );
    test(
      'settings - import public key which contains null users',
      testWithBrowser(async (t, browser) => {
        const acct = 'ci.tests.gmail@flowcrypt.test';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await contactsFrame.waitAndClick('@action-show-import-public-keys-form', { confirmGone: true });
        await contactsFrame.waitAndType('@input-bulk-public-keys', testConstants.nullUserPubKey);
        await contactsFrame.waitAndClick('@action-show-parsed-public-keys', { confirmGone: true });
        await contactsFrame.waitAll('iframe');
        const pubkeyFrame = await contactsFrame.getFrame(['pgp_pubkey.htm']);
        await pubkeyFrame.waitForInputValue('@input-email', 'demo@example.com');
        await pubkeyFrame.waitForContent('@action-add-contact', 'IMPORT KEY');
      })
    );
    test(
      'settings - import revoked key fails but the revocation info is saved',
      testWithBrowser(async (t, browser) => {
        const acct = 'ci.tests.gmail@flowcrypt.test';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const dbPage = await browser.newExtensionPage(t, 'chrome/dev/ci_unit_test.htm');
        const revocationBefore = await dbPage.page.evaluate(async () => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const db = await (window as any).ContactStore.dbOpen();
          const revocation: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['revocations'], 'readonly');
            const req = tx.objectStore('revocations').get('A5CFC8E8EA4AE69989FE2631097EEBF354259A5E');
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          return revocation;
        });
        expect(revocationBefore).to.be.an('undefined'); // no revocations yet
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await contactsFrame.waitAndClick('@action-show-import-public-keys-form', { confirmGone: true });
        await contactsFrame.waitAndType('@input-bulk-public-keys', testConstants.somerevokedRevoked1);
        await contactsFrame.waitAndClick('@action-show-parsed-public-keys');
        await contactsFrame.waitAll('iframe');
        const pubkeyFrame = await contactsFrame.getFrame(['pgp_pubkey.htm']);
        await pubkeyFrame.notPresent('@action-add-contact');
        await pubkeyFrame.notPresent('@manual-import-warning');
        expect((await pubkeyFrame.read('#pgp_block.pgp_pubkey'))?.toLowerCase()).to.include('not usable');
        const revocationAfter = await dbPage.page.evaluate(async () => {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const db = await (window as any).ContactStore.dbOpen();
          const revocation: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['revocations'], 'readonly');
            const req = tx.objectStore('revocations').get('A5CFC8E8EA4AE69989FE2631097EEBF354259A5E');
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          return revocation;
        });
        expect(revocationAfter).not.to.be.an('undefined'); // revocation is saved in the database
      })
    );
    test(
      'settings - #5147 check contact key import error',
      testWithBrowser(async (t, browser) => {
        const acct = 'ci.tests.gmail@flowcrypt.test';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await contactsFrame.waitAndClick('@action-show-import-public-keys-form', { confirmGone: true });
        const [fileChooser] = await Promise.all([
          settingsPage.page.waitForFileChooser(),
          contactsFrame.waitAndClick('@action-upload-key', { retryErrs: true }),
        ]);
        await fileChooser.accept(['test/samples/openpgp/pub_keys_5_good_1_unsupported.txt']);
        await Util.sleep(1);
        await contactsFrame.waitAll('iframe');
        const framesUrls = await contactsFrame.getFramesUrls(['pgp_pubkey.htm']);
        const firstFrameId = /frameId=.*?&/s.exec(framesUrls[0])![0];
        const errorFrame = await contactsFrame.getFrame(['pgp_pubkey.htm', firstFrameId]);
        await errorFrame.waitForContent('@error-introduce-label', 'This OpenPGP key is not usable.');
        await errorFrame.waitForContent('@error-introduce-label', 'Could not verify primary key: dsa keys are considered too weak');
        await errorFrame.waitForInputValue('@error-email-input', 'dsa@flowcrypt.test');
      })
    );
    test(
      'settings - remove public keys from contact',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility', {
          google: { acctAliases: flowcryptCompatibilityAliasList },
        });
        const dbPage = await browser.newExtensionPage(t, 'chrome/dev/ci_unit_test.htm');
        const foundKeys = await dbPage.page.evaluate(async () => {
          const acct = 'flowcrypt.compatibility@gmail.com';
          /* eslint-disable @typescript-eslint/no-explicit-any */
          const db = await (window as any).ContactStore.dbOpen();
          // first, unlink pubkeys from `flowcrypt.compatibility@gmail.com',
          // so they remain linked only to `flowcryptcompatibility@gmail.com'
          await (window as any).ContactStore.unlinkPubkey(db, acct, {
            id: '5520CACE2CB61EA713E5B0057FDE685548AEA788',
            type: 'openpgp ',
          });
          await (window as any).ContactStore.unlinkPubkey(db, acct, {
            id: 'E8F0517BA6D7DAB6081C96E4ADAC279C95093207',
            type: 'openpgp ',
          });
          const pubkey7FDE685548AEA788: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['pubkeys'], 'readonly');
            const req = tx.objectStore('pubkeys').get('5520CACE2CB61EA713E5B0057FDE685548AEA788');
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          const pubkeyADAC279C95093207: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['pubkeys'], 'readonly');
            const req = tx.objectStore('pubkeys').get('E8F0517BA6D7DAB6081C96E4ADAC279C95093207');
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          const contactsSize = (
            await (window as any).ContactStore.search(db, {
              hasPgp: true,
              substring: 'flowcrypt',
            })
          ).length;
          /* eslint-enable @typescript-eslint/no-explicit-any */
          return { pubkey7FDE685548AEA788, pubkeyADAC279C95093207, contactsSize };
        });
        expect(foundKeys.contactsSize).to.equal(1);
        expect(foundKeys.pubkey7FDE685548AEA788.fingerprint).to.equal('5520CACE2CB61EA713E5B0057FDE685548AEA788');
        expect(foundKeys.pubkeyADAC279C95093207.fingerprint).to.equal('E8F0517BA6D7DAB6081C96E4ADAC279C95093207');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const contactsFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-contacts-page', ['contacts.htm', 'placement=settings']);
        await contactsFrame.waitAll('@page-contacts');
        await Util.sleep(1);
        await contactsFrame.waitAndClick('@action-show-email-flowcryptcompatibilitygmailcom');
        await Util.sleep(1);
        const contacts = await contactsFrame.read('@page-contacts');
        expect(contacts).to.contain('5520 CACE 2CB6 1EA7 13E5 B005 7FDE 6855 48AE A788');
        expect(contacts).to.contain('E8F0 517B A6D7 DAB6 081C 96E4 ADAC 279C 9509 3207');
        await contactsFrame.waitAndClick('@action-remove-pubkey-5520CACE2CB61EA713E5B0057FDE685548AEA788-openpgp', {
          confirmGone: true,
        });
        await contactsFrame.waitAll('@page-contacts');
        await Util.sleep(1);
        const foundKeys1 = await dbPage.page.evaluate(async () => {
          /* eslint-disable @typescript-eslint/no-explicit-any */
          const db = await (window as any).ContactStore.dbOpen();
          const pubkey7FDE685548AEA788: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['pubkeys'], 'readonly');
            const req = tx.objectStore('pubkeys').get('5520CACE2CB61EA713E5B0057FDE685548AEA788');
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          const pubkeyADAC279C95093207: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['pubkeys'], 'readonly');
            const req = tx.objectStore('pubkeys').get('E8F0517BA6D7DAB6081C96E4ADAC279C95093207');
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          const contactsSize = (
            await (window as any).ContactStore.search(db, {
              hasPgp: true,
              substring: 'flowcrypt',
            })
          ).length;
          /* eslint-enable @typescript-eslint/no-explicit-any */
          return { pubkey7FDE685548AEA788, pubkeyADAC279C95093207, contactsSize };
        });
        expect(foundKeys1.contactsSize).to.equal(1);
        expect(foundKeys1.pubkey7FDE685548AEA788).to.be.an('undefined');
        expect(foundKeys1.pubkeyADAC279C95093207.fingerprint).to.equal('E8F0517BA6D7DAB6081C96E4ADAC279C95093207');
        await contactsFrame.waitAndClick('@action-show-email-flowcryptcompatibilitygmailcom');
        await Util.sleep(1);
        const contacts1 = await contactsFrame.read('@page-contacts');
        expect(contacts1).to.not.contain('5520 CACE 2CB6 1EA7 13E5 B005 7FDE 6855 48AE A788');
        expect(contacts1).to.contain('E8F0 517B A6D7 DAB6 081C 96E4 ADAC 279C 9509 3207');
        await contactsFrame.waitAndClick('@action-remove-pubkey-E8F0517BA6D7DAB6081C96E4ADAC279C95093207-openpgp', {
          confirmGone: true,
        });
        await contactsFrame.waitAll('@page-contacts');
        await Util.sleep(1);
        const foundKeys2 = await dbPage.page.evaluate(async () => {
          /* eslint-disable @typescript-eslint/no-explicit-any */
          const db = await (window as any).ContactStore.dbOpen();
          const pubkey7FDE685548AEA788: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['pubkeys'], 'readonly');
            const req = tx.objectStore('pubkeys').get('5520CACE2CB61EA713E5B0057FDE685548AEA788');
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          const pubkeyADAC279C95093207: { fingerprint: string } = await new Promise((resolve, reject) => {
            const tx = db.transaction(['pubkeys'], 'readonly');
            const req = tx.objectStore('pubkeys').get('E8F0517BA6D7DAB6081C96E4ADAC279C95093207');
            (window as any).ContactStore.setReqPipe(req, resolve, reject);
          });
          const contactsSize = (
            await (window as any).ContactStore.search(db, {
              hasPgp: true,
              substring: 'flowcrypt',
            })
          ).length;
          /* eslint-disable @typescript-eslint/no-explicit-any */
          return { pubkey7FDE685548AEA788, pubkeyADAC279C95093207, contactsSize };
        });
        expect(foundKeys2.contactsSize).to.equal(0);
        expect(foundKeys2.pubkey7FDE685548AEA788).to.be.an('undefined');
        expect(foundKeys2.pubkeyADAC279C95093207).to.be.an('undefined');
        await contactsFrame.waitTillGone('@action-show-email-flowcryptcompatibilitygmailcom');
        await SettingsPageRecipe.closeDialog(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'basic');
        await dbPage.close();
      })
    );
    test(
      'settings - my key page - primary + secondary',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.verifyMyKeyPage(settingsPage, 'flowcrypt.compatibility.1pp1', 'link', 0);
        await SettingsPageRecipe.verifyMyKeyPage(settingsPage, 'flowcrypt.compatibility.2pp1', 'link', 1);
      })
    );
    test(
      'settings - my key page - remove key',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.ready(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        await settingsPage.waitAll('@action-open-add-key-page');
        await settingsPage.waitAndClick('@action-remove-key-0');
        await settingsPage.waitAndRespondToModal(
          'confirm',
          'confirm',
          'Are you sure you want to remove encryption key with fingerprint E8F0 517B A6D7 DAB6 081C 96E4 ADAC 279C 9509 3207?'
        );
        await settingsPage.page.waitForNavigation({ waitUntil: 'networkidle0' });
        await Util.sleep(1);
        await settingsPage.waitAll('@action-open-add-key-page');
        await settingsPage.notPresent('@action-remove-key-0');
      })
    );
    test(
      'settings - my key page - generate key',
      testWithBrowser(async (t, browser) => {
        const acct = 'flowcrypt.compatibility@gmail.com';
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await SettingsPageRecipe.ready(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const addKeyPopup = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-add-key-page', ['add_key.htm']);
        await addKeyPopup.waitAndClick('@source-generate');
        const passphrase = 'long enough to suit requirements';
        await addKeyPopup.waitAndType('@input-step2bmanualcreate-passphrase-1', passphrase);
        await addKeyPopup.waitAndType('@input-step2bmanualcreate-passphrase-2', passphrase);
        // Uncheck backup_inbox to check if backup view correctly displayed
        await addKeyPopup.waitAndClick('@input-step2bmanualcreate-backup-inbox');
        await addKeyPopup.waitAndClick('@input-step2bmanualcreate-create-and-save');
        await addKeyPopup.waitAndClick('@input-backup-step3manual-no-backup'); // choose no_backup so that it doesn't affect other tests.
        await addKeyPopup.waitAndClick('@action-backup-step3manual-continue');
        await SettingsPageRecipe.ready(settingsPage);
        await settingsPage.waitAndClick('@action-remove-key-2'); // Delete newly generated key
        await SettingsPageRecipe.ready(settingsPage);
      })
    );
    test(
      'settings - my key page - privileged frames and action buttons should be hidden when using key manager test',
      testWithBrowser(async (t, browser) => {
        const acct = 'two.keys@key-manager-autogen.flowcrypt.test';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
          ekm: {
            keys: [twoKeys1, twoKeys2],
          },
          fes: {
            clientConfiguration: getKeyManagerAutogenRules(t.context.urls!.port!),
          },
        });
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acct);
        await SetupPageRecipe.autoSetupWithEKM(settingsPage);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        await settingsPage.waitForContent(`@container-key-status-59C63FE6952D93BC1EC9F9369332CCDBAE607602`, 'ACTIVE');
        // check imported key at index 1
        const myKeyFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, `@action-show-key-1`, ['my_key.htm', 'placement=settings']);
        await Util.sleep(1);
        await myKeyFrame.waitForContent(`@container-key-status-2601CB2E1902C007`, 'ACTIVE');
        await myKeyFrame.waitAll('@content-fingerprint');
        await myKeyFrame.notPresent('@action-update-prv');
        await myKeyFrame.notPresent('@action-revoke-certificate');
        await myKeyFrame.waitForContent('@label-download-prv', 'THIS PRIVATE KEY IS MANAGED BY EMAIL KEY MANAGER');
        await settingsPage.notPresent('@action-remove-key-0');
        const fingerprint = await myKeyFrame.readHtml('@content-fingerprint');
        // test for direct access at my_key_update.htm
        const myKeyUpdateFrame = await browser.newExtensionPage(
          t,
          `chrome/settings/modules/my_key_update.htm?placement=settings&acctEmail=${acct}&fingerprint=${fingerprint}&parentTabId=1`
        );
        await myKeyUpdateFrame.waitForContent('@container-err-title', 'Error: Insufficient Permission');
        // test for direct access at my add_key.htm
        const addKeyFrame = await browser.newExtensionPage(t, `chrome/settings/modules/add_key.htm?placement=settings&acctEmail=${acct}&parentTabId=1`);
        await addKeyFrame.waitForContent('@container-err-text', 'Please contact your IT staff if you wish to update your keys');
      })
    );
    test.todo('settings - edit contact public key');
    test(
      'settings - change passphrase - current in local storage',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const { acctEmail, settingsPage } = await BrowserRecipe.setUpFcPpChangeAcct(t, browser);
        const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
        await SettingsPageRecipe.changePassphrase(settingsPage, undefined, newPp); // change pp and test
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '16819bec18d4e011',
          content: ['changed correctly if this can be decrypted'],
        });
      })
    );
    test(
      'settings - change passphrase - current in session known',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const { acctEmail, passphrase, settingsPage } = await BrowserRecipe.setUpFcPpChangeAcct(t, browser);
        const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
        await SettingsPageRecipe.forgetAllPassPhrasesInStorage(settingsPage, passphrase);
        // decrypt msg and enter pp so that it's remembered in session
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '16819bec18d4e011',
          enterPp: {
            passphrase,
            isForgetPpChecked: true,
            isForgetPpHidden: false,
          },
          content: ['changed correctly if this can be decrypted'],
        });
        // change pp - should not ask for pp because already in session
        await SettingsPageRecipe.changePassphrase(settingsPage, undefined, newPp);
        // now it will remember the pass phrase so decrypts without asking
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '16819bec18d4e011',
          content: ['changed correctly if this can be decrypted'],
        });
        // test decrypt - should ask for new pass phrase
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '16819bec18d4e011',
          finishSessionBeforeTesting: true,
          enterPp: {
            passphrase: newPp,
            isForgetPpChecked: true,
            isForgetPpHidden: false,
          },
          content: ['changed correctly if this can be decrypted'],
        });
      })
    );
    test(
      'settings - change passphrase honoring FORBID_STORING_PASS_PHRASE ClientConfiguration',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'user@forbid-storing-passphrase-client-configuration.flowcrypt.test';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
          fes: {
            clientConfiguration: {
              flags: ['FORBID_STORING_PASS_PHRASE'],
            },
          },
        });
        const { settingsPage, passphrase } = await BrowserRecipe.setUpFcForbidPpStoringAcct(t, browser);
        const {
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A: savedPassphrase1,
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys: keys,
        } = await settingsPage.getFromLocalStorage([
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A',
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys',
        ]);
        expect((keys as KeyInfoWithIdentity[])[0].longid).to.equal('B8F687BCDE14435A');
        expect(savedPassphrase1).to.be.an('undefined');
        const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
        // decrypt msg, enter pp and make sure it's not stored to the local storage
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '179f6feb575df213',
          finishSessionBeforeTesting: true,
          enterPp: { passphrase, isForgetPpHidden: true, isForgetPpChecked: true },
          content: ['changed correctly if this can be decrypted'],
        });
        const { cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A: savedPassphrase2 } =
          await settingsPage.getFromLocalStorage(['cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A']);
        expect(savedPassphrase2).to.be.an('undefined');
        // change pp - should not ask for pp because already in session
        await SettingsPageRecipe.changePassphrase(settingsPage, undefined, newPp);
        const { cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A: savedPassphrase3 } =
          await settingsPage.getFromLocalStorage(['cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A']);
        expect(savedPassphrase3).to.be.an('undefined');
        // test decrypt - should not ask for pp because already in session
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '179f6feb575df213',
          content: ['changed correctly if this can be decrypted'],
        });
        // test decrypt - should ask for new pass phrase
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '179f6feb575df213',
          finishSessionBeforeTesting: true,
          enterPp: { passphrase: newPp, isForgetPpHidden: true, isForgetPpChecked: true },
          content: ['changed correctly if this can be decrypted'],
        });
      })
    );
    test(
      'settings - change passphrase - current in session unknown',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const { acctEmail, passphrase, settingsPage } = await BrowserRecipe.setUpFcPpChangeAcct(t, browser);
        const newPp = `temp ci test pp: ${Util.lousyRandom()}`;
        await SettingsPageRecipe.forgetAllPassPhrasesInStorage(settingsPage, passphrase);
        // pp wiped after switching to session - should be needed to change pp
        await SettingsPageRecipe.changePassphrase(settingsPage, passphrase, newPp);
        // now it will remember the pass phrase so decrypts without asking
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '16819bec18d4e011',
          content: ['changed correctly if this can be decrypted'],
        });
        // test decrypt - should ask for new pass phrase
        await InboxPageRecipe.checkDecryptMsg(t, browser, {
          acctEmail,
          threadId: '16819bec18d4e011',
          content: ['changed correctly if this can be decrypted'],
          finishSessionBeforeTesting: true,
          enterPp: { passphrase: newPp, isForgetPpChecked: true, isForgetPpHidden: false },
        });
      })
    );
    test(
      'settings - Catch.reportErr reports an error',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, 'flowcrypt.compatibility@gmail.com');
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const experimentalFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-module-experimental', ['experimental.htm']);
        await experimentalFrame.waitAndClick('@action-throw-err'); // mock tests will verify that err was reported to mock backend in `test.ts`
        internalTestState.expectIntentionalErrReport = true;
      })
    );
    test(
      'settings - Errors encountered during the addition/update of a private key should be handled properly',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const acct = 'flowcrypt.compatibility@gmail.com';
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acct);
        const keyCanBeFixedTestKey = testConstants.keyCanBeFixedTestKey;
        const longid = '9866DB9063926D73';
        await SetupPageRecipe.manualEnter(settingsPage, '', {
          fixKey: true,
          key: {
            title: '',
            armored: keyCanBeFixedTestKey,
            passphrase: 'hard to guess passphrase',
            longid,
          },
        });
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        await settingsPage.waitAndClick('@action-open-pubkey-page');
        const myKeyPage = await settingsPage.getFrame(['my_key.htm']);
        await myKeyPage.waitAndClick('@action-update-prv');
        await myKeyPage.waitAndClick('@source-paste');
        const invalidKeyFormat = 'non-valid-private-key-format';
        const invalidPrivateKeyBlock = '-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n\r\ninvalid-key\r\n-----END PGP PRIVATE KEY BLOCK-----';
        await myKeyPage.waitAndType('@input-prv-key', invalidKeyFormat);
        await myKeyPage.waitAndClick('@action-update-key');
        await myKeyPage.waitAndRespondToModal('warning', 'confirm', 'This does not appear to be a validly formatted key.');
        await myKeyPage.waitAndType('@input-prv-key', invalidPrivateKeyBlock);
        await myKeyPage.waitAndClick('@action-update-key');
        await myKeyPage.waitAndRespondToModal('error', 'confirm', 'An error happened when processing the key');
        await myKeyPage.waitAndType('@input-prv-key', keyCanBeFixedTestKey);
        await myKeyPage.waitAndType('@input-passphrase', 'hard to guess passphrase');
        await myKeyPage.waitAndClick('@action-update-key');
        await myKeyPage.waitAll('@input-compatibility-fix-expire-years', { timeout: 30 });
        await myKeyPage.selectOption('@input-compatibility-fix-expire-years', '1');
        await myKeyPage.waitAndClick('@action-fix-and-import-key');
        const { cryptup_flowcryptcompatibilitygmailcom_keys: keys } = await settingsPage.getFromLocalStorage(['cryptup_flowcryptcompatibilitygmailcom_keys']);
        const pubkey = await KeyUtil.parse((keys as KeyInfoWithIdentity[])[0].public);
        const expectedExpiration = new Date().getFullYear() + 1;
        const pubkeyExpiration = new Date(pubkey.expiration!).getFullYear();
        expect(pubkey.id.endsWith(longid)).to.equal(true);
        expect(pubkeyExpiration).to.equal(expectedExpiration);
      })
    );
    test(
      'settings - attachment previews are rendered according to their types',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const inboxPage = await browser.newExtensionPage(
          t,
          `chrome/settings/inbox/inbox.htm?acctEmail=flowcrypt.compatibility@gmail.com&threadId=174ab0ba9643b4fa`
        );
        // image
        const attachmentImage = await inboxPage.getFrame(['attachment.htm', 'name=tiny-face.png']);
        await attachmentImage.waitForSelTestState('ready');
        await attachmentImage.click('body');
        const attachmentPreviewImage = await inboxPage.getFrame(['attachment_preview.htm']);
        await attachmentPreviewImage.waitAll('#attachment-preview-container img.attachment-preview-img');
        await inboxPage.press('Escape');
        // text
        const attachmentText = await inboxPage.getFrame(['attachment.htm', 'name=small.txt']);
        await attachmentText.waitForSelTestState('ready');
        await attachmentText.click('body');
        const attachmentPreviewText = await inboxPage.getFrame(['attachment_preview.htm']);
        await attachmentPreviewText.waitForContent('#attachment-preview-container .attachment-preview-txt', 'small text file');
        await inboxPage.press('Escape');
        // pdf
        const attachmentPdf = await inboxPage.getFrame(['attachment.htm', 'name=small.pdf']);
        await attachmentPdf.waitForSelTestState('ready');
        await attachmentPdf.click('body');
        const attachmentPreviewPdf = await inboxPage.getFrame(['attachment_preview.htm']);
        await attachmentPreviewPdf.waitAll('#attachment-preview-container.attachment-preview-pdf .attachment-preview-pdf-page');
        await inboxPage.press('Escape');
        // no preview
        const attachmentOther = await inboxPage.getFrame(['attachment.htm', 'name=unknown']);
        await attachmentOther.waitForSelTestState('ready');
        await attachmentOther.click('body');
        const attachmentPreviewOther = await inboxPage.getFrame(['attachment_preview.htm']);
        await attachmentPreviewOther.waitForContent('#attachment-preview-container .attachment-preview-unavailable', 'No preview available');
        await attachmentPreviewOther.waitAll('#attachment-preview-container .attachment-preview-unavailable #attachment-preview-download');
      })
    );
    test(
      'settings - #5408 PDF files downloaded correctly from attachment previews',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const inboxPage = await browser.newExtensionPage(
          t,
          `chrome/settings/inbox/inbox.htm?acctEmail=flowcrypt.compatibility@gmail.com&threadId=174ab0ba9643b4fa`
        );
        const pdfFileName = 'small.pdf';
        const attachmentPdf = await inboxPage.getFrame(['attachment.htm', `name=${pdfFileName}`]);
        await attachmentPdf.waitForSelTestState('ready');
        await attachmentPdf.click('body');
        const attachmentPreviewPdf = await inboxPage.getFrame(['attachment_preview.htm']);
        await attachmentPreviewPdf.waitAll('#attachment-preview-container.attachment-preview-pdf .attachment-preview-pdf-page');

        const downloadedPdf = await inboxPage.awaitDownloadTriggeredByClicking(async () => {
          await attachmentPreviewPdf.waitAndClick('@attachment-preview-download');
        });
        expect(Object.entries(downloadedPdf).length).to.equal(1);
        expect(Object.keys(downloadedPdf)[0]).to.equal(pdfFileName);
        expect(downloadedPdf[pdfFileName].length).to.equal(15218);
      })
    );
    test(
      'settings - attachment previews with entering pass phrase',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const settingsPage = await browser.newExtensionSettingsPage(t, 'flowcrypt.compatibility@gmail.com');
        const k = Config.key('flowcrypt.compatibility.1pp1');
        await SettingsPageRecipe.forgetAllPassPhrasesInStorage(settingsPage, k.passphrase);
        const inboxPage = await browser.newExtensionPage(
          t,
          `chrome/settings/inbox/inbox.htm?acctEmail=flowcrypt.compatibility@gmail.com&threadId=174ab0ba9643b4fa`
        );
        const attachmentImage = await inboxPage.getFrame(['attachment.htm', 'name=tiny-face.png']);
        await attachmentImage.waitForSelTestState('ready');
        await attachmentImage.click('body');
        const passphraseDialog = await inboxPage.getFrame(['passphrase.htm']);
        await passphraseDialog.waitAndType('@input-pass-phrase', k.passphrase);
        await passphraseDialog.waitAndClick('@action-confirm-pass-phrase-entry');
        const attachmentPreviewImage = await inboxPage.getFrame(['attachment_preview.htm']);
        await attachmentPreviewImage.waitAll('#attachment-preview-container img.attachment-preview-img');
      })
    );
    test(
      'settings - inbox - show original',
      testWithBrowser(async (t, browser) => {
        const threadId = '15f7f5e966792203'; // signed inline
        const { acctEmail } = await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const inboxPage = await browser.newExtensionPage(t, `chrome/settings/inbox/inbox.htm?acctEmail=${acctEmail}&threadId=${threadId}`);
        await inboxPage.waitForSelTestState('ready');
        await inboxPage.waitAll('iframe');
        expect((await inboxPage.getFramesUrls(['pgp_block.htm'])).length).to.equal(1);
        expect(await inboxPage.read('@message-line')).to.not.contain('BEGIN');
        expect(await inboxPage.read('@see-original')).to.equal('SEE ORIGINAL');

        // switch to original
        await inboxPage.waitForNavigationIfAny(() => inboxPage.waitAndClick('@see-original'));
        await inboxPage.waitForSelTestState('ready');
        await inboxPage.waitAll('iframe');
        // expect no pgp blocks
        expect((await inboxPage.getFramesUrls(['pgp_block.htm'])).length).to.equal(0);
        expect(await inboxPage.read('@message-line')).to.contain('BEGIN');
        expect(await inboxPage.read('@see-original')).to.equal('SEE DECRYPTED');

        // switch back to decrypted
        await inboxPage.waitForNavigationIfAny(() => inboxPage.waitAndClick('@see-original'));
        await inboxPage.waitForSelTestState('ready');
        await inboxPage.waitAll('iframe');
        expect((await inboxPage.getFramesUrls(['pgp_block.htm'])).length).to.equal(1);
        expect(await inboxPage.read('@message-line')).to.not.contain('BEGIN');
        expect(await inboxPage.read('@see-original')).to.equal('SEE ORIGINAL');
      })
    );
    test(
      'settings - pgp/mime preview and download attachment',
      testWithBrowser(async (t, browser) => {
        const { authHdr } = await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        const checkPage = async (page: ControllablePage, withPreview: boolean) => {
          const pgpBlockFrame = await page.getFrame(['pgp_block.htm']);
          await pgpBlockFrame.waitAll('.download-attachment');

          let downloadedFiles: Dict<Buffer>;
          if (withPreview) {
            await pgpBlockFrame.waitAndClick('.preview-attachment');
            const attachmentPreviewImage = await page.getFrame(['attachment_preview.htm']);
            await attachmentPreviewImage.waitAll('#attachment-preview-container img.attachment-preview-img');
            downloadedFiles = await attachmentPreviewImage.awaitDownloadTriggeredByClicking(() =>
              attachmentPreviewImage.waitAndClick('@attachment-preview-download')
            );
          } else {
            downloadedFiles = await pgpBlockFrame.awaitDownloadTriggeredByClicking(() => pgpBlockFrame.waitAndClick('@download-attachment-0'));
          }

          expect(Object.keys(downloadedFiles)).contains('7 years.jpeg');
          await page.close();
        };
        const msgId = '16e8b01f136c3d28';
        for (const withPreview of [true, false]) {
          await checkPage(await browser.newPage(t, `${t.context.urls?.mockGmailUrl()}/${msgId}`, undefined, authHdr), withPreview);
          await checkPage(
            await browser.newExtensionPage(t, `chrome/settings/inbox/inbox.htm?acctEmail=flowcrypt.compatibility@gmail.com&threadId=${msgId}`),
            withPreview
          );
        }
      })
    );
    const checkIfFileDownloadsCorrectly = async (t: AvaContext, browser: BrowserHandle, threadId: string, fileName: string) => {
      const inboxPage = await browser.newExtensionPage(t, `chrome/settings/inbox/inbox.htm?acctEmail=flowcrypt.compatibility@gmail.com&threadId=${threadId}`);
      const attachment = await inboxPage.getFrame(['attachment.htm']);
      const downloadedFiles = await inboxPage.awaitDownloadTriggeredByClicking(async () => {
        await attachment.waitAndClick('@download-attachment');
      });
      expect(Object.keys(downloadedFiles)).contains(fileName);
      await inboxPage.close();
    };
    test(
      'settings - check if downloaded attachment name is correct',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'compatibility');
        // `what's up?.txt` becomes `what's_up_.txt` and this is native way and we can't change this logic
        // https://github.com/FlowCrypt/flowcrypt-browser/issues/3505#issuecomment-812269422
        await checkIfFileDownloadsCorrectly(t, browser, '188721aebb71c16c', "what's_up_.txt");
        await checkIfFileDownloadsCorrectly(t, browser, '188722a157fd54a8', `what's_up%253F.txt`);
        // should not strip .gpg or .pgp extension when downloading original file after unsuccesssful decryption
        // // Check if bad pgp attachment file got downloaded with original file name
        await checkIfFileDownloadsCorrectly(t, browser, '18610f7f4ae8da0a', 'test.bat.pgp');
      })
    );
    test(
      'settings - add unprotected key',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        await SettingsPageRecipe.addKeyTest(
          t,
          browser,
          'ci.tests.gmail@flowcrypt.test',
          testConstants.unprotectedPrvKey,
          'this is a new passphrase to protect previously unprotected key',
          { isSavePassphraseChecked: true, isSavePassphraseHidden: false }
        );
      })
    );
    test(
      'settings - add unprotected s/mime key',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const unprotectedPrvKey = fs.readFileSync('test/samples/smime/human-unprotected-pem.txt', 'utf8');
        await SettingsPageRecipe.addKeyTest(
          t,
          browser,
          'ci.tests.gmail@flowcrypt.test',
          unprotectedPrvKey,
          'this is a new passphrase to protect previously unprotected key',
          { isSavePassphraseChecked: true, isSavePassphraseHidden: false }
        );
      })
    );
    test(
      'settings - error modal when page parameter invalid',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setupCommonAcctWithAttester(t, browser, 'ci.tests.gmail');
        const invalidParamModalPage = await browser.newExtensionPage(t, `chrome/settings/index.htm?acctEmail=ci.tests.gmail@flowcrypt.test&page=invalid`);
        await Util.sleep(3);
        await invalidParamModalPage.waitForContent('.swal2-html-container', 'An unexpected value was found for the page parameter');
      })
    );
    test(
      'settings - my key page - update non-first private key',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultiple98acfa1eadab5b92, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        const settingsPage = await browser.newExtensionSettingsPage(t, acctEmail);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        // open key at index 1
        const myKeyFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, `@action-show-key-1`, ['my_key.htm', 'placement=settings']);
        await Util.sleep(1);
        await myKeyFrame.waitAll('@content-fingerprint');
        await myKeyFrame.waitAndClick('@action-update-prv');
        await myKeyFrame.waitAndClick('@source-paste');
        await myKeyFrame.waitAndType('@input-prv-key', testConstants.testKeyMultiple98acfa1eadab5b92);
        await myKeyFrame.type('@input-passphrase', '1234');
        await myKeyFrame.waitAndClick('@action-update-key');
        await PageRecipe.waitForModalAndRespond(myKeyFrame, 'confirm', {
          contentToCheck: 'Public and private key updated locally',
          clickOn: 'cancel',
        });
        const { cryptup_flowcrypttestkeymultiplegmailcom_passphrase_98ACFA1EADAB5B92: savedPassphrase } = await settingsPage.getFromLocalStorage([
          'cryptup_flowcrypttestkeymultiplegmailcom_passphrase_98ACFA1EADAB5B92',
        ]);
        expect(savedPassphrase).to.equal('1234');
        await settingsPage.close();
      })
    );
    test(
      'settings - my key page - update private key from file',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const dbPage = await browser.newExtensionPage(t, 'chrome/dev/ci_unit_test.htm');
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              // eslint-disable-next-line no-null/no-null
              armored: null,
              filePath: 'test/samples/openpgp/flowcrypttestkeymultiplegmailcom-0x98acfa1eadab5b92-original.asc',
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        // test the pubkey in the storage
        const oldContact = await dbPage.page.evaluate(async acctEmail => {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-return
          return await (window as any).ContactStore.getOneWithAllPubkeys(undefined, acctEmail);
        }, acctEmail);
        expect(oldContact.sortedPubkeys.length).to.equal(1);
        expect((oldContact.sortedPubkeys as PubkeyInfoWithLastCheck[])[0].pubkey.lastModified).to.equal(1610024667000);
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const myKeyFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, `@action-show-key-0`, ['my_key.htm', 'placement=settings']);
        await Util.sleep(1);
        await myKeyFrame.waitAll('@content-fingerprint');
        await myKeyFrame.waitAndClick('@action-update-prv');
        {
          const [fileChooser] = await Promise.all([settingsPage.page.waitForFileChooser(), myKeyFrame.waitAndClick('@source-file', { retryErrs: true })]);
          await fileChooser.accept(['test/samples/openpgp/flowcrypttestkeymultiplegmailcom-0x98acfa1eadab5b92-updated-userid-issue.key']); // binary key
        }
        await myKeyFrame.type('@input-passphrase', '1234');
        await myKeyFrame.waitAndClick('@action-update-key');
        await myKeyFrame.waitAll('@input-compatibility-fix-expire-years', {
          timeout: 30,
        });
        await myKeyFrame.selectOption('@input-compatibility-fix-expire-years', '1');
        await myKeyFrame.waitAndClick('@action-fix-and-import-key');
        // test the pubkey in the storage
        const expectedOldContact = await dbPage.page.evaluate(async acctEmail => {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-return
          return await (window as any).ContactStore.getOneWithAllPubkeys(undefined, acctEmail);
        }, acctEmail);
        expect(expectedOldContact.sortedPubkeys.length).to.equal(1);
        expect((expectedOldContact.sortedPubkeys as PubkeyInfoWithLastCheck[])[0].pubkey.lastModified).to.equal(1610024667000);
        await settingsPage.waitAndClick('@action-open-pubkey-page');
        const myKeyFrame2 = await settingsPage.getFrame(['my_key.htm']);
        await myKeyFrame2.waitAndClick('@action-update-prv');
        {
          const [fileChooser] = await Promise.all([settingsPage.page.waitForFileChooser(), myKeyFrame2.waitAndClick('@source-file', { retryErrs: true })]);
          await fileChooser.accept(['test/samples/openpgp/flowcrypttestkeymultiplegmailcom-0x98acfa1eadab5b92-updated.key']); // binary key
        }
        await myKeyFrame2.type('@input-passphrase', '1234');
        await myKeyFrame2.waitAndClick('@action-update-key');
        await PageRecipe.waitForModalAndRespond(myKeyFrame2, 'confirm', {
          contentToCheck: 'Public and private key updated locally',
          clickOn: 'cancel',
        });
        // test the pubkey in the storage
        const newContact = await dbPage.page.evaluate(async acctEmail => {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-return
          return await (window as any).ContactStore.getOneWithAllPubkeys(undefined, acctEmail);
        }, acctEmail);
        expect(newContact.sortedPubkeys.length).to.equal(1);
        const newPubkey = (newContact.sortedPubkeys as PubkeyInfoWithLastCheck[])[0].pubkey;
        expect(newPubkey.lastModified).to.equal(1689250647000);
        // we now have two uids
        expect(newPubkey.identities).to.eql(['Additional Name <flowcrypt.test@example.com>', 'flowcrypt.test.key.multiple@gmail.com']);
        expect(newPubkey.emails).to.eql(['flowcrypt.test@example.com', 'flowcrypt.test.key.multiple@gmail.com']);
        await settingsPage.close();
        await dbPage.close();
      })
    );
    test(
      'settings - my key page - revocation certificate',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const myKeyFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, `@action-show-key-0`, ['my_key.htm', 'placement=settings']);
        await Util.sleep(1);
        await myKeyFrame.waitAll('@content-fingerprint');
        await myKeyFrame.waitAndClick('@action-revoke-certificate');
        const downloadedFiles = await myKeyFrame.awaitDownloadTriggeredByClicking(() =>
          PageRecipe.waitForModalAndRespond(myKeyFrame, 'confirm', {
            contentToCheck: 'Would you like to generate and save a revocation cert now?',
            clickOn: 'confirm',
          })
        );
        const entries = Object.entries(downloadedFiles);
        expect(entries.length).to.equal(1);
        const [filename, data] = entries[0];
        expect(filename.endsWith('revocation-cert.asc')).to.be.true;
        expect(data.toString()).to.include('Comment: This is a revocation certificate');
        await settingsPage.close();
      })
    );
    test(
      'settings - manual backup several keys to file with the same pass phrase',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultiple98acfa1eadab5b92, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultipleSmimeCEA2D53BB9D24871, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultipleSmimeA35068FD4E037879, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        // opening backup.htm independently of settings/index.htm page limits functionality but sufficient for this test
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}&action=backup_manual&parentTabId=1%3A0`
        );
        // OpenPGP keys are checked, x509 keys are unchecked
        expect(await backupPage.isChecked('[data-id="47FB03183E03A8ED44E3BBFCCEA2D53BB9D24871"]')).to.equal(false);
        expect(await backupPage.isChecked('[data-id="5A08466253C956E9C76C2E95A35068FD4E037879"]')).to.equal(false);
        expect(await backupPage.isChecked('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(true);
        expect(await backupPage.isChecked('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(true);
        // OpenPGP keys are enabled, x509 keys are disabled
        expect(await backupPage.isDisabled('[data-id="47FB03183E03A8ED44E3BBFCCEA2D53BB9D24871"]')).to.equal(true);
        expect(await backupPage.isDisabled('[data-id="5A08466253C956E9C76C2E95A35068FD4E037879"]')).to.equal(true);
        expect(await backupPage.isDisabled('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(false);
        expect(await backupPage.isDisabled('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(false);
        await backupPage.waitAndClick('@input-backup-step3manual-file');
        await backupPage.waitAndClick('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]'); // uncheck
        // backing up to file when only one key is checked
        const backupFileRawData1 = await backupPage.awaitDownloadTriggeredByClicking('@action-backup-step3manual-continue');
        const { keys: keys1 } = await KeyUtil.readMany(
          Buf.fromUtfStr(backupFileRawData1['flowcrypt-backup-flowcrypttestkeymultiplegmailcom-515431151DDD3EA232B37A4C98ACFA1EADAB5B92.asc'].toString())
        );
        expect(keys1.length).to.equal(1);
        expect(keys1[0].id).to.equal('515431151DDD3EA232B37A4C98ACFA1EADAB5B92');
        await backupPage.waitAndRespondToModal('info', 'confirm', 'Downloading private key backup file');
        await backupPage.waitAndRespondToModal('info', 'confirm', 'Your private key has been successfully backed up');
        await backupPage.waitAndClick('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]'); // check
        // backing up to file when two keys are checked
        const backupFileRawData2 = await backupPage.awaitDownloadTriggeredByClicking('@action-backup-step3manual-continue', 2);
        const { keys: keys2 } = await KeyUtil.readMany(Buf.fromUtfStr(Buf.concat(Object.values(backupFileRawData2)).toUtfStr()));
        expect(keys2.length).to.equal(2);
        await backupPage.close();
      })
    );
    test(
      'settings - manual backup several keys to inbox with the same strong pass phrase',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple.inbox2@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const passphrase = 'strong enough passphrase for all keys';
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        const key1b383d0334e38b28 = await KeyUtil.parse(testConstants.testKeyMultiple1b383d0334e38b28);
        expect(await KeyUtil.decrypt(key1b383d0334e38b28, '1234')).to.equal(true);
        await KeyUtil.encrypt(key1b383d0334e38b28, passphrase);
        const key98acfa1eadab5b92 = await KeyUtil.parse(testConstants.testKeyMultiple98acfa1eadab5b92);
        expect(await KeyUtil.decrypt(key98acfa1eadab5b92, '1234')).to.equal(true);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: { title: '?', armored: KeyUtil.armor(key1b383d0334e38b28), passphrase, longid: '1b383d0334e38b28' },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, KeyUtil.armor(key98acfa1eadab5b92), passphrase, {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        // opening backup.htm independently of settings/index.htm page limits functionality but sufficient for this test
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}&action=backup_manual&parentTabId=1%3A0`
        );
        expect(await backupPage.isChecked('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(true);
        expect(await backupPage.isChecked('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(true);
        expect(await backupPage.isDisabled('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(false);
        expect(await backupPage.isDisabled('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(false);
        await backupPage.waitAndClick('@action-backup-step3manual-continue');
        await backupPage.waitAndRespondToModal('info', 'confirm', 'Your private keys have been successfully backed up');
        const sentMsg = (await GoogleData.withInitializedData(acctEmail)).searchMessagesBySubject('Your FlowCrypt Backup')[0];

        const mimeMsg = await Parse.convertBase64ToMimeMsg(sentMsg.raw!);
        const { keys } = await KeyUtil.readMany(Buf.concat(mimeMsg.attachments.map(a => a.content)));
        expect(keys.length).to.equal(2);
        await backupPage.close();
      })
    );
    test(
      'settings - manual backup several keys to file with a missing but guessed pass phrase',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage.close();
        const inboxPage = await browser.newExtensionPage(t, `chrome/settings/inbox/inbox.htm?acctEmail=${acctEmail}`);
        await BrowserRecipe.finishSession(inboxPage);
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultiple98acfa1eadab5b92, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        // opening backup.htm independently of settings/index.htm page limits functionality but sufficient for this test
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}` + `&action=backup_manual&parentTabId=1%3A0`
        );
        expect(await backupPage.isChecked('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(true);
        expect(await backupPage.isChecked('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(true);
        expect(await backupPage.isDisabled('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(false);
        expect(await backupPage.isDisabled('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(false);
        await backupPage.waitAndClick('@input-backup-step3manual-file');
        // one passphrase is not known but successfully guessed
        const downloadedFiles = await backupPage.awaitDownloadTriggeredByClicking('@action-backup-step3manual-continue', 2);
        expect(Object.keys(downloadedFiles).length).to.equal(2);

        const { keys: keys1 } = await KeyUtil.readMany(
          Buf.fromUtfStr(downloadedFiles['flowcrypt-backup-flowcrypttestkeymultiplegmailcom-515431151DDD3EA232B37A4C98ACFA1EADAB5B92.asc'].toString())
        );
        expect(keys1.length).to.equal(1);
        const { keys: keys2 } = await KeyUtil.readMany(
          Buf.fromUtfStr(downloadedFiles['flowcrypt-backup-flowcrypttestkeymultiplegmailcom-515431151DDD3EA232B37A4C98ACFA1EADAB5B92.asc'].toString())
        );
        expect(keys2.length).to.equal(1);
        await backupPage.close();
      })
    );
    test(
      'settings - manual backup several keys to inbox with a missing pass phrase',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        const inboxPage = await browser.newExtensionPage(t, `chrome/settings/inbox/inbox.htm?acctEmail=${acctEmail}`);
        await BrowserRecipe.finishSession(inboxPage);
        await inboxPage.close();
        const key98acfa1eadab5b92 = await KeyUtil.parse(testConstants.testKeyMultiple98acfa1eadab5b92);
        expect(await KeyUtil.decrypt(key98acfa1eadab5b92, '1234')).to.equal(true);
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, KeyUtil.armor(key98acfa1eadab5b92), 'new passphrase strong enough', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        await settingsPage.waitAndClick('@action-open-backup-page');
        const backupFrame = await settingsPage.getFrame(['backup.htm']);
        await backupFrame.waitAndClick('@action-go-manual');
        expect(await backupFrame.isChecked('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(true);
        expect(await backupFrame.isChecked('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(true);
        expect(await backupFrame.isDisabled('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(false);
        expect(await backupFrame.isDisabled('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(false);
        await backupFrame.waitAndClick('@action-backup-step3manual-continue');
        await backupFrame.waitAndRespondToModal('error', 'confirm', 'Your keys are protected with different pass phrases');
        await settingsPage.close();
      })
    );
    test(
      'settings - manual backup a key with a missing pass phrase',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        const key = {
          title: '?',
          armored: testConstants.testKeyMultiple1b383d0334e38b28,
          passphrase: '1234',
          longid: '1b383d0334e38b28',
        };
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'unused',
          { submitPubkey: false, usedPgpBefore: false, key },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        const inboxPage = await browser.newExtensionPage(t, `chrome/settings/inbox/inbox.htm?acctEmail=${acctEmail}`);
        await BrowserRecipe.finishSession(inboxPage);
        await inboxPage.close();
        await settingsPage.waitAndClick('@action-open-backup-page');
        const backupFrame = await settingsPage.getFrame(['backup.htm']);
        await backupFrame.waitAndClick('@action-go-manual');
        await backupFrame.waitAndClick('@action-backup-step3manual-continue');
        const ppFrame = await settingsPage.getFrame(['passphrase.htm']);
        await ppFrame.waitAndType('@input-pass-phrase', key.passphrase);
        await ppFrame.waitAndClick('@action-confirm-pass-phrase-entry');
        await Util.sleep(2);
        expect(ppFrame.frame.detached).to.equal(true);
        // todo: #4059 we would expect further iteraction with backupFrame here but it is actually wiped out
        await settingsPage.close();
      })
    );
    test(
      'settings - manual backup several keys to file with different pass phrases',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        const key98acfa1eadab5b92 = await KeyUtil.parse(testConstants.testKeyMultiple98acfa1eadab5b92);
        expect(await KeyUtil.decrypt(key98acfa1eadab5b92, '1234')).to.equal(true);
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, KeyUtil.armor(key98acfa1eadab5b92), 'new passphrase strong enough', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        // opening backup.htm independently of settings/index.htm page limits functionality but sufficient for this test
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}&action=backup_manual&parentTabId=1%3A0`
        );
        expect(await backupPage.isChecked('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(true);
        expect(await backupPage.isChecked('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(true);
        expect(await backupPage.isDisabled('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(false);
        expect(await backupPage.isDisabled('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(false);
        await backupPage.waitAndClick('@input-backup-step3manual-file');
        await backupPage.waitAndClick('@action-backup-step3manual-continue');
        await backupPage.waitAndRespondToModal('error', 'confirm', 'Your keys are protected with different pass phrases');
        await backupPage.close();
      })
    );
    test(
      'settings - setup_manual only backs up supplied key to file',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultiple98acfa1eadab5b92, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}&action=backup_manual&parentTabId=1%3A0` +
            '&type=openpgp&id=515431151DDD3EA232B37A4C98ACFA1EADAB5B92&idToken=fakeheader.01'
        );
        await backupPage.waitAndClick('@input-backup-step3manual-file');
        const downloadedFiles = await backupPage.awaitDownloadTriggeredByClicking('@action-backup-step3manual-continue');
        const { keys } = await KeyUtil.readMany(
          Buf.fromUtfStr(downloadedFiles['flowcrypt-backup-flowcrypttestkeymultiplegmailcom-515431151DDD3EA232B37A4C98ACFA1EADAB5B92.asc'].toString())
        );
        expect(keys.length).to.equal(1);
        expect(keys[0].id).to.equal('515431151DDD3EA232B37A4C98ACFA1EADAB5B92');
        await backupPage.waitAndRespondToModal('info', 'confirm', 'Downloading private key backup file');
        await backupPage.close();
      })
    );
    test(
      'settings - setup_manual only backs up supplied key to inbox',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'flowcrypt.test.key.multiple.inbox1@gmail.com';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        const passphrase = 'strong enough passphrase for inbox backup';
        const key98acfa1eadab5b92 = await KeyUtil.parse(testConstants.testKeyMultiple98acfa1eadab5b92);
        expect(await KeyUtil.decrypt(key98acfa1eadab5b92, '1234')).to.equal(true);
        await KeyUtil.encrypt(key98acfa1eadab5b92, passphrase);
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, KeyUtil.armor(key98acfa1eadab5b92), passphrase, {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}&action=backup_manual&parentTabId=17%3A0` +
            '&type=openpgp&id=515431151DDD3EA232B37A4C98ACFA1EADAB5B92&idToken=fakeheader.01'
        );
        await backupPage.waitAndClick('@action-backup-step3manual-continue');
        await backupPage.waitAndRespondToModal('info', 'confirm', 'Your private key has been successfully backed up');

        const sentMsg = (await GoogleData.withInitializedData(acctEmail)).searchMessagesBySubject('Your FlowCrypt Backup')[0];

        const mimeMsg = await Parse.convertBase64ToMimeMsg(sentMsg.raw!);
        const { keys } = await KeyUtil.readMany(new Buf(mimeMsg.attachments[0].content));
        expect(keys.length).to.equal(1);
        expect(KeyUtil.identityEquals(keys[0], { id: '515431151DDD3EA232B37A4C98ACFA1EADAB5B92', family: 'openpgp' })).to.equal(true);
        await backupPage.close();
      })
    );
    test(
      'settings - manual backup to inbox keys with weak pass phrases results in error',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
        });
        const acctEmail = 'flowcrypt.test.key.multiple@gmail.com';
        const settingsPage1 = await BrowserRecipe.openSettingsLoginApprove(t, browser, acctEmail);
        await SetupPageRecipe.manualEnter(
          settingsPage1,
          'unused',
          {
            submitPubkey: false,
            usedPgpBefore: false,
            key: {
              title: '?',
              armored: testConstants.testKeyMultiple1b383d0334e38b28,
              passphrase: '1234',
              longid: '1b383d0334e38b28',
            },
          },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        await settingsPage1.close();
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultiple98acfa1eadab5b92, '1234', {
          isSavePassphraseChecked: true,
          isSavePassphraseHidden: false,
        });
        // opening backup.htm independently of settings/index.htm page limits functionality but sufficient for this test
        const backupPage = await browser.newExtensionPage(
          t,
          `/chrome/settings/modules/backup.htm?acctEmail=${acctEmail}&action=backup_manual&parentTabId=1%3A0`
        );
        expect(await backupPage.isChecked('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(true);
        expect(await backupPage.isChecked('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(true);
        expect(await backupPage.isDisabled('[data-id="CB0485FE44FC22FF09AF0DB31B383D0334E38B28"]')).to.equal(false);
        expect(await backupPage.isDisabled('[data-id="515431151DDD3EA232B37A4C98ACFA1EADAB5B92"]')).to.equal(false);
        await backupPage.waitAndClick('@action-backup-step3manual-continue');
        await backupPage.waitAndRespondToModal('warning', 'confirm', `It's too weak for this backup method`);
        await Util.sleep(2);
        await backupPage.waitAny('@action-show-confirm-new-pp');
        await backupPage.close();
      })
    );
    test(
      'settings - manual enter and key update honor FORBID_STORING_PASS_PHRASE ClientConfiguration',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
          fes: {
            clientConfiguration: {
              flags: ['FORBID_STORING_PASS_PHRASE'],
            },
          },
        });
        const { settingsPage, passphrase } = await BrowserRecipe.setUpFcForbidPpStoringAcct(t, browser);
        const {
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A: savedPassphrase1,
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys: keys,
        } = await settingsPage.getFromLocalStorage([
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A',
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys',
        ]);
        expect(savedPassphrase1).to.be.an('undefined');
        expect((keys as KeyInfoWithIdentity[])[0].longid).to.equal('B8F687BCDE14435A');
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        // open key at index 0
        const myKeyFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, `@action-show-key-0`, ['my_key.htm', 'placement=settings']);
        await Util.sleep(1);
        await myKeyFrame.waitAll('@content-fingerprint');
        await myKeyFrame.waitAndClick('@action-update-prv');
        await myKeyFrame.waitAndClick('@source-paste');
        await myKeyFrame.waitAndType('@input-prv-key', testConstants.testKeyB8F687BCDE14435A);
        await myKeyFrame.type('@input-passphrase', passphrase);
        await myKeyFrame.waitAndClick('@action-update-key');
        await PageRecipe.waitForModalAndRespond(myKeyFrame, 'confirm', {
          contentToCheck: 'Public and private key updated locally',
          clickOn: 'cancel',
        });
        const { cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A: savedPassphrase2 } =
          await settingsPage.getFromLocalStorage(['cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A']);
        expect(savedPassphrase2).to.be.an('undefined');
        await settingsPage.close();
      })
    );
    test(
      'settings - email change',
      testWithBrowser(async (t, browser) => {
        const acct1 = 'ci.tests.gmail@flowcrypt.test';
        const acct2 = 'user@default-remember-passphrase-client-configuration.flowcrypt.test';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {
              [acct1]: {
                pubkey: somePubkey,
              },
            },
          },
          fes: {
            clientConfiguration: {
              flags: [],
            },
          },
        });
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const settingsPage = await browser.newExtensionSettingsPage(t, acct1);
        const { cryptup_citestsgmailflowcrypttest_rules: oldRules, cryptup_citestsgmailflowcrypttest_passphrase_07481C8ACF9D49FE: savedPassphrase1 } =
          await settingsPage.getFromLocalStorage(['cryptup_citestsgmailflowcrypttest_rules', 'cryptup_citestsgmailflowcrypttest_passphrase_07481C8ACF9D49FE']);
        expect(savedPassphrase1).not.to.be.an('undefined');
        expect((oldRules as { flags: string[] }).flags).not.to.include('DEFAULT_REMEMBER_PASS_PHRASE');
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const experimentalFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-module-experimental', ['experimental.htm']);
        await experimentalFrame.waitAndClick('@action-change-email');
        const oauthPopup1 = await browser.newPageTriggeredBy(t, () =>
          PageRecipe.waitForModalAndRespond(experimentalFrame, 'confirm', {
            contentToCheck: 'email address has changed',
            clickOn: 'confirm',
          })
        );
        t.context.mockApi!.configProvider.config.fes!.clientConfiguration = {
          flags: ['DEFAULT_REMEMBER_PASS_PHRASE'],
        };
        await OauthPageRecipe.mock(t, oauthPopup1, acct2, 'override_acct');
        await PageRecipe.waitForModalAndRespond(experimentalFrame, 'confirm', {
          contentToCheck: 'email from ci.tests.gmail@flowcrypt.test to user@default-remember-passphrase-client-configuration.flowcrypt.test',
          clickOn: 'confirm',
        });
        const newSettingsPage = await browser.newPageTriggeredBy(t, () =>
          PageRecipe.waitForModalAndRespond(experimentalFrame, 'info', {
            contentToCheck: 'Email address changed to user@default-remember-passphrase-client-configuration.flowcrypt.test',
            clickOn: 'confirm',
          })
        );
        await Util.sleep(2);
        // await PageRecipe.waitForModalAndRespond(?, 'confirm',
        //   { contentToCheck: 'Your email aliases on Gmail have refreshed since the last time you used FlowCrypt', clickOn: 'confirm' });
        const {
          cryptup_userdefaultrememberpassphraseclientconfigurationflowcrypttest_rules: newRules,
          cryptup_userdefaultrememberpassphraseclientconfigurationflowcrypttest_passphrase_07481C8ACF9D49FE: savedPassphrase2,
          cryptup_userdefaultrememberpassphraseclientconfigurationflowcrypttest_keys: keys,
        } = await settingsPage.getFromLocalStorage([
          'cryptup_userdefaultrememberpassphraseclientconfigurationflowcrypttest_rules',
          'cryptup_userdefaultrememberpassphraseclientconfigurationflowcrypttest_passphrase_07481C8ACF9D49FE',
          'cryptup_userdefaultrememberpassphraseclientconfigurationflowcrypttest_keys',
        ]);
        expect((newRules as { flags: string[] }).flags).to.include('DEFAULT_REMEMBER_PASS_PHRASE');
        expect((keys as KeyInfoWithIdentity[])[0].longid).to.equal('07481C8ACF9D49FE');
        expect(savedPassphrase2).not.to.be.an('undefined');
        await newSettingsPage.close();
        await settingsPage.close();
      })
    );
    test(
      'settings - ensure gracious behavior & ui should remain functional when updating client configuration',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
          ekm: {
            keys: [testConstants.existingPrv],
          },
          fes: {
            clientConfiguration: getKeyManagerAutogenRules(t.context.urls!.port!),
          },
        });
        const port = t.context.urls?.port;
        const domain = 'settings.flowcrypt.test';
        const acct = `test-update@${domain}`;
        const rulesKey = `cryptup_${emailKeyIndex(acct, 'rules')}`;
        const setupPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acct);
        await SetupPageRecipe.autoSetupWithEKM(setupPage);
        const clientConfiguration1 = (await setupPage.getFromLocalStorage([rulesKey]))[rulesKey] as FesClientConfiguration;
        expect(clientConfiguration1.flags).to.eql([
          'NO_PRV_BACKUP',
          'ENFORCE_ATTESTER_SUBMIT',
          'PRV_AUTOIMPORT_OR_AUTOGEN',
          'PASS_PHRASE_QUIET_AUTOGEN',
          'DEFAULT_REMEMBER_PASS_PHRASE',
        ]);
        expect(clientConfiguration1.disallow_attester_search_for_domains).to.eql([]);
        expect(clientConfiguration1.enforce_keygen_algo).to.equal('rsa2048');
        expect(clientConfiguration1.key_manager_url).to.equal(`https://localhost:${port}/flowcrypt-email-key-manager`);
        const accessToken = await BrowserRecipe.getGoogleAccessToken(setupPage, acct);
        await setupPage.close();
        // Set invalid client configuration and check if it ensures gracious behavior & ui remain functional
        t.context.mockApi!.configProvider.config.fes!.clientConfiguration = {
          // flags is required but don't return it (to mock invalid client configuration)
          key_manager_url: `https://localhost:${port}/flowcrypt-email-key-manager`, // eslint-disable-line @typescript-eslint/naming-convention
        };
        const extraAuthHeaders = { Authorization: `Bearer ${accessToken}` }; // eslint-disable-line @typescript-eslint/naming-convention
        const gmailPage = await browser.newMockGmailPage(t, extraAuthHeaders);
        const errorMsg = 'Failed to update FlowCrypt Client Configuration: Missing client configuration flags.';
        await PageRecipe.waitForToastToAppearAndDisappear(gmailPage, errorMsg);
        // Ensure previous client configuration remains same
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        await PageRecipe.waitForToastToAppearAndDisappear(settingsPage, errorMsg);
        const clientConfiguration2 = (await settingsPage.getFromLocalStorage([rulesKey]))[rulesKey] as FesClientConfiguration;
        expect(clientConfiguration2.flags).to.eql([
          'NO_PRV_BACKUP',
          'ENFORCE_ATTESTER_SUBMIT',
          'PRV_AUTOIMPORT_OR_AUTOGEN',
          'PASS_PHRASE_QUIET_AUTOGEN',
          'DEFAULT_REMEMBER_PASS_PHRASE',
        ]);
        expect(clientConfiguration2.disallow_attester_search_for_domains).to.eql([]);
        expect(clientConfiguration2.enforce_keygen_algo).to.equal('rsa2048');
        expect(clientConfiguration2.key_manager_url).to.equal(`https://localhost:${port}/flowcrypt-email-key-manager`);
      })
    );
    test(
      'settings - client configuration gets updated on settings and content script reloads',
      testWithBrowser(async (t, browser) => {
        const port = t.context.urls?.port;
        /* eslint-disable @typescript-eslint/naming-convention */
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
          ekm: {
            keys: [testConstants.existingPrv],
          },
          fes: {
            clientConfiguration: {
              flags: ['NO_PRV_BACKUP', 'ENFORCE_ATTESTER_SUBMIT', 'PRV_AUTOIMPORT_OR_AUTOGEN', 'PASS_PHRASE_QUIET_AUTOGEN', 'DEFAULT_REMEMBER_PASS_PHRASE'],
              // custom_keyserver_url: undefined,
              key_manager_url: `https://localhost:${port}/flowcrypt-email-key-manager`,
              // allow_attester_search_only_for_domains: undefined,
              disallow_attester_search_for_domains: ['disallowed_domain1.test', 'disallowed_domain2.test'],
              enforce_keygen_algo: 'rsa2048',
              // enforce_keygen_expire_months: undefined
            },
          },
        });
        /* eslint-enable @typescript-eslint/naming-convention */
        const domain = 'test1.settings.flowcrypt.test';
        const acct = `settings@${domain}`;
        const rulesKey = `cryptup_${emailKeyIndex(acct, 'rules')}`;
        const setupPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, acct);
        await SetupPageRecipe.autoSetupWithEKM(setupPage);
        const clientConfiguration1 = (await setupPage.getFromLocalStorage([rulesKey]))[rulesKey] as FesClientConfiguration;
        expect(clientConfiguration1.flags).to.eql([
          'NO_PRV_BACKUP',
          'ENFORCE_ATTESTER_SUBMIT',
          'PRV_AUTOIMPORT_OR_AUTOGEN',
          'PASS_PHRASE_QUIET_AUTOGEN',
          'DEFAULT_REMEMBER_PASS_PHRASE',
        ]);
        expect(clientConfiguration1.allow_attester_search_only_for_domains).to.be.an.undefined;
        expect(clientConfiguration1.disallow_attester_search_for_domains).to.eql(['disallowed_domain1.test', 'disallowed_domain2.test']);
        expect(clientConfiguration1.enforce_keygen_algo).to.equal('rsa2048');
        expect(clientConfiguration1.enforce_keygen_expire_months).to.be.an.undefined;
        expect(clientConfiguration1.custom_keyserver_url).to.be.an.undefined;
        expect(clientConfiguration1.key_manager_url).to.equal(`https://localhost:${port}/flowcrypt-email-key-manager`);
        await setupPage.close();
        // modify the setup
        /* eslint-disable @typescript-eslint/naming-convention */
        t.context.mockApi!.configProvider.config.fes!.clientConfiguration = {
          flags: ['NO_ATTESTER_SUBMIT', 'HIDE_ARMOR_META', 'DEFAULT_REMEMBER_PASS_PHRASE'],
          custom_keyserver_url: `https://localhost:${port}`,
          // key_manager_url: undefined,
          allow_attester_search_only_for_domains: ['allowed_domain1.test', 'allowed_domain2.test'],
          // disallow_attester_search_for_domains: undefined
          // enforce_keygen_algo: undefined
          enforce_keygen_expire_months: 12,
        };
        /* eslint-enable @typescript-eslint/naming-convention */
        // open the settings page
        const settingsPage = await browser.newExtensionSettingsPage(t, acct);
        const clientConfiguration2 = (await settingsPage.getFromLocalStorage([rulesKey]))[rulesKey] as FesClientConfiguration;
        // check that the configuration in the storage has been updated
        expect(clientConfiguration2.flags).to.eql(['NO_ATTESTER_SUBMIT', 'HIDE_ARMOR_META', 'DEFAULT_REMEMBER_PASS_PHRASE']);
        expect(clientConfiguration2.custom_keyserver_url).to.equal(`https://localhost:${port}`);
        expect(clientConfiguration2.key_manager_url).to.be.an.undefined;
        expect(clientConfiguration2.allow_attester_search_only_for_domains).to.eql(['allowed_domain1.test', 'allowed_domain2.test']);
        expect(clientConfiguration2.disallow_attester_search_for_domains).to.be.an.undefined;
        expect(clientConfiguration2.enforce_keygen_algo).to.be.an.undefined;
        expect(clientConfiguration2.enforce_keygen_expire_months).to.equal(12);
        const accessToken = await BrowserRecipe.getGoogleAccessToken(settingsPage, acct);
        // keep settingsPage open to re-read the storage later via it
        // re-configure the setup again
        /* eslint-disable @typescript-eslint/naming-convention */
        t.context.mockApi!.configProvider.config.fes!.clientConfiguration = {
          flags: ['NO_PRV_BACKUP', 'ENFORCE_ATTESTER_SUBMIT', 'PRV_AUTOIMPORT_OR_AUTOGEN', 'PASS_PHRASE_QUIET_AUTOGEN', 'DEFAULT_REMEMBER_PASS_PHRASE'],
          // custom_keyserver_url: undefined,
          key_manager_url: `https://localhost:${port}/flowcrypt-email-key-manager`,
          // allow_attester_search_only_for_domains: undefined,
          disallow_attester_search_for_domains: [],
          enforce_keygen_algo: 'rsa3072',
          // enforce_keygen_expire_months: undefined
        };
        const extraAuthHeaders = { Authorization: `Bearer ${accessToken}` };
        /* eslint-enable @typescript-eslint/naming-convention */
        let gmailPage = await browser.newMockGmailPage(t, extraAuthHeaders);
        await Util.sleep(3);
        // read the local storage from via the extension's own page (settings)
        const clientConfiguration3 = (await settingsPage.getFromLocalStorage([rulesKey]))[rulesKey] as FesClientConfiguration;
        // check that the configuration in the storage has been updated
        expect(clientConfiguration3.flags).to.eql([
          'NO_PRV_BACKUP',
          'ENFORCE_ATTESTER_SUBMIT',
          'PRV_AUTOIMPORT_OR_AUTOGEN',
          'PASS_PHRASE_QUIET_AUTOGEN',
          'DEFAULT_REMEMBER_PASS_PHRASE',
        ]);
        expect(clientConfiguration3.allow_attester_search_only_for_domains).to.be.an.undefined;
        expect(clientConfiguration3.disallow_attester_search_for_domains).to.eql([]);
        expect(clientConfiguration3.enforce_keygen_algo).to.equal('rsa3072');
        expect(clientConfiguration3.enforce_keygen_expire_months).to.be.an.undefined;
        expect(clientConfiguration3.custom_keyserver_url).to.be.an.undefined;
        expect(clientConfiguration3.key_manager_url).to.equal(`https://localhost:${port}/flowcrypt-email-key-manager`);
        await gmailPage.close();
        // configure an error
        t.context.mockApi!.configProvider.config.fes!.returnError = new HttpClientErr('Test error', Status.BAD_REQUEST);
        gmailPage = await browser.newMockGmailPage(t, extraAuthHeaders);
        await PageRecipe.waitForToastToAppearAndDisappear(
          gmailPage,
          'Failed to update FlowCrypt Client Configuration: ' +
            `BrowserMsg(ajax) Bad Request: 400 when GET-ing https://localhost:${port}/shared-tenant-fes/api/v1/client-configuration?domain=${domain} (no body)`
        );
        await gmailPage.close();
        // check that the configuration hasn't changed
        const clientConfiguration4 = (await settingsPage.getFromLocalStorage([rulesKey]))[rulesKey] as FesClientConfiguration;
        // check that the configuration in the storage has been updated
        expect(clientConfiguration4.flags).to.eql([
          'NO_PRV_BACKUP',
          'ENFORCE_ATTESTER_SUBMIT',
          'PRV_AUTOIMPORT_OR_AUTOGEN',
          'PASS_PHRASE_QUIET_AUTOGEN',
          'DEFAULT_REMEMBER_PASS_PHRASE',
        ]);
        expect(clientConfiguration4.allow_attester_search_only_for_domains).to.be.an.undefined;
        expect(clientConfiguration4.disallow_attester_search_for_domains).to.eql([]);
        expect(clientConfiguration4.enforce_keygen_algo).to.equal('rsa3072');
        expect(clientConfiguration4.enforce_keygen_expire_months).to.be.an.undefined;
        expect(clientConfiguration4.custom_keyserver_url).to.be.an.undefined;
        expect(clientConfiguration4.key_manager_url).to.equal(`https://localhost:${port}/flowcrypt-email-key-manager`);
        await settingsPage.close();
      })
    );
    test(
      'settings - email change to account that has FORBID_STORING_PASS_PHRASE',
      testWithBrowser(async (t, browser) => {
        const acct1 = 'ci.tests.gmail@flowcrypt.test';
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {
              [acct1]: {
                pubkey: somePubkey,
              },
            },
          },
          fes: {
            clientConfiguration: {
              flags: [],
            },
          },
        });
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const acct2 = 'user@forbid-storing-passphrase-client-configuration.flowcrypt.test';
        const settingsPage = await browser.newExtensionSettingsPage(t, acct1);
        const { cryptup_citestsgmailflowcrypttest_rules: oldRules, cryptup_citestsgmailflowcrypttest_passphrase_07481C8ACF9D49FE: savedPassphrase1 } =
          await settingsPage.getFromLocalStorage(['cryptup_citestsgmailflowcrypttest_rules', 'cryptup_citestsgmailflowcrypttest_passphrase_07481C8ACF9D49FE']);
        expect(savedPassphrase1).not.to.be.an('undefined');
        expect((oldRules as { flags: string[] }).flags).not.to.include('FORBID_STORING_PASS_PHRASE');
        await SettingsPageRecipe.toggleScreen(settingsPage, 'additional');
        const experimentalFrame = await SettingsPageRecipe.awaitNewPageFrame(settingsPage, '@action-open-module-experimental', ['experimental.htm']);
        await experimentalFrame.waitAndClick('@action-change-email');
        const oauthPopup1 = await browser.newPageTriggeredBy(t, () =>
          PageRecipe.waitForModalAndRespond(experimentalFrame, 'confirm', {
            contentToCheck: 'email address has changed',
            clickOn: 'confirm',
          })
        );
        t.context.mockApi!.configProvider.config.fes!.clientConfiguration = {
          flags: ['FORBID_STORING_PASS_PHRASE'],
        };
        await OauthPageRecipe.mock(t, oauthPopup1, acct2, 'override_acct');
        await PageRecipe.waitForModalAndRespond(experimentalFrame, 'confirm', {
          contentToCheck: 'email from ci.tests.gmail@flowcrypt.test to user@forbid-storing-passphrase-client-configuration.flowcrypt.test',
          clickOn: 'confirm',
        });
        const newSettingsPage = await browser.newPageTriggeredBy(t, () =>
          PageRecipe.waitForModalAndRespond(experimentalFrame, 'info', {
            contentToCheck: 'Email address changed to user@forbid-storing-passphrase-client-configuration.flowcrypt.test',
            clickOn: 'confirm',
          })
        );
        await Util.sleep(2);
        // await PageRecipe.waitForModalAndRespond(?, 'confirm',
        //   { contentToCheck: 'Your email aliases on Gmail have refreshed since the last time you used FlowCrypt', clickOn: 'confirm' });
        const {
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_rules: newRules,
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys: keys,
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_07481C8ACF9D49FE: savedPassphrase2,
        } = await settingsPage.getFromLocalStorage([
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_rules',
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys',
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_07481C8ACF9D49FE',
        ]);
        expect((newRules as { flags: string[] }).flags).to.include('FORBID_STORING_PASS_PHRASE');
        expect((keys as KeyInfoWithIdentity[])[0].longid).to.equal('07481C8ACF9D49FE');
        expect(savedPassphrase2).to.be.an('undefined');
        await newSettingsPage.close();
        await settingsPage.close();
      })
    );
    test(
      'settings - adding a key honors FORBID_STORING_PASS_PHRASE ClientConfiguration',
      testWithBrowser(async (t, browser) => {
        t.context.mockApi!.configProvider = new ConfigurationProvider({
          attester: {
            pubkeyLookup: {},
          },
          fes: {
            clientConfiguration: {
              flags: ['FORBID_STORING_PASS_PHRASE'],
            },
          },
        });
        const { acctEmail, settingsPage } = await BrowserRecipe.setUpFcForbidPpStoringAcct(t, browser);
        const {
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A: savedPassphrase1,
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys: keys1,
        } = await settingsPage.getFromLocalStorage([
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_B8F687BCDE14435A',
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys',
        ]);
        expect((keys1 as KeyInfoWithIdentity[])[0].longid).to.equal('B8F687BCDE14435A');
        expect(savedPassphrase1).to.be.an('undefined');
        await SettingsPageRecipe.addKeyTest(t, browser, acctEmail, testConstants.testKeyMultiple98acfa1eadab5b92, '1234', {
          isSavePassphraseChecked: false,
          isSavePassphraseHidden: true,
        });
        const {
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_98ACFA1EADAB5B92: savedPassphrase2,
          cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys: keys2,
        } = await settingsPage.getFromLocalStorage([
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_passphrase_98ACFA1EADAB5B92',
          'cryptup_userforbidstoringpassphraseclientconfigurationflowcrypttest_keys',
        ]);
        expect((keys2 as KeyInfoWithIdentity[]).map(ki => ki.longid)).to.include.members(['B8F687BCDE14435A', '98ACFA1EADAB5B92']);
        expect(savedPassphrase2).to.be.an('undefined');
      })
    );
    test.todo('settings - change passphrase - mismatch curent pp');
    test.todo('settings - change passphrase - mismatch new pp');
  }
};
