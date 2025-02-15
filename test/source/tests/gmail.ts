/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import test from 'ava';

import { expect } from 'chai';
import { BrowserHandle, ControllablePage, TIMEOUT_PAGE_LOAD } from './../browser';
import { Controllable } from './../browser/controllable';
import { TestUrls } from './../browser/test-urls';
import { TestWithBrowser } from './../test';
import { TestVariant, Util } from './../util';
import { ComposePageRecipe } from './page-recipe/compose-page-recipe';
import { GmailPageRecipe } from './page-recipe/gmail-page-recipe';
import { SetupPageRecipe } from './page-recipe/setup-page-recipe';
import { AvaContext, minutes } from './tooling';
import { BrowserRecipe } from './tooling/browser-recipe';

/**
 * All tests that use mail.google.com or have to operate without a Gmail API mock should go here
 */

export type GmailCategory = 'inbox' | 'sent' | 'drafts' | 'spam' | 'trash'; // 'all';

export const defineGmailTests = (testVariant: TestVariant, testWithBrowser: TestWithBrowser) => {
  if (testVariant === 'CONSUMER-LIVE-GMAIL') {
    const pageHasSecureReplyContainer = async (
      t: AvaContext,
      browser: BrowserHandle,
      gmailPage: ControllablePage,
      {
        // Check if compose frame(secure reply frame) has reply prompt
        isReplyPromptAccepted,
        // Compose Frame(Secure reply container) index. Default is 0 because "secure reply compose container" is located higher than the other "reply or forward buttons" container
        composeFrameIndex,
        // Total compose frame count
        composeFrameCount,
      }: {
        isReplyPromptAccepted?: boolean;
        composeFrameIndex?: number;
        composeFrameCount?: number;
      } = {}
    ) => {
      const urls = await gmailPage.getFramesUrls(['/chrome/elements/compose.htm'], { sleep: 0 });
      expect(urls.length).to.equal(composeFrameCount ?? 1);
      if (typeof isReplyPromptAccepted !== 'undefined') {
        const replyBox = await gmailPage.getFrame([urls[composeFrameIndex ?? 0]]);
        if (isReplyPromptAccepted) {
          await replyBox.waitAll('@action-send');
          await replyBox.notPresent('@action-accept-reply-prompt');
        } else {
          await replyBox.waitAll('@action-accept-reply-prompt');
          await replyBox.notPresent('@action-send');
        }
      }
    };

    const createSecureDraft = async (
      t: AvaContext,
      browser: BrowserHandle,
      gmailPage: ControllablePage,
      content: string,
      params: { offline: boolean } = { offline: false }
    ) => {
      let composeBox: Controllable | undefined;
      if (params.offline) {
        // TODO(@limonte): for some reason iframe is able to save the draft to the cloud even
        // after gmailPage.page.setOfflineMode(true) is called. Probably, the puppeteer issue, revisit.
        // const composeBoxFrame = await gmailPage.getFrame(['/chrome/elements/compose.htm']);
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/compose.htm'], { sleep: 1 });
        composeBox = await browser.newPage(t, urls[0]);
        await composeBox.page.setOfflineMode(true); // go offline mode
      } else {
        composeBox = await gmailPage.getFrame(['/chrome/elements/compose.htm']);
      }
      await composeBox.click('@input-body');
      await Util.sleep(1);
      await composeBox.type('@input-body', content, true);
      if (params.offline) {
        await ComposePageRecipe.waitWhenDraftIsSavedLocally(composeBox);
        await (composeBox as ControllablePage).close();
      } else {
        await ComposePageRecipe.waitWhenDraftIsSaved(composeBox);
      }
    };

    const pageHasSecureDraft = async (gmailPage: ControllablePage, expectedContent?: string) => {
      const secureDraftFrame = await gmailPage.getFrame(['/chrome/elements/compose.htm', '&draftId=']);
      if (expectedContent) {
        await secureDraftFrame.waitForContent('@input-body', expectedContent);
      } else {
        await secureDraftFrame.waitAll('@input-body');
      }
      return secureDraftFrame;
    };

    const pageDoesNotHaveSecureReplyContainer = async (gmailPage: ControllablePage) => {
      const urls = await gmailPage.getFramesUrls(['/chrome/elements/compose.htm'], { sleep: 0 });
      expect(urls.length).to.equal(0);
    };

    const openGmailPage = async (t: AvaContext, browser: BrowserHandle): Promise<ControllablePage> => {
      const url = TestUrls.gmail(0);
      return await browser.newPage(t, url);
    };

    const gotoGmailPage = async (gmailPage: ControllablePage, path: string, category: GmailCategory = 'inbox') => {
      const url = TestUrls.gmail(0, path, category);
      await Util.sleep(1);
      await gmailPage.goto(url);
    };

    test(
      'mail.google.com/chat',
      testWithBrowser(async (t, browser) => {
        const settingsPage = await BrowserRecipe.openSettingsLoginButCloseOauthWindowBeforeGrantingPermission(t, browser, 'ci.tests.gmail@flowcrypt.dev');
        await settingsPage.close();
        const googleChatPage = await BrowserRecipe.openGoogleChatPage(t, browser);
        await googleChatPage.notPresent(BrowserRecipe.oldAndNewComposeButtonSelectors); // compose button should not be injected
      })
    );

    test(
      'mail.google.com - send rich-text encrypted message',
      testWithBrowser(
        async (t, browser) => {
          const acctEmail = 'ci.tests.gmail@flowcrypt.dev';
          await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
          const gmailPage = await BrowserRecipe.openGmailPageAndVerifyComposeBtnPresent(t, browser);
          const composePage = await GmailPageRecipe.openSecureComposeWithRichTextWorkaround(t, gmailPage, browser);
          const subject = `New Rich Text Message ${Util.lousyRandom()}`;
          await ComposePageRecipe.fillMsg(composePage, { to: acctEmail }, subject, undefined, {
            richtext: true,
          });
          await ComposePageRecipe.sendAndClose(composePage);
          await GmailPageRecipe.expandMainMenuIfNeeded(gmailPage);
          await gmailPage.waitAndClick('[aria-label^="Inbox"]');
          await gmailPage.waitAndClick('[role="row"]:first-of-type'); // click the first message
          await gmailPage.waitForContent('.nH h2.hP', `Automated puppeteer test: ${subject}`);
          const urls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_block.htm'], { sleep: 1 });
          await GmailPageRecipe.deleteThread(gmailPage);
          expect(urls.length).to.eq(1);
        },
        undefined,
        minutes(6) // explicitly set timer-controlled timeout
      )
    );

    test(
      'mail.google.com - back button works in offline mode',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDWztBnnCgRHzjrvmFqLtcJD');
        const expectedMessage = { content: ['this should decrypt even offline'], signature: 'signed', encryption: 'encrypted' };
        await BrowserRecipe.pgpBlockCheck(t, await gmailPage.getFrame(['/chrome/elements/pgp_block.htm'], { sleep: 10, timeout: 25 }), expectedMessage);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDRNgcQxLmkhBCKVSFwkfdvV'); // plain convo
        await gmailPage.page.setOfflineMode(true); // go offline mode
        await gmailPage.page.goBack({ waitUntil: 'load' });
        await BrowserRecipe.pgpBlockCheck(t, await gmailPage.getFrame(['/chrome/elements/pgp_block.htm']), expectedMessage);
      })
    );

    test(
      'mail.google.com - rendering attachments',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDXBWBWBfVKHssLtMqvDQSWN');
        await gmailPage.waitForContent('.aVW span:first-child', '36');
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/attachment.htm']);
        expect(urls.length).to.equal(36);
      })
    );

    test(
      'mail.google.com - msg.asc message content renders',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/QgrcJHrtqfgLGKqwChjKsHKzZQpwRHMBqpG');
        await gmailPage.waitAll('@action-show-original-conversation');
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_block.htm'], { sleep: 10, appearIn: 25 });
        expect(urls.length).to.equal(1);
        const pgpBlockFrame = await gmailPage.getFrame(['pgp_block.htm']);
        await BrowserRecipe.pgpBlockCheck(t, pgpBlockFrame, {
          content: ['test that content from msg.asc renders'],
          encryption: 'encrypted',
          signature: 'not signed',
        });
        await pageHasSecureReplyContainer(t, browser, gmailPage);
        expect(await gmailPage.isElementVisible('.aQH')).to.equal(false); // original attachment container(s) should be hidden
      })
    );

    test(
      'mail.google.com - Thunderbird signature [html] is recognized',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDZKPJrNLplXZhKfWwtgjrXt');
        // validate pgp_block.htm is rendered
        const pgpBlockUrls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_block.htm'], {
          sleep: 10,
          appearIn: 25,
        });
        expect(pgpBlockUrls.length).to.equal(1);
        const pgpBlockFrame = await gmailPage.getFrame([pgpBlockUrls[0]]);
        await BrowserRecipe.pgpBlockCheck(t, pgpBlockFrame, {
          content: ['1234'],
          encryption: 'not encrypted',
          signature: 'signed',
        });
        await pageHasSecureReplyContainer(t, browser, gmailPage);
        await testMinimumElementHeight(gmailPage, '.pgp_block.signedDetached', 80);
        await testMinimumElementHeight(gmailPage, '.pgp_block.publicKey', 120);
        const pubkeyPage = await gmailPage.getFrame(['/chrome/elements/pgp_pubkey.htm']);
        await pubkeyPage.waitForContent('@container-pgp-pubkey', 'Fingerprint: 50B7 A032 B5E1 FBAB 24BA B205 B362 45FD AC2F BF3D');
        expect(await gmailPage.isElementVisible('.aQH')).to.equal(false); // original attachment container(s) should be hidden
      })
    );

    test(
      'mail.google.com - Thunderbird signature [plain] is recognized + correct height',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDZKPKzSnGtGKZrPZSbTBNnB');
        // validate pgp_block.htm is rendered
        const pgpBlockUrls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_block.htm'], {
          sleep: 10,
          appearIn: 25,
        });
        expect(pgpBlockUrls.length).to.equal(1);
        await testMinimumElementHeight(gmailPage, '.pgp_block.signedDetached', 80);
        await testMinimumElementHeight(gmailPage, '.pgp_block.publicKey', 120);
        const pgpBlockFrame = await gmailPage.getFrame([pgpBlockUrls[0]]);
        await BrowserRecipe.pgpBlockCheck(t, pgpBlockFrame, {
          content: ['1234'],
          encryption: 'not encrypted',
          signature: 'signed',
        });
        await pageHasSecureReplyContainer(t, browser, gmailPage);
        const pubkeyPage = await gmailPage.getFrame(['/chrome/elements/pgp_pubkey.htm']);
        await pubkeyPage.waitForContent('@container-pgp-pubkey', 'Fingerprint: 50B7 A032 B5E1 FBAB 24BA B205 B362 45FD AC2F BF3D');
        expect(await gmailPage.isElementVisible('.aQH')).to.equal(false); // original attachment container(s) should be hidden
      })
    );

    test(
      'mail.google.com - pubkey gets rendered with new signed and encrypted Thunderbird signature',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDZKPLBqWFzbgWqCrplTQdNz');
        const pgpBlockFrame = await gmailPage.getFrame(['pgp_block.htm'], { sleep: 10, timeout: 25 });
        await BrowserRecipe.pgpBlockCheck(t, pgpBlockFrame, {
          content: ['Encrypted Subject: [ci.test] Thunderbird html signed + encrypted', '1234'],
          encryption: 'encrypted',
          signature: 'signed',
        });
        await pageHasSecureReplyContainer(t, browser, gmailPage);
        const pubkeyPage = await gmailPage.getFrame(['/chrome/elements/pgp_pubkey.htm']);
        await pubkeyPage.waitForContent('@container-pgp-pubkey', 'Fingerprint: 50B7 A032 B5E1 FBAB 24BA B205 B362 45FD AC2F BF3D');
        expect(await gmailPage.isElementVisible('.aQH')).to.equal(false); // original attachment container(s) should be hidden
      })
    );

    // draft-sensitive test
    // fails in 'master' too, should be fixed in separate PR
    test.skip(
      'mail.google.com - saving and rendering compose drafts when offline',
      testWithBrowser(
        async (t, browser) => {
          await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
          t.timeout(minutes(6)); // extend ava's timeout
          const gmailPage = await openGmailPage(t, browser);
          // create compose draft
          await gmailPage.waitAndClick('@action-secure-compose', { delay: 1 });
          await createSecureDraft(t, browser, gmailPage, 'compose draft 1', { offline: true });
          await gmailPage.waitAndClick('@action-secure-compose', { delay: 1 });
          await createSecureDraft(t, browser, gmailPage, 'compose draft 2', { offline: true });
          await gmailPage.reload({ timeout: TIMEOUT_PAGE_LOAD * 1000, waitUntil: 'load' });
          await GmailPageRecipe.expandMainMenuIfNeeded(gmailPage);
          await gmailPage.waitAndClick('[data-tooltip="Drafts"]');
          await gmailPage.waitForContent('#fc_offline_drafts', 'FlowCrypt offline drafts:');
          await gmailPage.ensureElementsCount('#fc_offline_drafts a', 2);
          await gmailPage.waitAndClick('#fc_offline_drafts a:first-of-type');
          // compose draft 2 should be first in list as drafts are sorted by date descending
          const draft = await pageHasSecureDraft(gmailPage, 'compose draft 2');
          await draft.type('@input-body', 'trigger saving a draft to the cloud', true);
          await ComposePageRecipe.waitWhenDraftIsSaved(draft);
          // after draft 2 is saved to the cloud, it should be removed from offline drafts
          await gmailPage.reload({ timeout: TIMEOUT_PAGE_LOAD * 1000, waitUntil: 'load' });
          await gmailPage.waitForContent('#fc_offline_drafts', 'FlowCrypt offline drafts:');
          await gmailPage.ensureElementsCount('#fc_offline_drafts a', 1);
          await gmailPage.waitAndClick('#fc_offline_drafts a');
          await pageHasSecureDraft(gmailPage, 'compose draft 1');
        },
        undefined,
        minutes(6) // explicitly set timer-controlled timeout
      )
    );

    // convo-sensitive, draft-sensitive test
    test.serial(
      'mail.google.com - secure reply btn, reply draft',
      testWithBrowser(
        async (t, browser) => {
          await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
          const gmailPage = await openGmailPage(t, browser);
          const threadId = '181d226b4e69f172'; // 1st message -- thread id
          await gotoGmailPage(gmailPage, `/${threadId}`); // go to encrypted convo
          t.timeout(minutes(4)); // extend ava's timeout
          await GmailPageRecipe.trimConvo(gmailPage, threadId);
          await gmailPage.waitAndClick('@secure-reply-button');
          let replyBox = await gmailPage.getFrame(['/chrome/elements/compose.htm'], { sleep: 5 });
          await Util.sleep(3);
          expect(await replyBox.read('@recipients-preview')).to.equal('e2e.enterprise.test@flowcrypt.com');
          await createSecureDraft(t, browser, gmailPage, 'reply draft');
          await createSecureDraft(t, browser, gmailPage, 'offline reply draft', { offline: true });
          t.timeout(minutes(4)); // extend ava's timeout
          await gmailPage.reload({ timeout: TIMEOUT_PAGE_LOAD * 1000, waitUntil: 'load' }, true);
          replyBox = await pageHasSecureDraft(gmailPage, 'offline reply draft');
          await Util.sleep(2);
          await replyBox.waitAndClick('@action-send', { confirmGone: true });
          await Util.sleep(2);
          await gmailPage.reload({ timeout: TIMEOUT_PAGE_LOAD * 1000, waitUntil: 'load' }, true);
          await gmailPage.waitAndClick('.h7:last-child .ajz', { delay: 1 }); // the small triangle which toggles the message details
          await gmailPage.waitForContent('.h7:last-child .ajA', 'Re: [ci.test] encrypted email for reply render'); // make sure that the subject of the sent draft is corrent
          await GmailPageRecipe.trimConvo(gmailPage, threadId);
        },
        undefined,
        minutes(7) // this test often takes more than 5 minutes
      )
    );

    // draft-sensitive test
    test.serial(
      'mail.google.com - multiple compose windows, saving/opening compose draft',
      testWithBrowser(
        async (t, browser) => {
          await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
          t.timeout(minutes(4)); // extend ava's timeout
          const gmailPage = await openGmailPage(t, browser);
          // create compose draft
          await gmailPage.waitAndClick('@action-secure-compose', { delay: 1 });
          await createSecureDraft(t, browser, gmailPage, 'a compose draft');
          await gmailPage.reload({ timeout: TIMEOUT_PAGE_LOAD * 1000, waitUntil: 'load' });
          t.timeout(minutes(4)); // extend ava's timeout
          await gotoGmailPage(gmailPage, '', 'drafts'); // to go drafts section
          // open new compose window and saved draft
          await gmailPage.waitAndClick('@action-secure-compose', { delay: 1 });
          await gmailPage.waitAndClick('//*[text()="Draft"]');
          await Util.sleep(2);
          // verify that there are two compose windows: new compose window and secure draft
          const urls = await gmailPage.getFramesUrls(['/chrome/elements/compose.htm'], { sleep: 1 });
          expect(urls.length).to.equal(2);
          await pageHasSecureDraft(gmailPage, 'compose draft');
          // try to open 4 compose windows at the same time
          await gmailPage.waitAndClick('@action-secure-compose', { delay: 1 });
          await gmailPage.waitAndClick('@action-secure-compose', { delay: 1 });
          await gmailPage.waitForContent('.ui-toast-title', 'Only 3 FlowCrypt windows can be opened at a time');
        },
        undefined,
        minutes(6) // the test usually takes around 4 minutes
      )
    );

    test(
      'mail.google.com - plain message contains smart replies',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await Util.sleep(1);
        await gotoGmailPage(gmailPage, '/FMfcgzGpHHKCrKRLptBSNwkpMxzkdcQc'); // plain convo with smart replies
        await gmailPage.waitForContent('.brb', 'Yes');
      })
    );

    test(
      'mail.google.com - plain reply to encrypted and signed messages',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDRNgcQxLmkhBCKVSFwkfdvV'); // plain convo
        await gmailPage.waitAndClick('[data-tooltip="Reply"]', { delay: 1 });
        await gotoGmailPage(gmailPage, '/181d226b4e69f172'); // go to encrypted convo
        await gmailPage.waitAndClick('[data-tooltip="Reply"]', { delay: 1 });
        await gmailPage.waitTillGone('.reply_message');
        await gmailPage.waitAll('[data-tooltip^="Send"]'); // The Send button from the Standard reply box
        await gmailPage.waitForContent(
          '.reply_message_evaluated .error_notification',
          'The last message was encrypted, but you are composing a reply without encryption.'
        );
        await gmailPage.waitAndClick('[data-tooltip="Secure Reply"]'); // Switch to encrypted reply
        await gmailPage.waitAll('.reply_message');
        await pageHasSecureReplyContainer(t, browser, gmailPage, { isReplyPromptAccepted: true });
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDRNpjDdNvCrwzqvXspZZxvh'); // go to signed convo
        await gmailPage.waitAndClick('[data-tooltip="Reply"]', { delay: 1 });
        await gmailPage.waitTillGone('.reply_message');
        await gmailPage.waitAll('[data-tooltip^="Send"]'); // The Send button from the Standard reply box
        await gmailPage.notPresent('.reply_message_evaluated .error_notification'); // should not show the warning about switching to encrypted reply
      })
    );

    // https://github.com/FlowCrypt/flowcrypt-browser/issues/5906
    test(
      'mail.google.com - Keep original reply message when switching to secure mode',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGqRGfPBbNLWvfPvDbxnHBwkdGf'); // plain convo
        await Util.sleep(30);
        await gmailPage.waitAndClick('[role="listitem"] .adf.ads', { delay: 1 }); // click first message of thread
        await Util.sleep(3);
        const messages = await gmailPage.target.$$('[role="listitem"] .adn.ads');
        const plainReplyButton = await messages[0].$('[data-tooltip="Reply"]');
        await Util.sleep(1);
        await plainReplyButton!.click();
        await gmailPage.waitAndClick('#switch_to_encrypted_reply'); // Switch to encrypted compose
        await Util.sleep(2);
        await gmailPage.waitAll('.reply_message');
        await pageHasSecureReplyContainer(t, browser, gmailPage, { isReplyPromptAccepted: true, composeFrameCount: 2 });
        const replyBox = await gmailPage.getFrame(['/chrome/elements/compose.htm', '&skipClickPrompt=___cu_true___'], { sleep: 5 });
        await Util.sleep(3);
        await replyBox.waitAndClick('@action-expand-quoted-text');
        // Check if quoted message doesn't contain last message
        expect(await replyBox.read('@input-body')).to.not.contain(`Here's reply`);
      })
    );

    test(
      'mail.google.com - switch to encrypted reply for middle message',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGqRGfPBbNLWvfPvDbxnHBwkdGf'); // plain convo
        await gmailPage.waitAndClick('[role="listitem"] .adf.ads', { delay: 1 }); // click first message of thread
        await Util.sleep(3);
        const messages = await gmailPage.target.$$('[role="listitem"] .adn.ads');
        expect(messages.length).to.equal(2);

        const plainReplyButton = await messages[0].$('[data-tooltip="Reply"]');
        expect(plainReplyButton).to.be.ok;
        await Util.sleep(1);
        await plainReplyButton!.click();
        await gmailPage.waitAll('[data-tooltip^="Send"]'); // The Send button from the Standard reply box
        await gmailPage.waitForContent(
          '.reply_message_evaluated .error_notification',
          'The last message was encrypted, but you are composing a reply without encryption.'
        );

        const secureReplyButton = await messages[0].$('[data-tooltip="Secure Reply"]');
        expect(secureReplyButton).to.be.ok;
        await secureReplyButton!.click(); // Switch to encrypted reply
        await gmailPage.waitAll('.reply_message');
        await pageHasSecureReplyContainer(t, browser, gmailPage, { isReplyPromptAccepted: true, composeFrameCount: 2 });
      })
    );

    test(
      'mail.google.com - plain reply with dot menu',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDRNgcQxLmkhBCKVSFwkfdvV'); // plain convo
        await gmailPage.waitAndClick('[data-tooltip="Reply"]', { delay: 1 });
        await gotoGmailPage(gmailPage, '/FMfcgzGtwgfMhWTlgRwwKWzRhqNZzwXz'); // go to encrypted convo
        await Util.sleep(5);
        await gmailPage.waitAndClick('.adn [data-tooltip="More"]', { delay: 1 });
        await gmailPage.waitAndClick('[act="24"]', { delay: 1 }); // click reply-all
        await Util.sleep(3);
        await gmailPage.waitAll('[data-tooltip^="Send"]'); // The Send button from the Standard reply box
        await gmailPage.waitForContent(
          '.reply_message_evaluated .error_notification',
          'The last message was encrypted, but you are composing a reply without encryption.'
        );
        await gmailPage.waitAndClick('[data-tooltip="Secure Reply"]'); // Switch to encrypted reply
        await gmailPage.waitAll('.reply_message');
        await pageHasSecureReplyContainer(t, browser, gmailPage, { isReplyPromptAccepted: true });
        const replyBox = await gmailPage.getFrame(['/chrome/elements/compose.htm'], { sleep: 5 });
        await Util.sleep(3);
        expect(await replyBox.read('@recipients-preview')).to.equal(['flowcrypt.compatibility@gmail.com', 'e2e.enterprise.test@flowcrypt.com'].join(''));
      })
    );

    test(
      'mail.google.com - switch to encrypted forward',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGtwgfMhWTlgRwwKWzRhqNZzwXz'); // go to encrypted convo
        await Util.sleep(5);
        await gmailPage.waitAndClick('.adn [data-tooltip="More"]', { delay: 1 });
        await gmailPage.waitAndClick('[act="25"]', { delay: 1 }); // click forward
        await Util.sleep(3);
        await gmailPage.waitAll('[data-tooltip^="Send"]'); // The Send button from the Standard reply box
        await gmailPage.waitForContent(
          '.reply_message_evaluated .error_notification',
          'The last message was encrypted, but you are composing a message without encryption. Switch to encrypted compose'
        );
        await gmailPage.waitAndClick('#switch_to_encrypted_reply'); // Switch to encrypted compose
        await Util.sleep(3);
        const replyBox2 = await gmailPage.getFrame(['/chrome/elements/compose.htm'], { sleep: 5 });
        await Util.sleep(3);
        await replyBox2.waitForContent('@input-body', '---------- Forwarded message ---------');
      })
    );

    test(
      'mail.google.com - secure reply and forward in dot menu',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGtwgfMhWTlgRwwKWzRhqNZzwXz'); // go to encrypted convo
        const gmailContextMenu = '.J-J5-Ji.aap';
        await gmailPage.waitAndClick(gmailContextMenu);
        await Util.sleep(1);
        expect(await gmailPage.isElementPresent('@action-reply-message-button'));
        await gmailPage.waitAndClick('@action-reply-message-button');
        const replyBox = await gmailPage.getFrame(['/chrome/elements/compose.htm'], { sleep: 5 });
        await replyBox.waitForContent('@input-body', '');
        await gmailPage.waitAndClick(gmailContextMenu);
        await Util.sleep(1);
        expect(await gmailPage.isElementPresent('@action-reply-all-message-button'));
        await gmailPage.waitAndClick('@action-reply-all-message-button');
        const replyBox2 = await gmailPage.getFrame(['/chrome/elements/compose.htm'], { sleep: 5 });
        await replyBox2.waitForContent('@input-body', '');
        const recipientsCount = await replyBox2.target.$$eval('.email_address', elements => elements.length);
        expect(recipientsCount).to.equal(2);
        await gmailPage.waitAndClick(gmailContextMenu);
        await Util.sleep(1);
        expect(await gmailPage.isElementPresent('@action-forward-message-button'));
        await gmailPage.waitAndClick('@action-forward-message-button');
        const replyBox3 = await gmailPage.getFrame(['/chrome/elements/compose.htm'], { sleep: 5 });
        await replyBox3.waitForContent('@input-body', '---------- Forwarded message ---------');
      })
    );

    // convo-sensitive, draft-sensitive test
    test.serial(
      'mail.google.com - plain reply draft',
      testWithBrowser(
        async (t, browser) => {
          await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
          const gmailPage = await openGmailPage(t, browser);
          const threadId = '181d226b4e69f172'; // 1st message -- thread id
          await gotoGmailPage(gmailPage, `/${threadId}`); // go to encrypted convo
          await GmailPageRecipe.trimConvo(gmailPage, threadId);
          await gmailPage.waitAndClick('[data-tooltip="Reply"]', { delay: 5 });
          t.timeout(minutes(2)); // extend ava's timeout
          await Util.sleep(5);
          await gmailPage.waitTillFocusIsIn('div[aria-label="Message Body"]', { timeout: 10 });
          await gmailPage.type('div[aria-label="Message Body"]', 'plain reply', true);
          await gmailPage.waitForContent('.oG.aOy', 'Draft saved');
          // sometimes "Page has unsaved data" alert is displayed here, auto-accept it
          await gmailPage.reload({ timeout: TIMEOUT_PAGE_LOAD * 1000, waitUntil: 'networkidle2' }, true);
          await gmailPage.waitForContent('div[aria-label="Message Body"]', 'plain reply', 30);
          await pageDoesNotHaveSecureReplyContainer(gmailPage);
          await gmailPage.click('[aria-label^="Discard draft"]');
        },
        undefined,
        minutes(5) // explicitly set timer-controlled timeout
      )
    );

    test(
      'mail.google.com - Outlook encrypted message with attachment is recognized',
      testWithBrowser(async (t, browser) => {
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, 'ci.tests.gmail@flowcrypt.dev');
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'flowcrypt.compatibility.1pp1',
          { submitPubkey: false, usedPgpBefore: true },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGllVqqBbjHQQRDsSwcZBlMRzDr');
        await Util.sleep(5);
        await gmailPage.waitAll('iframe');
        expect(await gmailPage.isElementPresent('@container-attachments')).to.equal(false);
        await gmailPage.waitAll(['.aZi'], { visible: false });
        expect(await gmailPage.isElementVisible('.aQH')).to.equal(false); // original attachment container(s) should be hidden
        await gmailPage.close();
      })
    );

    test(
      `mail.google.com - simple attachments triggering processAttachments() keep "download all" button visible`,
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/KtbxLvHkSWwbVHxgCbWNvXVKGjFgqMbGQq');
        await Util.sleep(5);
        await gmailPage.waitAll('iframe');
        await gmailPage.waitAll(['.aZi'], { visible: true });
        await gmailPage.close();
      })
    );

    test(
      `mail.google.com - encrypted text inside "message" attachment`,
      testWithBrowser(async (t, browser) => {
        const settingsPage = await BrowserRecipe.openSettingsLoginApprove(t, browser, 'ci.tests.gmail@flowcrypt.dev');
        await SetupPageRecipe.manualEnter(
          settingsPage,
          'flowcrypt.compatibility.1pp1',
          { submitPubkey: false, usedPgpBefore: true },
          { isSavePassphraseChecked: false, isSavePassphraseHidden: false }
        );
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGrbHprlHvtTJscCJQpZcqrKQbg');
        await Util.sleep(5);
        await gmailPage.waitAll('iframe');
        expect(await gmailPage.isElementPresent('@container-attachments')).to.equal(false);
        await gmailPage.waitAll(['.aZi'], { visible: false });
        await gmailPage.close();
      })
    );

    test(
      `mail.google.com - large clipped PGP/MIME encrypted message rendered correctly`,
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGtxKSjjzhRZRRzddjMvJnpDRQf');
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_block.htm'], { sleep: 10, appearIn: 25 });
        expect(urls.length).to.equal(1);
        const pgpBlockFrame = await gmailPage.getFrame(['pgp_block.htm']);
        await BrowserRecipe.pgpBlockCheck(t, pgpBlockFrame, {
          content: ['Check it'],
          encryption: 'encrypted',
          signature: 'signed',
        });
        await pageHasSecureReplyContainer(t, browser, gmailPage);
      })
    );

    test(
      `mail.google.com - attachments which contain emoji in filename are rendered correctly`,
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGtwqFGhMwWtLRjkPJlQlZHSlrW');
        await Util.sleep(5);
        await gmailPage.waitAll('iframe');
        await gmailPage.waitAll(['.aZo'], { visible: false });
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/attachment.htm']);
        expect(urls.length).to.equal(2);
        expect(await gmailPage.waitForContent('.aVW span:first-child', '2'));
        expect(await gmailPage.waitForContent('.aVW span.a2H', ' •  Scanned by Gmail'));
        await gmailPage.close();
      })
    );

    test(
      `mail.google.com - render plain text for "message" attachment (which has plain text)`,
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGrbHrBdFGBXqpFZvSkcQpKkvrM');
        await Util.sleep(5);
        await gmailPage.waitForContent('.a3s', 'Plain message');
        expect(await gmailPage.isElementPresent('.aQH')).to.equal(true); // gmail attachment container
        // expect no pgp blocks
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_block.htm']);
        expect(urls.length).to.equal(0);
      })
    );

    test(
      'mail.google.com - pubkey file gets rendered',
      testWithBrowser(async (t, browser) => {
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const gmailPage = await openGmailPage(t, browser);
        await gotoGmailPage(gmailPage, '/FMfcgzGkbDXBWCgTcMJlmBtfNxrbzTTn');
        const urls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_pubkey.htm']);
        expect(urls.length).to.equal(1);
        await pageHasSecureReplyContainer(t, browser, gmailPage);
        expect(await gmailPage.isElementVisible('.aVW')).to.equal(false); // attachment label count should be hidden
        expect(await gmailPage.isElementVisible('.aQH')).to.equal(false); // original attachment container(s) should be hidden
      })
    );

    // uses live openpgpkey.flowcrypt.com WKD
    test(
      'can lookup public key from WKD directly',
      testWithBrowser(async (t, browser) => {
        const acctEmail = 'ci.tests.gmail@flowcrypt.dev';
        await BrowserRecipe.setUpCommonAcct(t, browser, 'ci.tests.gmail');
        const composePage = await ComposePageRecipe.openStandalone(t, browser, acctEmail);
        await ComposePageRecipe.fillMsg(composePage, { to: 'demo@flowcrypt.com' }, 'should find pubkey from WKD directly');
        await composePage.waitForContent('.email_address.has_pgp', 'demo@flowcrypt.com');
        expect(await composePage.attr('.email_address.has_pgp', 'title')).to.contain('0997 7F6F 512C A5AD 76F0 C210 248B 60EB 6D04 4DF8 (openpgp)');
      })
    );

    // todo - missing equivalent sample at ci.tests.gmail
    // test('mail.google.com - pubkey gets rendered when using quoted-printable mime', testWithBrowser('compatibility', async (t, browser) => {
    //   const gmailPage = await openGmailPage(t, browser, '/WhctKJVRFztXGwvSbwcrbDshGTnLWMFvhwJmhqllRWwvpKnlpblQMXVZLTsKfWdPWKhPFBV');
    //   const urls = await gmailPage.getFramesUrls(['/chrome/elements/pgp_pubkey.htm'], { sleep: 10, appearIn: 20 });
    //   expect(urls.length).to.equal(1);
    //   await pageHasSecureReplyContainer(t, browser, gmailPage);
    //   const pubkeyPage = await browser.newPage(t, urls[0]);
    //   const content = await pubkeyPage.read('body');
    //   expect(content).to.contain('Fingerprint: 7A2E 4FFD 34BC 4AED 0F54 4199 D652 7AD6 65C3 B0DD');
    // }));

    const testMinimumElementHeight = async (page: ControllablePage, selector: string, min: number) => {
      // testing https://github.com/FlowCrypt/flowcrypt-browser/issues/3519
      const elStyle = await page.target.$eval(selector, el => el.getAttribute('style')); // 'height: 289.162px;'
      const elHeight = Number(elStyle?.replace('height: ', '').replace('px;', ''));
      if (isNaN(elHeight)) {
        throw Error(`msgIframeHeight iNaN`);
      }
      expect(elHeight).to.be.above(min, 'Expected iframe height above 80px (in particular not expecting 60 or 30 which are defaults suggesting failure)');
    };
  }
};
