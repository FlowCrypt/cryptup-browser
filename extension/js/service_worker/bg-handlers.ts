/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { BgUtils } from './bgutils.js';
import { Bm } from '../common/browser/browser-msg.js';
import { Gmail } from '../common/api/email-provider/gmail/gmail.js';
import { GlobalStore } from '../common/platform/store/global-store.js';
import { ContactStore } from '../common/platform/store/contact-store.js';
import { Api } from '../common/api/shared/api.js';
import { ExpirationCache } from '../common/core/expiration-cache.js';
import { GoogleOAuth } from '../common/api/authentication/google/google-oauth.js';
import { AcctStore } from '../common/platform/store/acct-store.js';
import { ConfiguredIdpOAuth } from '../common/api/authentication/configured-idp-oauth.js';
import { Url, Str } from '../common/core/common.js';
import { Attachment, ThunderbirdAttachment } from '../common/core/attachment.js';

export class BgHandlers {
  public static openSettingsPageHandler: Bm.AsyncResponselessHandler = async ({ page, path, pageUrlParams, addNewAcct, acctEmail }: Bm.Settings) => {
    await BgUtils.openSettingsPage(path, acctEmail, page, pageUrlParams, addNewAcct === true);
  };

  public static dbOperationHandler = async (db: IDBDatabase, request: Bm.Db): Promise<Bm.Res.Db> => {
    if (!db) {
      console.info(`db corrupted, skipping: ${request.f}`);
      return await new Promise(() => undefined); // never resolve, error was already shown
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
    const dbFunc = (ContactStore as any)[request.f] as (db: IDBDatabase, ...args: any[]) => Promise<Bm.Res.Db>; // due to https://github.com/Microsoft/TypeScript/issues/6480
    if (request.f === 'obj') {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-argument
      return await dbFunc(request.args[0] as any); // db not needed, it goes through background because openpgp.js may not be available in the frame
    }

    return await dbFunc(db, ...request.args);
  };

  public static ajaxHandler = async (r: Bm.Ajax): Promise<Bm.Res.Ajax> => {
    return await Api.ajax(r.req, r.resFmt);
  };

  public static ajaxGmailAttachmentGetChunkHandler = async (r: Bm.AjaxGmailAttachmentGetChunk): Promise<Bm.Res.AjaxGmailAttachmentGetChunk> => {
    return { chunk: await new Gmail(r.acctEmail).attachmentGetChunk(r.msgId, r.attachmentId, r.treatAs) };
  };

  public static expirationCacheGetHandler = async <V>(r: Bm.ExpirationCacheGet): Promise<Bm.Res.ExpirationCacheGet<V>> => {
    const expirationCache = new ExpirationCache<V>(r.prefix, r.expirationTicks);
    return await expirationCache.get(r.key);
  };

  public static expirationCacheSetHandler = async <V>(r: Bm.ExpirationCacheSet<V>): Promise<Bm.Res.ExpirationCacheSet> => {
    const expirationCache = new ExpirationCache<V>(r.prefix, r.expirationTicks);
    await expirationCache.set(r.key, r.value, r.expiration);
  };

  public static expirationCacheDeleteExpiredHandler = async (r: Bm.ExpirationCacheDeleteExpired): Promise<Bm.Res.ExpirationCacheDeleteExpired> => {
    const expirationCache = new ExpirationCache(r.prefix, r.expirationTicks);
    await expirationCache.deleteExpired();
  };

  public static getApiAuthorization = async (r: Bm.GetApiAuthorization): Promise<Bm.Res.GetApiAuthorization> => {
    // force refresh token
    const { email } = GoogleOAuth.parseIdToken(r.idToken);
    if (email) {
      const storage = await AcctStore.get(email, ['authentication']);
      if (storage.authentication?.oauth) {
        return await ConfiguredIdpOAuth.authHdr(email, true, true);
      }
      return await GoogleOAuth.googleApiAuthHeader(email, true);
    }
    return undefined;
  };

  public static updateUninstallUrl: Bm.AsyncResponselessHandler = async () => {
    const acctEmails = await GlobalStore.acctEmailsGet();

    if (typeof chrome.runtime.setUninstallURL !== 'undefined') {
      const email = acctEmails?.length ? acctEmails[0] : undefined;

      chrome.runtime.setUninstallURL(`https://flowcrypt.com/leaving.htm#${JSON.stringify({ email, metrics: null })}`); // eslint-disable-line no-null/no-null
    }
  };

  public static getActiveTabInfo: Bm.AsyncRespondingHandler = () =>
    new Promise((resolve, reject) => {
      chrome.tabs.query({ active: true, currentWindow: true, url: ['*://mail.google.com/*', '*://inbox.google.com/*'] }, activeTabs => {
        if (activeTabs.length) {
          if (activeTabs[0].id !== undefined) {
            type ScriptRes = { acctEmail: string | undefined; sameWorld: boolean | undefined };

            chrome.scripting.executeScript(
              {
                target: { tabId: activeTabs[0].id },
                func: () => {
                  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
                  return { acctEmail: (window as any).account_email_global, sameWorld: (window as any).same_world_global };
                },
              },
              results => {
                const scriptResult = results[0].result as ScriptRes;
                if (scriptResult) {
                  resolve({
                    provider: 'gmail',
                    acctEmail: scriptResult.acctEmail,
                    sameWorld: scriptResult.sameWorld === true,
                  });
                } else {
                  reject(new Error('Script execution failed'));
                }
              }
            );
          } else {
            reject(new Error('tabs[0].id is undefined'));
          }
        } else {
          resolve({ provider: undefined, acctEmail: undefined, sameWorld: undefined });
        }
      });
    });

  public static thunderbirdSecureComposeHandler = () => {
    const handleClickEvent = async (tabId: number, acctEmail: string, thunderbirdMsgId: number, composeMethod?: messenger.compose._ComposeDetailsType) => {
      const accountEmails = await GlobalStore.acctEmailsGet();
      const useFullScreenSecureCompose = (await messenger.windows.getCurrent()).type === 'messageCompose';
      composeMethod = composeMethod === 'reply' || composeMethod === 'forward' ? composeMethod : undefined;
      if (accountEmails.length !== 0) {
        await BgUtils.openExtensionTab(
          Url.create('/chrome/settings/inbox/inbox.htm', { acctEmail, useFullScreenSecureCompose, thunderbirdMsgId, composeMethod })
        );
        await messenger.tabs.remove(tabId);
      } else {
        await BgUtils.openExtensionTab(Url.create('/chrome/settings/initial.htm', {}));
      }
    };
    messenger.composeAction.onClicked.addListener(async tab => {
      const messageDetails = await messenger.compose.getComposeDetails(Number(tab.id));
      const composeMethod = messageDetails.type;
      const msgId = Number(messageDetails.relatedMessageId);
      const acctEmail = Str.parseEmail(messageDetails.from as string).email;
      if (acctEmail) await handleClickEvent(Number(tab.id), acctEmail, msgId, composeMethod);
    });
    messenger.messageDisplayAction.onClicked.addListener(async tab => {
      const tabId = Number(tab.id);
      const messageDetails = await messenger.messageDisplay.getDisplayedMessage(tabId);
      if (messageDetails) {
        const msgId = messageDetails.id;
        const accountId = messageDetails?.folder?.accountId || '';
        const acctEmail = (await messenger.accounts.get(accountId))?.name || '';
        await handleClickEvent(tabId, acctEmail, msgId);
      }
    });
  };

  public static thunderbirdContentScriptRegistration = async () => {
    const contentScriptGroups = chrome.runtime.getManifest().content_scripts ?? []; // we know it's in the manifest
    // sweetalert2.js throws error in Thunderbird environment
    const files = contentScriptGroups[0].js?.filter(url => !url.includes('sweetalert2')).map(url => url.replace(/moz-extension:\/\/[^/]+\//, './')) ?? [];
    await messenger.messageDisplayScripts.register({
      js: files.map(file => ({ file })),
      css: [{ file: './css/cryptup.css' }],
    });
  };

  public static thunderbirdGetDownloadableAttachment = async (): Promise<Bm.Res.ThunderbirdGetDownloadableAttachment> => {
    const processableAttachments: ThunderbirdAttachment[] = [];
    const [tab] = await messenger.mailTabs.query({ active: true, currentWindow: true });
    const message = await messenger.messageDisplay.getDisplayedMessage(tab.id);
    let from = '';
    if (tab.id && message?.id) {
      from = Str.parseEmail(message.author).email || '';
      const mimeMsg = await messenger.messages.getFull(message.id);
      let attachments = await messenger.messages.listAttachments(message.id);
      const fcAttachments: Attachment[] = [];
      if (mimeMsg.parts?.[0].contentType === 'multipart/signed' && mimeMsg.parts?.[0].parts?.length === 2) {
        attachments = attachments.filter(file => file.contentType === 'application/pgp-signature');
      }
      // convert Thunderbird Attachments to FlowCrypt recognizable Attachments
      for (const attachment of attachments) {
        const file = await messenger.messages.getAttachmentFile(message.id, attachment.partName);
        fcAttachments.push(
          new Attachment({
            data: new Uint8Array(await file.arrayBuffer()),
            type: attachment.contentType,
            name: attachment.name,
            length: attachment.size,
          })
        );
      }
      for (const fcAttachment of fcAttachments) {
        processableAttachments.push({
          name: fcAttachment.name,
          contentType: fcAttachment.type,
          data: fcAttachment.getData(),
          treatAs: fcAttachment.treatAs(fcAttachments),
        });
      }
    }
    return { from, processableAttachments };
  };

  public static thunderbirdInitiateAttachmentDownload = async (
    r: Bm.ThunderbirdInitiateAttachmentDownload
  ): Promise<Bm.Res.ThunderbirdInitiateAttachmentDownload> => {
    // todo - add prompt  using messenger.notifications.create. requires `notifications` permission;
    const blob = new Blob([r.decryptedContent]);
    const fileUrl = URL.createObjectURL(blob);
    await browser.downloads.download({
      url: fileUrl,
      filename: r.decryptedFileName,
      saveAs: true,
    });
    URL.revokeObjectURL(fileUrl);
  };

  public static thunderbirdGetCurrentUserHandler = async (): Promise<Bm.Res.ThunderbirdGetCurrentUser> => {
    const [tab] = await messenger.tabs.query({ active: true, currentWindow: true });
    if (tab.id) {
      const messageDetails = await messenger.messageDisplay.getDisplayedMessage(tab.id);
      const accountId = messageDetails?.folder?.accountId || '';
      return (await messenger.accounts.get(accountId))?.name;
    }
    return;
  };

  public static thunderbirdOpenPassphraseDialog = async (r: Bm.ThunderbirdOpenPassphraseDialog): Promise<Bm.Res.ThunderbirdOpenPassphraseDialog> => {
    await BgUtils.openExtensionTab(`chrome/elements/passphrase.htm?type=message&parentTabId=0&acctEmail=${r.acctEmail}&longids=${r.longids}`, true);
  };
}
