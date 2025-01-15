/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { GoogleOAuth } from '../common/api/authentication/google/google-oauth.js';
import { Bm, BrowserMsg } from '../common/browser/browser-msg.js';
import { emailKeyIndex } from '../common/core/common.js';
import { ExpirationCache } from '../common/core/expiration-cache.js';
import { BgHandlers } from './bg-handlers.js';
import { Catch } from '../common/platform/catch.js';
import { ContactStore } from '../common/platform/store/contact-store.js';
import { BgUtils } from './bgutils.js';
import { migrateGlobal, moveContactsToEmailsAndPubkeys, updateOpgpRevocations, updateSearchables, updateX509FingerprintsAndLongids } from './migrations.js';
import { GlobalStore, GlobalStoreDict } from '../common/platform/store/global-store.js';
import { VERSION } from '../common/core/const.js';
import { injectFcIntoWebmail } from './inject.js';
import { ConfiguredIdpOAuth } from '../common/api/authentication/configured-idp-oauth.js';

console.info('background.js service worker starting');

(async () => {
  let db: IDBDatabase;
  let storage: GlobalStoreDict;
  const inMemoryStore = new ExpirationCache<string>('in_memory_store', 4 * 60 * 60 * 1000); // 4 hours
  BrowserMsg.createIntervalAlarm('delete_expired', 1); // each minute

  try {
    await migrateGlobal();
    await GlobalStore.set({ version: Number(VERSION.replace(/\./g, '')) });
    storage = await GlobalStore.get(['settings_seen']);
  } catch (e) {
    await BgUtils.handleStoreErr(GlobalStore.errCategorize(e));
    return;
  }
  if (!storage.settings_seen) {
    await BgUtils.openSettingsPage('initial.htm'); // called after the very first installation of the plugin
    // eslint-disable-next-line @typescript-eslint/naming-convention
    await GlobalStore.set({ settings_seen: true });
  }
  try {
    db = await ContactStore.dbOpen(); // takes 4-10 ms first time
    await updateOpgpRevocations(db);
    await updateX509FingerprintsAndLongids(db);
    await updateSearchables(db);
    await moveContactsToEmailsAndPubkeys(db);
  } catch (e) {
    await BgUtils.handleStoreErr(e);
    return;
  }
  // storage related handlers

  BrowserMsg.bgAddListener('db', (r: Bm.Db) => BgHandlers.dbOperationHandler(db, r));
  BrowserMsg.bgAddListener('inMemoryStoreSet', async (r: Bm.InMemoryStoreSet) => inMemoryStore.set(emailKeyIndex(r.acctEmail, r.key), r.value, r.expiration));
  BrowserMsg.bgAddListener('inMemoryStoreGet', async (r: Bm.InMemoryStoreGet) => inMemoryStore.get(emailKeyIndex(r.acctEmail, r.key)));

  BrowserMsg.bgAddListener('ajax', BgHandlers.ajaxHandler);
  BrowserMsg.bgAddListener('ajaxGmailAttachmentGetChunk', BgHandlers.ajaxGmailAttachmentGetChunkHandler);
  BrowserMsg.bgAddListener('expirationCacheGet', BgHandlers.expirationCacheGetHandler);
  BrowserMsg.bgAddListener('expirationCacheSet', BgHandlers.expirationCacheSetHandler);
  BrowserMsg.bgAddListener('expirationCacheDeleteExpired', BgHandlers.expirationCacheDeleteExpiredHandler);
  BrowserMsg.bgAddListener('getApiAuthorization', BgHandlers.getApiAuthorization);
  BrowserMsg.bgAddListener('settings', BgHandlers.openSettingsPageHandler);
  BrowserMsg.bgAddListener('update_uninstall_url', BgHandlers.updateUninstallUrl);
  BrowserMsg.bgAddListener('get_active_tab_info', BgHandlers.getActiveTabInfo);
  BrowserMsg.bgAddListener('reconnect_acct_auth_popup', (r: Bm.ReconnectAcctAuthPopup) => GoogleOAuth.newAuthPopup(r));
  BrowserMsg.bgAddListener('reconnect_custom_idp_acct_auth_popup', (r: Bm.ReconnectCustomIDPAcctAuthPopup) => ConfiguredIdpOAuth.newAuthPopup(r.acctEmail));
  BrowserMsg.intervalAddListener('delete_expired', inMemoryStore.deleteExpired);
  BrowserMsg.bgListen();
  BrowserMsg.alarmListen();
  await BgHandlers.updateUninstallUrl({});
  injectFcIntoWebmail();

  if (Catch.isThunderbirdMail()) {
    BgHandlers.thunderbirdSecureComposeHandler();
    await BgHandlers.thunderbirdContentScriptRegistration();
    BrowserMsg.bgAddListener('thunderbirdGetCurrentUser', BgHandlers.thunderbirdGetCurrentUserHandler);
    BrowserMsg.bgAddListener('thunderbirdGetDownloadableAttachment', BgHandlers.thunderbirdGetDownloadableAttachment);
    BrowserMsg.bgAddListener('thunderbirdInitiateAttachmentDownload', BgHandlers.thunderbirdInitiateAttachmentDownload);
    BrowserMsg.bgAddListener('thunderbirdOpenPassphraseDialog', BgHandlers.thunderbirdOpenPassphraseDialog);
  }
})().catch(Catch.reportErr);
