/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { AuthRes } from '../api/authentication/google/google-oauth.js';
import { AjaxErr } from '../api/shared/api-error.js';
import { Buf } from '../core/buf.js';
import { Dict, Str, UrlParams, Value } from '../core/common.js';
import { NotificationGroupType } from '../notifications.js';
import { Catch } from '../platform/catch.js';
import { PassphraseDialogType } from '../xss-safe-factory.js';
import { BrowserMsgCommonHandlers } from './browser-msg-common-handlers.js';
import { Env } from './env.js';
import { RenderMessage } from '../render-message.js';
import { SymEncryptedMessage, SymmetricMessageEncryption } from '../symmetric-message-encryption.js';
import { Ajax as ApiAjax, ResFmt } from '../api/shared/api.js';
import { Ui } from './ui.js';

export type GoogleAuthWindowResult$result = 'Success' | 'Denied' | 'Error' | 'Closed';
export type ScreenDimensions = { width: number; height: number; availLeft: number; availTop: number };
export interface ChildFrame {
  readonly parentTabId: string;
}

export namespace Bm {
  export type Dest = string;
  export type Sender = chrome.runtime.MessageSender | 'background';
  export type Response = unknown;
  export type RawResponse = { result: unknown; exception?: Bm.ErrAsJson };
  export type Raw = {
    name: string;
    data: { bm: AnyRequest | object };
    to: Dest | null;
    uid: string;
    stack: string;
  };
  export type RawWithWindowExtensions = Raw & {
    to: Dest;
    data: { bm: AnyRequest & { messageSender?: Dest } };
    responseName?: string;
    propagateToParent?: boolean;
  };

  export type SetCss = { css: Dict<string>; traverseUp?: number; selector: string };
  export type AddOrRemoveClass = { class: string; selector: string };
  export type Settings = {
    path?: string;
    page?: string;
    acctEmail?: string;
    pageUrlParams?: UrlParams;
    addNewAcct?: boolean;
  };
  export type PassphraseDialog = { type: PassphraseDialogType; longids: string[]; initiatorFrameId?: string };
  export type ScrollToReplyBox = { replyMsgId: string };
  export type ScrollToCursorInReplyBox = { replyMsgId: string; cursorOffsetTop: number };
  export type NotificationShow = { notification: string; group: NotificationGroupType; callbacks?: Dict<() => void> };
  export type NotificationShowAuthPopupNeeded = { acctEmail: string };
  export type RenderPublicKeys = { afterFrameId: string; publicKeys: string[]; traverseUp?: number };
  export type SubscribeDialog = { isAuthErr?: boolean };
  export type ComposeWindow = { frameId: string };
  export type ComposeWindowOpenDraft = { draftId: string };
  export type ReinsertReplyBox = { replyMsgId: string };
  export type AddPubkeyDialog = { emails: string[] };
  export type Reload = { advanced?: boolean };
  export type Redirect = { location: string };
  export type OpenGoogleAuthDialog = { acctEmail?: string; scopes?: string[] };
  export type OpenPage = { page: string; addUrlText?: string | UrlParams };
  export type PassphraseEntry = { entered: boolean; initiatorFrameId?: string };
  export type AsyncResult<T> = { requestUid: string; payload: T };
  export type ConfirmationResult = AsyncResult<boolean>;
  export type AuthWindowResult = { url?: string; error?: string };
  export type Db = { f: string; args: unknown[] };
  export type InMemoryStoreSet = {
    acctEmail: string;
    key: string;
    value: string | undefined;
    expiration: number | undefined;
  };
  export type InMemoryStoreGet = { acctEmail: string; key: string };
  export type GetGoogleApiAuthorization = { idToken: string };
  export type ReconnectAcctAuthPopup = { acctEmail: string; scopes?: string[]; screenDimensions: ScreenDimensions };
  export type Ajax = { req: ApiAjax; resFmt: ResFmt };
  export type AjaxProgress = { operationId: string; percent?: number; loaded: number; total: number; expectedTransferSize: number };
  export type AjaxGmailAttachmentGetChunk = { acctEmail: string; msgId: string; attachmentId: string; treatAs: string };
  export type ExpirationCacheGet = { key: string; prefix: string; expirationTicks: number };
  export type ExpirationCacheSet<V> = { key: string; prefix: string; value: V | undefined; expirationTicks: number; expiration?: number };
  export type ExpirationCacheDeleteExpired = { prefix: string; expirationTicks: number };
  export type ShowAttachmentPreview = { iframeUrl: string };
  export type ShowConfirmation = { text: string; isHTML: boolean; messageSender: Dest; requestUid: string; footer?: string };
  export type ReRenderRecipient = { email: string };
  export type PgpBlockRetry = { frameId: string; messageSender: Dest };
  export type PgpBlockReady = { frameId: string; messageSender: Dest };

  export namespace Res {
    export type GetActiveTabInfo = {
      provider: 'gmail' | undefined;
      acctEmail: string | undefined;
      sameWorld: boolean | undefined;
    };
    export type InMemoryStoreGet = string | undefined;
    // eslint-disable-next-line @typescript-eslint/no-invalid-void-type
    export type InMemoryStoreSet = void;
    export type GetGoogleApiAuthorization = string | undefined;
    export type ReconnectAcctAuthPopup = AuthRes;
    export type AjaxGmailAttachmentGetChunk = { chunk: Buf };
    export type ExpirationCacheGet<V> = Promise<V | undefined>;
    export type ExpirationCacheSet = Promise<void>;
    export type ExpirationCacheDeleteExpired = Promise<void>;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    export type Db = any; // not included in Any below
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    export type Ajax = any; // not included in Any below

    export type Any =
      | GetActiveTabInfo
      | ReconnectAcctAuthPopup
      | InMemoryStoreGet
      | GetGoogleApiAuthorization
      | InMemoryStoreSet
      | ExpirationCacheGet<unknown>
      | ExpirationCacheSet
      | ExpirationCacheDeleteExpired
      | AjaxGmailAttachmentGetChunk
      | ConfirmationResult;
  }

  export type AnyRequest =
    | PassphraseEntry
    | OpenPage
    | GetGoogleApiAuthorization
    | ExpirationCacheGet
    | ExpirationCacheSet<unknown>
    | ExpirationCacheDeleteExpired
    | OpenGoogleAuthDialog
    | Redirect
    | Reload
    | AddPubkeyDialog
    | ReinsertReplyBox
    | ComposeWindow
    | ScrollToReplyBox
    | ScrollToCursorInReplyBox
    | SubscribeDialog
    | RenderPublicKeys
    | NotificationShowAuthPopupNeeded
    | ComposeWindowOpenDraft
    | NotificationShow
    | PassphraseDialog
    | Settings
    | SetCss
    | AddOrRemoveClass
    | ReconnectAcctAuthPopup
    | Db
    | InMemoryStoreSet
    | InMemoryStoreGet
    | AjaxProgress
    | ShowAttachmentPreview
    | ShowConfirmation
    | ReRenderRecipient
    | AuthWindowResult
    | RenderMessage
    | PgpBlockReady
    | PgpBlockRetry
    | ConfirmationResult
    | Ajax;

  export type AsyncRespondingHandler = (req: AnyRequest) => Promise<Res.Any>;
  export type AsyncResponselessHandler = (req: AnyRequest) => Promise<void>;

  type StandardErrAsJson = { stack?: string; message: string; errorConstructor: 'Error' };
  type AjaxErrDetails = {
    status: number;
    url: string;
    responseText: string;
    statusText: string;
    resMsg?: string;
    resDetails?: string;
  };
  type AjaxErrAsJson = {
    stack?: string;
    message: string;
    errorConstructor: 'AjaxErr';
    ajaxErrorDetails: AjaxErrDetails;
  };
  export type ErrAsJson = StandardErrAsJson | AjaxErrAsJson;
}

type Handler = Bm.AsyncRespondingHandler | Bm.AsyncResponselessHandler;
type IntervalHandler = () => void | Promise<void>;
type Handlers = Dict<Handler>;

export class BgNotReadyErr extends Error {}
// ts-prune-ignore-next
export class TabIdRequiredError extends Error {}

export class BrowserMsg {
  public static MAX_SIZE = 1024 * 1024; // 1MB

  public static send = {
    // todo - may want to organise this differently, seems to always confuse me when sending a message
    bg: {
      settings: (bm: Bm.Settings) => {
        BrowserMsg.sendCatch(undefined, 'settings', bm);
      },
      updateUninstallUrl: () => {
        BrowserMsg.sendCatch(undefined, 'update_uninstall_url', {});
      },
      await: {
        reconnectAcctAuthPopup: (bm: Bm.ReconnectAcctAuthPopup) =>
          BrowserMsg.sendAwait(undefined, 'reconnect_acct_auth_popup', bm, true) as Promise<Bm.Res.ReconnectAcctAuthPopup>,
        getActiveTabInfo: () => BrowserMsg.sendAwait(undefined, 'get_active_tab_info', undefined, true) as Promise<Bm.Res.GetActiveTabInfo>,
        inMemoryStoreGet: (bm: Bm.InMemoryStoreGet) => BrowserMsg.sendAwait(undefined, 'inMemoryStoreGet', bm, true) as Promise<Bm.Res.InMemoryStoreGet>,
        inMemoryStoreSet: (bm: Bm.InMemoryStoreSet) => BrowserMsg.sendAwait(undefined, 'inMemoryStoreSet', bm, true) as Promise<Bm.Res.InMemoryStoreSet>,
        getGoogleApiAuthorization: (bm: Bm.GetGoogleApiAuthorization) =>
          BrowserMsg.sendAwait(undefined, 'getGoogleApiAuthorization', bm, true) as Promise<Bm.Res.GetGoogleApiAuthorization>,
        db: (bm: Bm.Db): Promise<Bm.Res.Db> => BrowserMsg.sendAwait(undefined, 'db', bm, true) as Promise<Bm.Res.Db>,
        ajax: (bm: Bm.Ajax): Promise<Bm.Res.Ajax> => BrowserMsg.sendAwait(undefined, 'ajax', bm, true) as Promise<Bm.Res.Ajax>,
        ajaxGmailAttachmentGetChunk: (bm: Bm.AjaxGmailAttachmentGetChunk) =>
          BrowserMsg.sendAwait(undefined, 'ajaxGmailAttachmentGetChunk', bm, true) as Promise<Bm.Res.AjaxGmailAttachmentGetChunk>,
        expirationCacheGet: <V>(bm: Bm.ExpirationCacheGet) =>
          BrowserMsg.sendAwait(undefined, 'expirationCacheGet', bm, true) as Promise<Bm.Res.ExpirationCacheGet<V>>,
        expirationCacheSet: <V>(bm: Bm.ExpirationCacheSet<V>) =>
          BrowserMsg.sendAwait(undefined, 'expirationCacheSet', bm, true) as Promise<Bm.Res.ExpirationCacheSet>,
        expirationCacheDeleteExpired: (bm: Bm.ExpirationCacheDeleteExpired) =>
          BrowserMsg.sendAwait(undefined, 'expirationCacheDeleteExpired', bm, true) as Promise<Bm.Res.ExpirationCacheDeleteExpired>,
      },
    },
    passphraseEntry: (bm: Bm.PassphraseEntry, sendCallback = Value.noop) => BrowserMsg.sendCatch('broadcast', 'passphrase_entry', bm, sendCallback, false),
    addEndSessionBtn: (dest: Bm.Dest) => BrowserMsg.sendCatch(dest, 'add_end_session_btn', {}),
    openPage: (dest: Bm.Dest, bm: Bm.OpenPage) => BrowserMsg.sendCatch(dest, 'open_page', bm),
    setCss: (dest: Bm.Dest, bm: Bm.SetCss) => BrowserMsg.sendCatch(dest, 'set_css', bm),
    addClass: (dest: Bm.Dest, bm: Bm.AddOrRemoveClass) => BrowserMsg.sendCatch(dest, 'add_class', bm),
    removeClass: (dest: Bm.Dest, bm: Bm.AddOrRemoveClass) => BrowserMsg.sendCatch(dest, 'remove_class', bm),
    closeDialog: (frame: ChildFrame) => BrowserMsg.sendToParentWindow(frame, 'close_dialog', {}),
    authWindowResult: (dest: Bm.Dest, bm: Bm.AuthWindowResult) => BrowserMsg.sendCatch(dest, 'auth_window_result', bm),
    closePage: (dest: Bm.Dest) => BrowserMsg.sendCatch(dest, 'close_page', {}),
    setActiveWindow: (dest: Bm.Dest, bm: Bm.ComposeWindow) => BrowserMsg.sendCatch(dest, 'set_active_window', bm),
    focusPreviousActiveWindow: (dest: Bm.Dest, bm: Bm.ComposeWindow) => BrowserMsg.sendCatch(dest, 'focus_previous_active_window', bm),
    closeComposeWindow: (dest: Bm.Dest, bm: Bm.ComposeWindow) => BrowserMsg.sendCatch(dest, 'close_compose_window', bm),
    focusBody: (dest: Bm.Dest) => BrowserMsg.sendCatch(dest, 'focus_body', {}),
    focusFrame: (dest: Bm.Dest, bm: Bm.ComposeWindow) => BrowserMsg.sendCatch(dest, 'focus_frame', bm),
    closeReplyMessage: (dest: Bm.Dest, bm: Bm.ComposeWindow) => BrowserMsg.sendCatch(dest, 'close_reply_message', bm),
    scrollToReplyBox: (dest: Bm.Dest, bm: Bm.ScrollToReplyBox) => BrowserMsg.sendCatch(dest, 'scroll_to_reply_box', bm),
    scrollToCursorInReplyBox: (dest: Bm.Dest, bm: Bm.ScrollToCursorInReplyBox) => BrowserMsg.sendCatch(dest, 'scroll_to_cursor_in_reply_box', bm),
    reinsertReplyBox: (dest: Bm.Dest, bm: Bm.ReinsertReplyBox) => BrowserMsg.sendCatch(dest, 'reinsert_reply_box', bm),
    passphraseDialog: (dest: Bm.Dest, bm: Bm.PassphraseDialog) => BrowserMsg.sendCatch(dest, 'passphrase_dialog', bm),
    notificationShow: (dest: Bm.Dest, bm: Bm.NotificationShow) => BrowserMsg.sendCatch(dest, 'notification_show', bm),
    notificationShowAuthPopupNeeded: (dest: Bm.Dest, bm: Bm.NotificationShowAuthPopupNeeded) =>
      BrowserMsg.sendCatch(dest, 'notification_show_auth_popup_needed', bm),
    showConfirmation: (frame: ChildFrame, bm: Bm.ShowConfirmation) => BrowserMsg.sendToParentWindow(frame, 'confirmation_show', bm, 'confirmation_result'),
    renderPublicKeys: (dest: Bm.Dest, bm: Bm.RenderPublicKeys) => BrowserMsg.sendCatch(dest, 'render_public_keys', bm),
    replyPubkeyMismatch: (dest: Bm.Dest) => BrowserMsg.sendCatch(dest, 'reply_pubkey_mismatch', {}),
    addPubkeyDialog: (dest: Bm.Dest, bm: Bm.AddPubkeyDialog) => BrowserMsg.sendCatch(dest, 'add_pubkey_dialog', bm),
    reload: (dest: Bm.Dest, bm: Bm.Reload) => BrowserMsg.sendCatch(dest, 'reload', bm),
    redirect: (dest: Bm.Dest, bm: Bm.Redirect) => BrowserMsg.sendCatch(dest, 'redirect', bm),
    addToContacts: (dest: Bm.Dest) => BrowserMsg.sendCatch(dest, 'addToContacts', {}),
    reRenderRecipient: (dest: Bm.Dest, bm: Bm.ReRenderRecipient) => BrowserMsg.sendCatch(dest, 'reRenderRecipient', bm),
    showAttachmentPreview: (frame: ChildFrame, bm: Bm.ShowAttachmentPreview) => BrowserMsg.sendToParentWindow(frame, 'show_attachment_preview', bm),
    ajaxProgress: (dest: Bm.Dest, bm: Bm.AjaxProgress) => BrowserMsg.sendCatch(dest, 'ajax_progress', bm),
    pgpBlockRender: (dest: Bm.Dest, bm: RenderMessage) => BrowserMsg.sendCatch(dest, 'pgp_block_render', bm),
    pgpBlockReady: (frame: ChildFrame, bm: Bm.PgpBlockReady) => BrowserMsg.sendToParentWindow(frame, 'pgp_block_ready', bm),
    pgpBlockRetry: (frame: ChildFrame, bm: Bm.PgpBlockRetry) => BrowserMsg.sendToParentWindow(frame, 'pgp_block_retry', bm),
    setHandlerReadyForPGPBlock: (dest: Bm.Dest) => {
      BrowserMsg.sendCatch(dest, 'set_handler_ready_for_pgp_block', {});
    },
  };
  private static readonly processed = new Set<string>(); // or ExpirationCache?
  /* eslint-disable @typescript-eslint/naming-convention */
  private static HANDLERS_REGISTERED_BACKGROUND: Handlers = {};
  private static INTERVAL_HANDLERS: Dict<IntervalHandler> = {};
  private static HANDLERS_REGISTERED_FRAME: Handlers = {
    set_css: BrowserMsgCommonHandlers.setCss,
    add_class: BrowserMsgCommonHandlers.addClass,
    remove_class: BrowserMsgCommonHandlers.removeClass,
  };
  /* eslint-enable @typescript-eslint/naming-convention */

  public static renderFatalErrCorner(message: string, style: 'GREEN-NOTIFICATION' | 'RED-RELOAD-PROMPT') {
    const div = document.createElement('div');
    div.textContent = message;
    div.style.position = 'fixed';
    div.style.bottom = '0';
    div.style.right = '0';
    div.style.fontSize = '12px';
    div.style.backgroundColor = '#31a217';
    div.style.color = 'white';
    div.style.padding = '1px 3px';
    div.style.zIndex = '1000';
    if (style === 'RED-RELOAD-PROMPT') {
      div.style.fontSize = '14px';
      div.style.backgroundColor = '#a44';
      div.style.padding = '4px 6px';
      const a = document.createElement('a');
      a.href = location.href.split('#')[0];
      a.textContent = 'RELOAD';
      a.style.color = 'white';
      a.style.fontWeight = 'bold';
      a.style.marginLeft = '12px';
      div.appendChild(a);
    }
    document.body.appendChild(div);
  }

  public static generateTabId(contentScript?: boolean) {
    return `${contentScript ? 'cs' : 'ex'}.${Str.sloppyRandom(10)}`;
  }

  public static async retryOnBgNotReadyErr<T>(operation: () => Promise<T>, maxAttempts = 10, delayMs = 300): Promise<T> {
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        return await operation();
      } catch (e) {
        if (!(e instanceof BgNotReadyErr) || attempt === maxAttempts - 1) {
          throw e;
        }
        await Ui.delay(delayMs);
      }
    }
    throw new BgNotReadyErr('Unexpected error after maximum retries');
  }

  public static addListener(name: string, handler: Handler) {
    BrowserMsg.HANDLERS_REGISTERED_FRAME[name] = handler;
  }

  public static listen(dest: Bm.Dest) {
    chrome.runtime.onMessage.addListener((msg: Bm.Raw, _sender, rawRespond: (rawResponse: Bm.RawResponse) => void) => {
      // console.debug(`listener(${dest}) new message: ${msg.name} to ${msg.to} with id ${msg.uid} from`, _sender);
      if (msg.to && [dest, 'broadcast'].includes(msg.to)) {
        BrowserMsg.handleMsg(msg, rawRespond);
      }
      return false; // will not respond as we only need response for BrowserMsg.send.bg.await
    });
    BrowserMsg.listenForWindowMessages(dest);
  }

  public static bgAddListener(name: string, handler: Handler) {
    BrowserMsg.HANDLERS_REGISTERED_BACKGROUND[name] = handler;
  }

  public static createIntervalAlarm(action: string, periodInMinutes: number) {
    const alarmName = `${action}_interval_${Date.now()}`;
    void chrome.alarms.create(alarmName, { periodInMinutes });
  }

  public static intervalAddListener(name: string, handler: IntervalHandler) {
    BrowserMsg.INTERVAL_HANDLERS[name] = handler;
  }

  public static bgListen() {
    chrome.runtime.onMessage.addListener((msg: Bm.Raw, _sender, rawRespond: (rawRes: Bm.RawResponse) => void) => {
      const respondIfPageStillOpen = (response: Bm.RawResponse) => {
        try {
          // avoiding unnecessary errors when target tab gets closed
          rawRespond(response);
        } catch (cannotRespondErr) {
          if (cannotRespondErr instanceof Error && cannotRespondErr.message === 'Attempting to use a disconnected port object') {
            // the page we're responding to is closed - ec when closing secure compose
          } else {
            if (cannotRespondErr instanceof Error) {
              cannotRespondErr.stack += `\n\nOriginal msg sender stack: ${msg.stack}`;
            }
            Catch.reportErr(Catch.rewrapErr(cannotRespondErr, `BrowserMsg.bgListen.respondIfPageStillOpen:${msg.name}`));
          }
        }
      };
      try {
        if (Object.keys(BrowserMsg.HANDLERS_REGISTERED_BACKGROUND).includes(msg.name)) {
          // standard or broadcast message
          const handler: Bm.AsyncRespondingHandler = BrowserMsg.HANDLERS_REGISTERED_BACKGROUND[msg.name];
          BrowserMsg.sendRawResponse(handler(msg.data.bm), respondIfPageStillOpen);
          return true; // will respond
        } else {
          // broadcast message that backend does not have a handler for - ignored
          return false; // no plans to respond
        }
      } catch (exception) {
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
        BrowserMsg.sendRawResponse(Promise.reject(exception), respondIfPageStillOpen);
        return true; // will respond
      }
    });
  }

  public static alarmListen() {
    const alarmListener = (alarm: { name: string }) => {
      const alarmName = alarm.name;
      const actionName = alarmName.split('_interval')[0];
      if (BrowserMsg.INTERVAL_HANDLERS[actionName]) {
        Catch.try(BrowserMsg.INTERVAL_HANDLERS[actionName])();
      }
    };

    chrome.alarms.onAlarm.addListener(alarmListener);
  }

  protected static listenForWindowMessages(dest: Bm.Dest) {
    const extensionOrigin = Env.getExtensionOrigin();

    addEventListener('message', e => {
      if (e.origin !== 'https://mail.google.com' && e.origin !== extensionOrigin) return;
      const encryptedMsg = e.data as SymEncryptedMessage;
      if (!encryptedMsg || typeof encryptedMsg.uid !== 'string' || BrowserMsg.processed.has(encryptedMsg.uid)) return;
      Catch.try(async () => {
        let handled = false;
        if ([dest, 'broadcast'].includes(encryptedMsg.to)) {
          const msg = await SymmetricMessageEncryption.decrypt(encryptedMsg);
          handled = BrowserMsg.handleMsg(msg, (rawResponse: Bm.RawResponse) => {
            if (msg.responseName && typeof msg.data.bm.messageSender !== 'undefined') {
              // send response as a new request
              BrowserMsg.sendRaw(msg.data.bm.messageSender, msg.responseName, rawResponse.result as Dict<unknown>).catch(Catch.reportErr);
            }
          });
        }
        if (!handled && encryptedMsg.propagateToParent) {
          BrowserMsg.processed.add(encryptedMsg.uid);
          BrowserMsg.sendUpParentLine(encryptedMsg);
        }
      })();
    });
  }

  private static sendToParentWindow(parentReference: ChildFrame, name: string, bm: Dict<unknown> & { messageSender?: Bm.Dest }, responseName?: string) {
    const raw: Bm.RawWithWindowExtensions = {
      data: { bm },
      name,
      stack: '',
      to: parentReference.parentTabId,
      uid: SymmetricMessageEncryption.generateIV(),
      responseName,
    };
    Catch.try(async () => {
      BrowserMsg.sendUpParentLine(await SymmetricMessageEncryption.encrypt(raw));
    })();
  }

  private static sendToChildren(encryptedMsg: SymEncryptedMessage) {
    const extensionOrigin = Env.getExtensionOrigin();
    const childFrames = Array.from(document.querySelectorAll('iframe'));
    const childFramesWithExtensionOrigin = childFrames.filter(iframe => {
      try {
        const iframeOrigin = new URL(iframe.src).origin;
        return iframeOrigin === extensionOrigin;
      } catch {
        return false;
      }
    });
    for (const childFrame of childFramesWithExtensionOrigin) {
      childFrame.contentWindow?.postMessage(encryptedMsg, extensionOrigin);
    }
  }

  private static handleMsg(msg: Bm.Raw, rawRespond: (rawResponse: Bm.RawResponse) => void) {
    try {
      if (!BrowserMsg.processed.has(msg.uid)) {
        BrowserMsg.processed.add(msg.uid);
        if (typeof BrowserMsg.HANDLERS_REGISTERED_FRAME[msg.name] !== 'undefined') {
          const handler: Bm.AsyncRespondingHandler = BrowserMsg.HANDLERS_REGISTERED_FRAME[msg.name];
          BrowserMsg.sendRawResponse(handler(msg.data.bm), rawRespond);
          return true;
        }
      } else {
        // sometimes received events get duplicated
        // while first event is being processed, second even will arrive
        // that's why we generate a unique id of each request (uid) and filter them above to identify truly unique requests
        // if we got here, that means we are handing a duplicate request
        // we'll indicate will respond = true, so that the processing of the actual request is not negatively affected
        // leaving it at "false" would respond with null, which would throw an error back to the original BrowserMsg sender:
        // "Error: BrowserMsg.sendAwait(pgpMsgDiagnosePubkeys) returned(null) with lastError: (no lastError)"
        // the duplication is likely caused by our routing mechanism. Sometimes browser will deliver the message directly as well as through bg
      }
    } catch (e) {
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
      BrowserMsg.sendRawResponse(Promise.reject(e), rawRespond);
    }
    return false;
  }

  private static sendCatch = (dest: Bm.Dest | undefined, name: string, bm: Dict<unknown>, sendCallback = Value.noop, postToSelf = true) => {
    BrowserMsg.sendAwait(dest, name, bm, false, sendCallback, postToSelf).catch(Catch.reportErr);
  };

  private static sendAwait = async (
    destString: string | undefined,
    name: string,
    bm?: Dict<unknown>,
    awaitRes = false,
    sendCallback = Value.noop,
    postToSelf = true
  ): Promise<Bm.Response> => {
    bm = bm || {};
    // console.debug(`sendAwait ${name} to ${destString || 'bg'}`, bm);
    const isBackgroundPage = Env.isBackgroundPage();
    if (isBackgroundPage && BrowserMsg.HANDLERS_REGISTERED_BACKGROUND && typeof destString === 'undefined') {
      // calling from bg script to bg script: skip messaging
      const handler: Bm.AsyncRespondingHandler = BrowserMsg.HANDLERS_REGISTERED_BACKGROUND[name];
      return await handler(bm);
    }
    return await BrowserMsg.sendRaw(destString, name, bm, awaitRes, sendCallback, postToSelf);
  };

  private static sendRaw = async (
    destString: string | undefined,
    name: string,
    bm: Dict<unknown>,
    awaitRes = false,
    sendCallback = Value.noop,
    postToSelf = true
  ): Promise<Bm.Response> => {
    const msg: Bm.Raw = {
      name,
      data: { bm },
      to: destString || null, // eslint-disable-line no-null/no-null
      uid: SymmetricMessageEncryption.generateIV(),
      stack: Catch.stackTrace(),
    };
    const runtimeMessagePromise = new Promise((resolve, reject) => {
      const processRawMsgResponse = (r: Bm.RawResponse) => {
        if (!awaitRes) {
          resolve(undefined);
        } else if (!r || typeof r !== 'object') {
          // r can be null if we sent a message to a non-existent window id
          const lastError = chrome.runtime.lastError ? chrome.runtime.lastError.message || '(empty lastError)' : '(no lastError)';
          let e: Error;
          if (typeof destString === 'undefined' && typeof r === 'undefined') {
            if (lastError === 'The object could not be cloned.') {
              e = new Error(`BrowserMsg.sendAwait(${name}) failed with lastError: ${lastError}`);
            } else if (
              lastError === 'Could not establish connection. Receiving end does not exist.' ||
              lastError === 'The message port closed before a response was received.'
            ) {
              // "The message port closed before a response was received." could also happen for otherwise working extension, if bg script
              //    did not return `true` (indicating async response). That would be our own coding error in BrowserMsg.
              e = new BgNotReadyErr(`BgNotReadyErr: BrowserMsg.sendAwait(${name}) failed with lastError: ${lastError}`);
            } else {
              e = new Error(`BrowserMsg.sendAwait(${name}) failed with unknown lastError: ${lastError}`);
            }
          } else {
            e = new Error(`BrowserMsg.sendAwait(${name}) returned(${String(r)}) with lastError: ${lastError}`);
          }
          e.stack = `${msg.stack}\n\n${e.stack}`;
          reject(e);
        } else if (typeof r === 'object' && r.exception) {
          reject(BrowserMsg.jsonToErr(r.exception, msg));
        } else if (!r.result || typeof r.result !== 'object') {
          resolve(r.result);
        } else {
          resolve(r.result);
        }
      };
      try {
        if (chrome.runtime) {
          if (Env.isBackgroundPage()) {
            chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
              for (const tab of tabs) {
                chrome.tabs.sendMessage(Number(tab.id), msg, resolve);
              }
            });
          } else {
            if (awaitRes) {
              chrome.runtime.sendMessage(msg, processRawMsgResponse);
            } else {
              void chrome.runtime.sendMessage(msg);
            }
          }
        } else {
          BrowserMsg.renderFatalErrCorner('Error: missing chrome.runtime', 'RED-RELOAD-PROMPT');
        }
      } catch (e) {
        if (e instanceof Error && e.message === 'Extension context invalidated.') {
          BrowserMsg.renderFatalErrCorner('Restart browser to re-enable FlowCrypt', 'GREEN-NOTIFICATION');
        } else {
          throw e;
        }
      }
    });
    // eslint-disable-next-line no-null/no-null
    if (!Env.isBackgroundPage() && msg.to !== null) {
      // send via window messaging in parallel
      const validMsg: Bm.RawWithWindowExtensions = { ...msg, to: msg.to };
      // todo: can objUrls be deleted by another recipient?
      const encryptedMsg = await SymmetricMessageEncryption.encrypt(validMsg);
      BrowserMsg.sendToChildren(encryptedMsg);
      if (postToSelf) {
        window.postMessage(encryptedMsg, '*');
      }
      BrowserMsg.sendUpParentLine(encryptedMsg);
    }
    sendCallback();
    // only runtimeMessagePromise can potentially yield a result
    return runtimeMessagePromise;
  };

  private static sendUpParentLine(encryptedMsg: SymEncryptedMessage) {
    const encryptedWithPropagationFlag: SymEncryptedMessage = { ...encryptedMsg, propagateToParent: true };
    let w: Window = window;
    while (w.parent && w.parent !== w) {
      w = w.parent;
      parent.postMessage(encryptedWithPropagationFlag, '*');
    }
  }

  private static errToJson(e: unknown): Bm.ErrAsJson {
    if (e instanceof AjaxErr) {
      const { message, stack, status, url, responseText, statusText, resMsg, resDetails } = e;
      return {
        stack,
        message,
        errorConstructor: 'AjaxErr',
        ajaxErrorDetails: { status, url, responseText, statusText, resMsg, resDetails },
      };
    }
    const { stack, message } = Catch.rewrapErr(e, 'sendRawResponse');
    return { stack, message, errorConstructor: 'Error' };
  }

  private static jsonToErr(errAsJson: Bm.ErrAsJson, msg: Bm.Raw) {
    const stackInfo = `\n\n[callerStack]\n${msg.stack}\n[/callerStack]\n\n[responderStack]\n${errAsJson.stack}\n[/responderStack]\n`;
    if (errAsJson.errorConstructor === 'AjaxErr') {
      const { status, url, responseText, statusText, resMsg, resDetails } = errAsJson.ajaxErrorDetails;
      return new AjaxErr(`BrowserMsg(${msg.name}) ${errAsJson.message}`, stackInfo, status, url, responseText, statusText, resMsg, resDetails);
    }
    const e = new Error(`BrowserMsg(${msg.name}) ${errAsJson.message}`);
    e.stack += stackInfo;
    return e;
  }

  private static sendRawResponse(handlerPromise: Promise<Bm.Res.Any>, rawRespond: (rawResponse: Bm.RawResponse) => void) {
    try {
      handlerPromise
        .then(result => {
          rawRespond({ result, exception: undefined });
        })
        .catch((e: unknown) => {
          rawRespond({ result: undefined, exception: BrowserMsg.errToJson(e) });
        });
    } catch (e) {
      rawRespond({ result: undefined, exception: BrowserMsg.errToJson(e) });
    }
  }
}
