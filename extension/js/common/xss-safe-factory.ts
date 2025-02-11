/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

// eslint-disable-next-line @typescript-eslint/triple-slash-reference
/// <reference path="../../../node_modules/@types/chrome/index.d.ts" />

'use strict';

import { Dict, Str, Url, UrlParams } from './core/common.js';
import { Attachment } from './core/attachment.js';
import { Browser } from './browser/browser.js';
import { BrowserMsg } from './browser/browser-msg.js';
import { Catch } from './platform/catch.js';
import { MsgBlock } from './core/msg-block.js';
import { PgpArmor } from './core/crypto/pgp/pgp-armor.js';
import { Ui } from './browser/ui.js';
import { WebMailName, WebMailVersion } from './browser/env.js';
import { Xss } from './platform/xss.js';
import { Buf } from './core/buf.js';
import { ReplyOption } from '../../chrome/elements/compose-modules/compose-reply-btn-popover-module.js';

type Placement = 'settings' | 'settings_compose' | 'default' | 'dialog' | 'gmail' | 'embedded' | 'compose';
export type WebmailVariantString = undefined | 'html' | 'standard' | 'new';
export type PassphraseDialogType = 'embedded' | 'message' | 'attachment' | 'draft' | 'sign' | `quote` | `backup` | 'update_key';
export type FactoryReplyParams = {
  replyMsgId?: string;
  draftId?: string;
  subject?: string;
  removeAfterClose?: boolean;
  replyOption?: ReplyOption;
};

export class XssSafeFactory {
  /**
   * XSS WARNING
   *
   * Method return values are inserted directly into DOM.
   *
   * All public methods are expected to escape unknown content to prevent XSS.
   *
   * If you add or edit a method, REQUEST A SECOND SET OF EYES TO REVIEW CHANGES
   */

  private setParams: UrlParams;
  private reloadableCls: string;
  private destroyableCls: string;
  private hideGmailNewMsgInThreadNotification = '<style>.ata-asE { display: none !important; visibility: hidden !important; }</style>';

  public constructor(acctEmail: string, parentTabId: string, reloadableCls = '', destroyableCls = '', setParams: UrlParams = {}) {
    this.reloadableCls = Xss.escape(reloadableCls);
    this.destroyableCls = Xss.escape(destroyableCls);
    this.setParams = setParams;
    this.setParams.acctEmail = acctEmail;
    this.setParams.parentTabId = parentTabId;
  }

  /**
   * XSS WARNING
   *
   * Return values are inserted directly into DOM. Results must be html escaped.
   *
   * When edited, REQUEST A SECOND SET OF EYES TO REVIEW CHANGES
   */
  public static renderableMsgBlock = (factory: XssSafeFactory, block: MsgBlock, isOutgoing?: boolean) => {
    if (block.type === 'plainText') {
      return XssSafeFactory.renderPlainContent(block.content);
    } else if (block.type === 'plainHtml') {
      return Xss.htmlSanitizeAndStripAllTags(Str.with(block.content), '<br>') + '<br><br>';
    } else if (block.type === 'publicKey') {
      return factory.embeddedPubkey(PgpArmor.normalize(Str.with(block.content), 'publicKey'), isOutgoing);
    } else if (block.type === 'privateKey') {
      return factory.embeddedBackup(PgpArmor.normalize(Str.with(block.content), 'privateKey'));
    } else if (block.type === 'certificate') {
      return factory.embeddedPubkey(Str.with(block.content), isOutgoing);
    } else if (['encryptedAttachment', 'plainAttachment'].includes(block.type)) {
      return block.attachmentMeta
        ? factory.embeddedAttachment(new Attachment(block.attachmentMeta), block.type === 'encryptedAttachment')
        : '[missing encrypted attachment details]';
    } else {
      Catch.report(`don't know how to process block type: ${block.type} (not a hard fail)`);
      return '';
    }
  };

  public static renderPlainContent = (content: string | Buf) => {
    return Xss.escape(Str.with(content)).replace(/\n/g, '<br>') + '<br><br>';
  };
  /**
   * XSS WARNING
   *
   * Return values are inserted directly into DOM. Results must be html escaped.
   *
   * When edited, REQUEST A SECOND SET OF EYES TO REVIEW CHANGES
   */

  public srcImg = (relPath: string) => {
    return this.extUrl(`img/${relPath}`);
  };

  public srcComposeMsg = (draftId?: string, useFullScreenSecureCompose?: boolean, thunderbirdMsgId?: number, replyOption?: string, replyMsgId?: string) => {
    return this.frameSrc(this.extUrl('chrome/elements/compose.htm'), {
      frameId: this.newId(),
      draftId,
      useFullScreenSecureCompose,
      thunderbirdMsgId,
      replyOption,
      replyMsgId,
    });
  };

  public srcPassphraseDialog = (longids: string[] = [], type: PassphraseDialogType, initiatorFrameId?: string) => {
    return this.frameSrc(this.extUrl('chrome/elements/passphrase.htm'), { type, longids, initiatorFrameId });
  };

  public srcAddPubkeyDialog = (emails: string[], placement: Placement) => {
    return this.frameSrc(this.extUrl('chrome/elements/add_pubkey.htm'), { emails, placement });
  };

  public srcPgpAttachmentIframe = (
    a: Attachment,
    isEncrypted: boolean,
    parentTabId?: string,
    iframeUrl = 'chrome/elements/attachment.htm',
    errorDetailsOpened?: boolean,
    initiatorFrameId?: string
  ) => {
    if (!a.id && !a.url && a.hasData()) {
      // data provided directly, pass as object url
      a.url = Browser.objUrlCreate(a.getData());
    }
    return this.frameSrc(
      this.extUrl(iframeUrl),
      {
        frameId: this.newId(),
        msgId: a.msgId,
        name: a.name,
        type: a.type,
        size: a.length,
        attachmentId: a.id,
        url: a.url,
        isEncrypted,
        errorDetailsOpened,
        initiatorFrameId,
      },
      parentTabId
    );
  };

  public srcPgpBlockIframe = () => {
    const frameId = this.newId();
    return {
      frameId,
      frameSrc: this.frameSrc(this.extUrl('chrome/elements/pgp_block.htm'), {
        frameId,
      }),
    };
  };

  public srcPgpPubkeyIframe = (armoredPubkey: string, isOutgoing?: boolean) => {
    return this.frameSrc(this.extUrl('chrome/elements/pgp_pubkey.htm'), {
      frameId: this.newId(),
      armoredPubkey,
      minimized: Boolean(isOutgoing),
    });
  };

  public srcBackupIframe = (armoredPrvBackup: string) => {
    return this.frameSrc(this.extUrl('chrome/elements/backup.htm'), { frameId: this.newId(), armoredPrvBackup });
  };

  public srcReplyMsgIframe = (convoParams: FactoryReplyParams, skipClickPrompt: boolean, ignoreDraft: boolean) => {
    const params: UrlParams = {
      isReplyBox: true,
      frameId: `frame_${Str.sloppyRandom(10)}`,
      skipClickPrompt: Boolean(skipClickPrompt),
      ignoreDraft: Boolean(ignoreDraft),
      replyMsgId: convoParams.replyMsgId,
      draftId: convoParams.draftId,
      removeAfterClose: convoParams.removeAfterClose,
      replyOption: convoParams.replyOption,
    };
    return this.frameSrc(this.extUrl('chrome/elements/compose.htm'), params);
  };

  public metaNotificationContainer = () => {
    return `<div class="${this.destroyableCls} webmail_notifications" style="text-align: center;"></div>`;
  };

  public metaStylesheet = (file: string) => {
    return `<link class="${this.destroyableCls}" rel="stylesheet" href="${this.extUrl(`css/${file}.css`)}" />`;
  };

  public showPassphraseDialog = async (longids: string[], type: PassphraseDialogType, initiatorFrameId?: string) => {
    const result = await Ui.modal.iframe(this.srcPassphraseDialog(longids, type, initiatorFrameId), 500, 'dialog-passphrase');
    if (result.dismiss) {
      // dialog is dismissed by user interaction, not by closeDialog()
      BrowserMsg.send.passphraseEntry({ entered: false });
    }
  };

  public showAddPubkeyDialog = async (emails: string[]) => {
    await Ui.modal.iframe(this.srcAddPubkeyDialog(emails, 'gmail'), undefined, 'dialog-add-pubkey');
  };

  public embeddedCompose = (draftId?: string, openInFullScreen?: boolean, thunderbirdMsgId?: number, replyOption?: string, replyMsgId?: string) => {
    const srcComposeMsg = this.srcComposeMsg(draftId, openInFullScreen, thunderbirdMsgId, replyOption, replyMsgId);
    return Ui.e('div', {
      class: openInFullScreen ? 'secure_compose_window active full_window' : 'secure_compose_window',
      html: this.iframe(srcComposeMsg, [], { scrolling: 'no' }),
      'data-frame-id': String(Url.parse(['frameId'], srcComposeMsg).frameId),
      'data-test': 'container-new-message',
    });
  };

  public embeddedAttachment = (meta: Attachment, isEncrypted: boolean, parentTabId?: string) => {
    return Ui.e('span', {
      class: 'pgp_attachment',
      html: this.iframe(this.srcPgpAttachmentIframe(meta, isEncrypted, parentTabId)),
    });
  };

  public embeddedMsg = (
    type: string // for diagnostic purposes
  ) => {
    const { frameId, frameSrc } = this.srcPgpBlockIframe();
    return { frameId, frameXssSafe: this.iframe(frameSrc, ['pgp_block', type]) + this.hideGmailNewMsgInThreadNotification }; // xss-safe-factory
  };

  public embeddedPubkey = (armoredPubkey: string, isOutgoing?: boolean) => {
    return this.iframe(this.srcPgpPubkeyIframe(armoredPubkey, isOutgoing), ['pgp_block', 'publicKey']);
  };

  public embeddedBackup = (armoredPrvBackup: string) => {
    return this.iframe(this.srcBackupIframe(armoredPrvBackup), ['backup_block']);
  };

  public embeddedReply = (convoParams: FactoryReplyParams, skipClickPrompt: boolean, ignoreDraft = false) => {
    return this.iframe(this.srcReplyMsgIframe(convoParams, skipClickPrompt, ignoreDraft), ['reply_message']);
  };

  public embeddedPassphrase = (longids: string[]) => {
    return this.iframe(this.srcPassphraseDialog(longids, 'embedded'), [], { 'data-test': 'embedded-passphrase' }); // xss-safe-factory
  };

  public embeddedAttachmentStatus = (content: string) => {
    return Ui.e('div', { class: 'attachment_loader', html: Xss.htmlSanitize(content) });
  };

  public btnCompose = (webmailName: WebMailName, webmailVersion: WebMailVersion) => {
    if (webmailName === 'outlook') {
      const btn = `<div class="new_secure_compose_window_button" id="flowcrypt_secure_compose_button_icon" title="New Secure Email"><img src="${this.srcImg(
        'logo-19-19.png'
      )}"></div>`;
      return `<div id="flowcrypt_secure_compose_button" class="_fce_c ${this.destroyableCls} cryptup_compose_button_container" role="presentation">${btn}</div>`;
    } else {
      const elAttrs = 'data-tooltip="Secure Compose" aria-label="Secure Compose" id="flowcrypt_secure_compose_button_icon"';
      const title = 'Secure Compose';
      const btnEl =
        webmailVersion === 'gmail2022' ? `<div class="compose_icon_simple" ${elAttrs}></div><div class="apW">${title}</div>` : `<div ${elAttrs}>${title}</div>`;
      const containerCls = webmailVersion === 'gmail2022' ? 'pb-25px' : 'z0';
      return `<div class="${this.destroyableCls} ${containerCls}" id="flowcrypt_secure_compose_button" role="button" tabindex="0" data-test="action-secure-compose" >${btnEl}</div>`;
    }
  };

  public btnSecureReply = () => {
    return `<div class="${
      this.destroyableCls
    } reply_message_button" data-test="secure-reply-button" role="button" tabindex="0" data-tooltip="Secure Reply" aria-label="Secure Reply">
      <img title="Secure Reply" src="${this.srcImg('svgs/reply-icon.svg')}" />
      </div>`;
  };

  public btnSecureMenuBtn = (replyOption: ReplyOption) => {
    const actionText = replyOption.replace('a_', '').replace('_', ' ');
    const action = {
      underscore: actionText.replace(' ', '_'),
      hyphen: actionText.replace(' ', '-'),
    };
    // * The action_${action.underscore}_message_button is used as an identifier in GmailElementReplacer.actionActivateSecureReplyHandler()
    return `<div class="action_${action.underscore}_message_button action_menu_message_button" data-test="action-${action.hyphen}-message-button">
    <img src="${this.srcImg(`svgs/${action.hyphen}-icon.svg`)}" /><span>secure ${actionText}</span>
    </div>`;
  };

  public btnEndPPSession = (webmailName: string) => {
    return `<a href="#" class="action_finish_session" title="End Pass Phrase Session" data-test="action-finish-session">
              <img src="${this.srcImg('svgs/unlock.svg')}">
              ${webmailName === 'gmail' ? 'End Pass Phrase Session' : ''}
            </a>`;
  };

  public btnWithoutFc = () => {
    const span = `<span>see original</span>`;
    return `<span class="hk J-J5-Ji cryptup_convo_button show_original_conversation ${this.destroyableCls}" data-test="action-show-original-conversation" data-tooltip="Show conversation without FlowCrypt">${span}</span>`;
  };

  public btnWithFc = () => {
    return `<span class="hk J-J5-Ji cryptup_convo_button use_secure_reply ${this.destroyableCls}" data-tooltip="Use Secure Reply"><span>secure reply</span></span>`;
  };

  public btnRecipientsUseEncryption = (webmailName: WebMailName) => {
    if (webmailName !== 'gmail') {
      Catch.report('switch_to_secure not implemented for ' + webmailName);
      return '';
    } else {
      return '<div class="aoD az6 recipients_use_encryption">Your recipients seem to have encryption set up! <a href="#">Secure Compose</a></div>';
    }
  };

  public btnSettings = (webmailName: WebMailName) => {
    if (webmailName !== 'gmail') {
      Catch.report('btnSettings not implemented for ' + webmailName);
      return '';
    } else {
      return `<div id="fc_settings_btn" class="f1">FlowCrypt</div>`;
    }
  };

  private frameSrc = (path: string, params: UrlParams = {}, parentTabId?: string) => {
    for (const k of Object.keys(this.setParams)) {
      params[k] = this.setParams[k];
    }
    if (parentTabId) {
      params.parentTabId = parentTabId;
    }
    return Url.create(path, params);
  };

  private extUrl = (s: string) => {
    return chrome.runtime.getURL(s);
  };

  private newId = () => {
    return `frame_${Str.sloppyRandom(10)}`;
  };

  private iframe = (src: string, classes: string[] = [], elAttributes: UrlParams = {}) => {
    const id = String(Url.parse(['frameId'], src).frameId);
    const classAttribute = (classes || []).concat(this.reloadableCls).join(' ');
    const attrs: Dict<string> = { id, class: classAttribute, src };
    for (const name of Object.keys(elAttributes)) {
      attrs[name] = String(elAttributes[name]);
    }
    return Ui.e('iframe', attrs);
  };
}
