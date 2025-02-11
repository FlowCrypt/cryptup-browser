/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Dict, Str } from '../../../common/core/common.js';
import { FactoryReplyParams, XssSafeFactory } from '../../../common/xss-safe-factory.js';
import { ApiErr } from '../../../common/api/shared/api-error.js';
import { Attachment } from '../../../common/core/attachment.js';
import { BrowserMsg } from '../../../common/browser/browser-msg.js';
import { Catch } from '../../../common/platform/catch.js';
import { GlobalStore, LocalDraft } from '../../../common/platform/store/global-store.js';
import { Injector } from '../../../common/inject.js';
import { PubLookup } from '../../../common/api/pub-lookup.js';
import { Notifications } from '../../../common/notifications.js';
import { PgpArmor } from '../../../common/core/crypto/pgp/pgp-armor.js';
import { Ui } from '../../../common/browser/ui.js';
import { WebmailCommon } from '../../../common/webmail.js';
import { Xss } from '../../../common/platform/xss.js';
import { ClientConfiguration } from '../../../common/client-configuration.js';
// todo: can we somehow define a purely relay class for ContactStore to clearly show that crypto-libraries are not loaded and can't be used?
import { ContactStore } from '../../../common/platform/store/contact-store.js';
import { MessageRenderer } from '../../../common/message-renderer.js';
import { RelayManager } from '../../../common/relay-manager.js';
import { MessageInfo } from '../../../common/render-message.js';
import { GmailLoaderContext } from './gmail-loader-context.js';
import { MessageBody, Mime } from '../../../common/core/mime.js';
import { MsgBlock } from '../../../common/core/msg-block.js';
import { ReplyOption } from '../../../../chrome/elements/compose-modules/compose-reply-btn-popover-module.js';
import { WebmailElementReplacer, IntervalFunction } from '../generic/webmail-element-replacer.js';

export class GmailElementReplacer extends WebmailElementReplacer {
  private debug = false;

  private recipientHasPgpCache: Dict<boolean> = {};
  private pubLookup: PubLookup;
  private webmailCommon: WebmailCommon;
  private currentlyEvaluatingStandardComposeBoxRecipients = false;
  private currentlyReplacingAttachments = false;
  private switchToEncryptedReply = false;
  private removeNextReplyBoxBorders = false;
  private lastSwitchToEncryptedReply = false;
  private replyOption: ReplyOption | undefined;
  private lastReplyOption: ReplyOption | undefined;

  private sel = {
    // gmail_variant=standard|new
    convoRoot: 'div.if',
    convoRootScrollable: '.Tm.aeJ',
    subject: 'h2.hP',
    autoReplies: 'div.brb',
    msgOuter: 'div.adn',
    msgInner: 'div.a3s:visible:not(.undefined), .message_inner_body:visible',
    msgInnerText: 'table.cf.An',
    msgInnerContainingPgp: "div.a3s:not(.undefined):contains('" + PgpArmor.headers('null').begin + "')",
    msgActionsBtn: '.J-J5-Ji.aap',
    msgActionsMenu: '.b7.J-M',
    attachmentsContainerOuter: 'div.hq.gt',
    attachmentsContainerInner: 'div.aQH',
    translatePrompt: '.adI, .wl4W9b',
    standardComposeWin: '.aaZ:visible',
    replyOptionImg: 'div.J-JN-M-I-Jm',
    settingsBtnContainer: 'div.aeH > div > .fY',
    standardComposeRecipient: 'div.az9 span[email][data-hovercard-id]',
    numberOfAttachments: '.aVW',
    numberOfAttachmentsLabel: '.aVW span:first-child',
    attachmentsButtons: '.aZi',
    draftsList: '.ae4',
  };

  public constructor(
    private readonly factory: XssSafeFactory,
    clientConfiguration: ClientConfiguration,
    private readonly acctEmail: string,
    private readonly messageRenderer: MessageRenderer,
    private readonly injector: Injector,
    private readonly notifications: Notifications,
    private readonly relayManager: RelayManager
  ) {
    super();
    this.webmailCommon = new WebmailCommon(acctEmail, injector);
    this.pubLookup = new PubLookup(clientConfiguration);
    this.setupSecureActionsOnGmailMenu();
  }

  public getIntervalFunctions = (): IntervalFunction[] => {
    return [
      { interval: 1000, handler: () => this.everything() },
      { interval: 30000, handler: () => this.webmailCommon.addOrRemoveEndSessionBtnIfNeeded() },
    ];
  };

  public setReplyBoxEditable = async (replyOption?: ReplyOption) => {
    const replyContainerIframe = $('.reply_message_iframe_container > iframe').last();
    if (replyContainerIframe.length) {
      $(replyContainerIframe).replaceWith(
        this.factory.embeddedReply(this.getLastMsgReplyParams(this.getConvoRootEl(replyContainerIframe[0]), replyOption), true)
      ); // xss-safe-value
    } else {
      await this.replaceStandardReplyBox(undefined, true);
    }
  };

  public reinsertReplyBox = (replyMsgId: string) => {
    const params: FactoryReplyParams = { replyMsgId };
    $('.reply_message_iframe_container:visible')
      .last()
      .append(this.factory.embeddedReply(params, false, true)); // xss-safe-value
  };

  public scrollToReplyBox = (replyMsgId: string) => {
    const convoRootScrollable = $(this.sel.convoRootScrollable);
    if (convoRootScrollable) {
      const replyMsg = $(replyMsgId);
      if (replyMsg) {
        convoRootScrollable.css('scroll-behavior', 'smooth');
        const gmailHeaderHeight = 120;
        const topGap = 80; // so the bottom of the prev message will be visible
        // scroll to the bottom of the element,
        // or to the top of the element if the element's height is bigger than the convoRoot
        /* eslint-disable @typescript-eslint/no-non-null-assertion */
        convoRootScrollable.get(0)!.scrollTop =
          replyMsg.position().top + $(replyMsg).height()! - Math.max(0, $(replyMsg).height()! - convoRootScrollable.height()! + gmailHeaderHeight + topGap);
        /* eslint-enable @typescript-eslint/no-non-null-assertion */
      }
    } else if (/^#inbox\/[a-zA-Z]+$/.exec(window.location.hash)) {
      // is a conversation view, but no scrollable conversation element
      Catch.report(`Cannot find Gmail scrollable element: ${this.sel.convoRootScrollable}`);
    }
  };

  public scrollToCursorInReplyBox = (replyMsgId: string, cursorOffsetTop: number) => {
    const convoRootScrollable = $(this.sel.convoRootScrollable);
    if (convoRootScrollable) {
      const replyMsg = $(replyMsgId);
      /* eslint-disable @typescript-eslint/no-non-null-assertion */
      const replyMsgOffsetTop = replyMsg.offset()!.top - convoRootScrollable.offset()!.top;
      const bottomGap = 150;
      // check if cursor went above the visible part of convoRootScrollable
      if (replyMsgOffsetTop + cursorOffsetTop < 0) {
        convoRootScrollable.css('scroll-behavior', '');
        convoRootScrollable.get(0)!.scrollTop += replyMsgOffsetTop + cursorOffsetTop;
      }
      // check if cursor went below the visible part of convoRootScrollable
      if (replyMsgOffsetTop + cursorOffsetTop > convoRootScrollable.get(0)!.clientHeight - bottomGap) {
        convoRootScrollable.css('scroll-behavior', '');
        convoRootScrollable.get(0)!.scrollTop += replyMsgOffsetTop + cursorOffsetTop - convoRootScrollable.get(0)!.clientHeight + bottomGap;
      }
      /* eslint-enable @typescript-eslint/no-non-null-assertion */
    }
  };

  public setupSecureActionsOnGmailMenu = () => {
    const observer = new MutationObserver(() => {
      const gmailActionsMenu = document.querySelector(this.sel.msgActionsMenu);
      if (gmailActionsMenu && (gmailActionsMenu as HTMLElement).offsetParent !== undefined) {
        this.addSecureActionsToMessageMenu();
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  };

  private everything = () => {
    this.replaceArmoredBlocks().catch(Catch.reportErr);
    this.replaceAttachments().catch(Catch.reportErr);
    this.replaceComposeDraftLinks();
    this.replaceConvoBtns();
    this.replaceStandardReplyBox().catch(Catch.reportErr);
    this.evaluateStandardComposeRecipients().catch(Catch.reportErr);
    this.addSettingsBtn();
    this.renderLocalDrafts().catch(Catch.reportErr);
  };

  private replaceArmoredBlocks = async () => {
    const emailsContainingPgpBlock = $(this.sel.msgOuter).find(this.sel.msgInnerContainingPgp).not('.evaluated');
    for (const emailContainer of emailsContainingPgpBlock) {
      if (this.debug) {
        console.debug('replaceArmoredBlocks() for of emailsContainingPgpBlock -> emailContainer', emailContainer);
      }
      $(emailContainer).addClass('evaluated');
      if (this.debug) {
        console.debug('replaceArmoredBlocks() for of emailsContainingPgpBlock -> emailContainer added evaluated');
      }
      const msgId = this.determineMsgId(emailContainer);
      const blocksFromEmailContainer = this.parseBlocksFromEmailContainer(emailContainer);
      let currentEmailContainer = $(emailContainer);
      if (!this.isPlainTextOrHtml(blocksFromEmailContainer)) {
        const { renderedXssSafe: renderedFromEmailContainerXssSafe } = this.messageRenderer.renderMsg({ blocks: blocksFromEmailContainer }, false); // xss-safe-value
        currentEmailContainer = GmailLoaderContext.updateMsgBodyEl_DANGEROUSLY(emailContainer, 'set', renderedFromEmailContainerXssSafe); // xss-safe-factory: replace_blocks is XSS safe
      }

      let blocks: MsgBlock[] = [];
      let messageInfo: MessageInfo | undefined;
      try {
        let body: MessageBody | undefined;
        let attachments: Attachment[] = [];

        ({ body, blocks, attachments, messageInfo } = await this.messageRenderer.msgGetProcessed(msgId));

        if (Mime.isBodyEmpty(body) && !this.currentlyReplacingAttachments) {
          // check if message body was converted to attachment by Gmail
          // happens for pgp/mime messages with attachments
          // https://github.com/FlowCrypt/flowcrypt-browser/issues/5458
          const encryptedMsgAttachment = attachments.find(a => !a.name && a.treatAs(attachments) === 'encryptedMsg');
          if (encryptedMsgAttachment) {
            const msgEl = this.getMsgBodyEl(msgId);
            const loaderContext = new GmailLoaderContext(this.factory, msgEl);
            await this.messageRenderer.processAttachment(encryptedMsgAttachment, body, attachments, loaderContext, undefined, msgId, messageInfo);
            $(this.sel.translatePrompt).hide();
          }
        }
      } catch (e) {
        this.handleException(e);
        // fill with fallback values from the element
        blocks = blocksFromEmailContainer;
        // todo: print info for offline?
      }

      if (this.isPlainTextOrHtml(blocks) && this.isPlainTextOrHtml(blocksFromEmailContainer)) {
        continue;
      }
      const setMessageInfo = messageInfo ?? {
        isPwdMsgBasedOnMsgSnippet: MessageRenderer.isPwdMsg(emailContainer.innerText),
        plainSubject: undefined, // todo: take from this.sel.subject?
      };
      if (!setMessageInfo.from) {
        setMessageInfo.from = this.getFrom(this.getMsgBodyEl(msgId));
      }
      const { renderedXssSafe, blocksInFrames } = this.messageRenderer.renderMsg({ blocks, senderEmail: setMessageInfo.from?.email }, false); // xss-safe-value
      if (!renderedXssSafe) continue;
      $(this.sel.translatePrompt).hide();

      if (this.debug) {
        console.debug('replaceArmoredBlocks() for of emailsContainingPgpBlock -> emailContainer replacing');
      }
      GmailLoaderContext.updateMsgBodyEl_DANGEROUSLY(currentEmailContainer, 'set', renderedXssSafe); // xss-safe-factory: replace_blocks is XSS safe
      if (this.debug) {
        console.debug('replaceArmoredBlocks() for of emailsContainingPgpBlock -> emailContainer replaced');
      }
      this.messageRenderer.startProcessingInlineBlocks(this.relayManager, this.factory, setMessageInfo, blocksInFrames);
    }
  };

  private isPlainTextOrHtml = (blocks: MsgBlock[]) => {
    return blocks.find(b => !['plainText', 'plainHtml'].includes(b.type)) === undefined;
  };

  private parseBlocksFromEmailContainer = (emailContainer: HTMLElement) => {
    const parseTextBlocks = (text: string) => Mime.processBody({ text });

    const el = document.createElement('div');
    el.appendChild(emailContainer.cloneNode(true));

    // add ">" character to the beginning of each line inside
    // gmail_quote elements for correct parsing of text blocks
    // https://github.com/FlowCrypt/flowcrypt-browser/issues/5574
    const gmailQuoteElements = el.querySelectorAll<HTMLElement>('.gmail_quote');
    for (const gmailQuoteElement of gmailQuoteElements) {
      let lines = gmailQuoteElement.innerText.split('\n');
      lines = lines.map(line => '> ' + line);
      gmailQuoteElement.innerText = lines.join('\n');
    }

    const text = el.innerText;
    const blocksFromEmailContainer = parseTextBlocks(text);

    if (!this.isPlainTextOrHtml(blocksFromEmailContainer) || !emailContainer.textContent) {
      return blocksFromEmailContainer;
    }

    const armorHeader = PgpArmor.ARMOR_HEADER_DICT.null;
    if (text.includes(armorHeader.begin) && !text.includes(armorHeader.end as string)) {
      // handles case when part of message is clipped and "END PGP MESSAGE" line isn't visible
      // .textContent property returns content of not visible nodes too
      return parseTextBlocks(emailContainer.textContent);
    }

    return blocksFromEmailContainer;
  };

  private addFcConvoIcon = (containerSel: JQuery, iconHtml: string, iconSel: string, onClick: () => void) => {
    if ($(containerSel).find(iconSel).length) {
      return;
    }
    containerSel.addClass('appended').children('.use_secure_reply, .show_original_conversation').remove(); // remove previous FlowCrypt buttons, if any
    Xss.sanitizePrepend(containerSel, iconHtml)
      .children(iconSel)
      .off()
      .on('click', Ui.event.prevent('double', Catch.try(onClick)));
  };

  private isEncrypted = (): boolean => {
    return !!$('iframe.pgp_block').filter(':visible').length;
  };

  private addMenuButton = (replyOption: ReplyOption, gmailContextMenuBtn: string) => {
    if ($(gmailContextMenuBtn).is(':visible')) {
      const button = $(this.factory.btnSecureMenuBtn(replyOption)).insertAfter(gmailContextMenuBtn); // xss-safe-factory
      button.on(
        'click',
        Ui.event.handle((el, ev: JQuery.Event) => this.actionActivateSecureReplyHandler(el, ev))
      );
    }
  };

  private replaceConvoBtns = (force = false) => {
    const convoUpperIconsContainer = $('div.hj:visible');
    const convoUpperIcons = $('span.pYTkkf-JX-ank-Rtc0Jf');
    const useEncryptionInThisConvo = this.isEncrypted() || force;
    // reply buttons
    const visibleReplyBtns = $('td.acX:visible');
    if (visibleReplyBtns.not('.replaced, .inserted').length) {
      // last reply button in convo gets replaced
      if (this.isEncrypted()) {
        $(this.sel.autoReplies).remove(); // make smart replies available for non-encrypted conversations
      }
      const convoReplyBtnsToReplace = visibleReplyBtns.not('.replaced, .inserted');
      const convoReplyBtnsArr = convoReplyBtnsToReplace.get();
      // only replace the last one FlowCrypt reply button if does not have any buttons replaced yet, and only replace the last one
      for (const elem of convoReplyBtnsArr) {
        $(elem).addClass('inserted');
        const gmailReplyBtn = $(elem).find('.aaq.L3');
        const secureReplyBtn = $(this.factory.btnSecureReply()).insertAfter(gmailReplyBtn); // xss-safe-factory
        secureReplyBtn.addClass(gmailReplyBtn.attr('class') || '');
        secureReplyBtn.off();
        secureReplyBtn.on(
          'focusin',
          Ui.event.handle(target => {
            $(target).addClass('T-I-JO');
          })
        );
        secureReplyBtn.on(
          'focusout',
          Ui.event.handle(target => {
            $(target).removeClass('T-I-JO');
          })
        );
        secureReplyBtn.on(
          'mouseenter',
          Ui.event.handle(target => {
            $(target).addClass('T-I-JW');
          })
        );
        secureReplyBtn.on(
          'mouseleave',
          Ui.event.handle(target => {
            $(target).removeClass('T-I-JW');
          })
        );
        secureReplyBtn.on(
          'click',
          Ui.event.handle((el, ev: JQuery.Event) => this.actionActivateSecureReplyHandler(el, ev))
        );
        secureReplyBtn.on('keydown', event => {
          if (event.key === 'Enter') {
            event.stopImmediatePropagation();
            $(secureReplyBtn).trigger('click');
          }
        });
      }
    }
    // conversation top-right icon buttons
    if (convoUpperIconsContainer.length) {
      if (useEncryptionInThisConvo) {
        if (!convoUpperIconsContainer.is('.appended') || convoUpperIconsContainer.find(convoUpperIcons).length) {
          this.addFcConvoIcon(convoUpperIconsContainer, this.factory.btnWithoutFc(), '.show_original_conversation', () => {
            convoUpperIconsContainer.find(convoUpperIcons).last().trigger('click');
          });
        }
      }
    }
  };

  private actionActivateSecureReplyHandler = async (btn: HTMLElement, event: JQuery.Event) => {
    event.stopImmediatePropagation();
    const secureReplyInvokedFromMenu = btn.className.includes('action_menu_message_button');
    let replyOption: ReplyOption;
    if (btn.className.includes('reply-all')) {
      replyOption = 'a_reply_all';
    } else if (btn.className.includes('forward')) {
      replyOption = 'a_forward';
    } else {
      replyOption = 'a_reply';
    }
    if ($('#switch_to_encrypted_reply').length) {
      $('#switch_to_encrypted_reply').trigger('click');
      return;
    }
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    const messageContainer = secureReplyInvokedFromMenu ? $('.T-I-JO.T-I-Kq').closest('.h7') : $(btn.closest('.h7')!);
    if (messageContainer.is(':last-child')) {
      if (this.isEncrypted()) {
        await this.setReplyBoxEditable(replyOption);
      } else {
        await this.replaceStandardReplyBox(undefined, true);
      }
    } else {
      this.insertEncryptedReplyBox(messageContainer, replyOption);
    }
    if (secureReplyInvokedFromMenu) {
      $(this.sel.msgActionsBtn).removeClass('T-I-JO T-I-Kq');
      $(this.sel.msgActionsMenu).hide();
    }
  };

  private replaceComposeDraftLinks = () => {
    const allContenteditableEls = $("div[contenteditable='true']").not('.evaluated').addClass('evaluated');
    for (const contenteditableEl of allContenteditableEls) {
      const contenteditable = $(contenteditableEl);
      let draftId = '';
      const legacyDraftLinkMatch = /\[flowcrypt:link:draft_compose:([0-9a-fr\-]+)]/.exec(contenteditable.html().substring(0, 1000));
      if (legacyDraftLinkMatch) {
        const [, legacyDraftId] = legacyDraftLinkMatch;
        draftId = legacyDraftId;
      }
      const draftHtml = contenteditable.html();
      // Used some hacky way to check if draft is compose draft or draft from thread reply
      // Reply `table` element (class named aoP) has avatar image(class named ajn). Compose draft doesn't have it
      // For thread reply draft, we don't need to call openComposeWin
      // Reply draft window will be replaced by secure compose by replaceStandardReplyBox function
      const isComposeDraft = $(contenteditable).closest('table.aoP').find('img.ajn').length < 1;
      if (PgpArmor.isEncryptedMsg(draftHtml) && isComposeDraft) {
        draftId = String($(contenteditable).closest('.I5').find('input[name="draft"]')?.val())?.split(':')[1] ?? '';
      }
      if (draftId) {
        // close original draft window
        const closeGmailComposeWindow = (target: JQuery) => {
          const mouseUpEvent = new MouseEvent('mouseup', {
            bubbles: true,
            cancelable: true,
          });
          target.closest('.nH.Hd').find('.Ha')[0].dispatchEvent(mouseUpEvent); // jquery's trigger('mouseup') doesn't work for some reason
        };
        if (this.injector.openComposeWin(draftId)) {
          closeGmailComposeWindow(contenteditable);
        }
      }
    }
  };

  /**
   * Related bugs (fixed):
   * https://github.com/FlowCrypt/flowcrypt-browser/issues/1870
   * https://github.com/FlowCrypt/flowcrypt-browser/issues/2309
   * https://github.com/FlowCrypt/flowcrypt-browser/issues/3180
   */
  private replaceAttachments = async () => {
    if (this.currentlyReplacingAttachments) {
      return;
    }
    try {
      this.currentlyReplacingAttachments = true;
      for (const attachmentsContainerEl of $(this.sel.attachmentsContainerInner).not('.evaluated')) {
        const attachmentsContainer = $(attachmentsContainerEl);
        if (this.debug) {
          console.debug('replaceAttachments() for of -> attachmentsContainer, setting evaluated', attachmentsContainer);
        }
        attachmentsContainer.addClass('evaluated');
        // In the exact moment we check, only some of the attachments of a message may be loaded into the DOM, while others won't
        // Because of that we need to listen to new attachments being inserted into the DOM
        const attachmentsContainerObserver = new MutationObserver(async mutationsList => {
          for (const mutation of mutationsList) {
            if (mutation.type === 'childList') {
              for (const addedNode of mutation.addedNodes) {
                if (this.debug) {
                  console.debug(
                    'replaceAttachments() for of -> attachmentsContainer MutationObserver -> processNewPgpAttachments(addedNode)',
                    $(addedNode as HTMLElement)
                  );
                }
                await this.processNewPgpAttachments($(addedNode as HTMLElement), attachmentsContainer);
              }
            }
          }
        });
        if (this.debug) {
          console.debug('replaceAttachments() for of -> attachmentsContainer enabling MutationObserver');
        }
        attachmentsContainerObserver.observe(attachmentsContainerEl, { subtree: true, childList: true });
        if (this.debug) {
          console.debug('replaceAttachments() for of -> processNewPgpAttachments(attachmentsContainerEl)');
        }
        await this.processNewPgpAttachments(attachmentsContainer.children().not('.evaluated'), attachmentsContainer);
      }
    } finally {
      this.currentlyReplacingAttachments = false;
    }
  };

  private processNewPgpAttachments = async (pgpAttachments: JQuery, attachmentsContainer: JQuery) => {
    if (this.debug) {
      console.debug('processNewPgpAttachments()');
    }
    const newPgpAttachments = this.filterAttachments(pgpAttachments, Attachment.webmailNamePattern);
    newPgpAttachments.addClass('evaluated');
    if (newPgpAttachments.length) {
      const msgId = this.determineMsgId(attachmentsContainer);
      if (msgId) {
        Xss.sanitizePrepend(newPgpAttachments, this.factory.embeddedAttachmentStatus('Getting file info..' + Ui.spinner('green')));
        try {
          if (this.debug) {
            console.debug('processNewPgpAttachments() -> msgGet may take some time');
          }
          const { attachments, messageInfo, body } = await this.messageRenderer.msgGetProcessed(msgId);
          if (this.debug) {
            console.debug('processNewPgpAttachments() -> msgGet done -> processAttachments', attachments);
          }
          await this.processAttachments(msgId, attachments, attachmentsContainer, messageInfo, body, false);
        } catch (e) {
          this.handleException(e, $(newPgpAttachments).find('.attachment_loader'));
        }
      } else {
        $(newPgpAttachments).prepend(this.factory.embeddedAttachmentStatus('Unknown message id')); // xss-safe-factory
      }
    }
  };

  private processAttachments = async (
    msgId: string,
    attachments: Attachment[],
    attachmentsContainerInner: JQuery,
    messageInfo: MessageInfo,
    body: MessageBody,
    skipGoogleDrive: boolean
  ) => {
    if (this.debug) {
      console.debug('processAttachments()', attachments);
    }
    const msgEl = this.getMsgBodyEl(msgId);
    if (!messageInfo.from?.email) {
      messageInfo.from = this.getFrom(msgEl);
    }
    const loaderContext = new GmailLoaderContext(this.factory, msgEl, attachmentsContainerInner);
    attachmentsContainerInner = $(attachmentsContainerInner);
    attachmentsContainerInner.parent().find(this.sel.numberOfAttachments).hide();
    let nRenderedAttachments = attachments.length;
    for (const a of attachments.reverse()) {
      const attachmentSel = this.filterAttachments(
        attachmentsContainerInner.children().not('.attachment_processed'),
        new RegExp(`^${Str.regexEscape(a.name || 'noname')}$`)
      ).first();
      const renderStatus = await this.messageRenderer.processAttachment(
        a,
        body,
        attachments,
        loaderContext,
        attachmentSel,
        msgId,
        messageInfo,
        skipGoogleDrive
      );
      if (renderStatus === 'hidden' || a.shouldBeHidden()) {
        nRenderedAttachments--;
      }
    }
    if (nRenderedAttachments !== attachments.length) {
      // according to #4200, no point in showing "download all" button if at least one attachment is encrypted etc.
      $(this.sel.attachmentsButtons).hide();
    }
    if (nRenderedAttachments === 0) {
      attachmentsContainerInner.parents(this.sel.attachmentsContainerOuter).first().hide();
      $(this.sel.attachmentsContainerOuter).children('.hp').hide();
      if ($('.pgp_block').length === 0) {
        attachmentsContainerInner.parents(this.sel.attachmentsContainerOuter).first().hide();
      }
    } else {
      const attachmentsLabel = nRenderedAttachments > 1 ? `${nRenderedAttachments} Attachments` : 'One Attachment';
      attachmentsContainerInner.parent().find(this.sel.numberOfAttachmentsLabel).text(attachmentsLabel);
      attachmentsContainerInner.parent().find(this.sel.numberOfAttachments).show();
    }
    if (!skipGoogleDrive) {
      await this.processGoogleDriveAttachments(msgId, loaderContext.msgEl, attachmentsContainerInner, messageInfo);
    }
  };

  private processGoogleDriveAttachments = async (msgId: string, msgEl: JQuery, attachmentsContainerInner: JQuery, messageInfo: MessageInfo) => {
    const notProcessedAttachmentsLoaders = attachmentsContainerInner.find('.attachment_loader');
    if (notProcessedAttachmentsLoaders.length && msgEl.find('.gmail_drive_chip, a[href^="https://drive.google.com/file"]').length) {
      // replace google drive attachments - they do not get returned by Gmail API thus did not get replaced above
      const googleDriveAttachments: Attachment[] = [];
      for (const attachmentLoaderEl of notProcessedAttachmentsLoaders) {
        const downloadUrl = $(attachmentLoaderEl).parent().attr('download_url');
        if (downloadUrl) {
          const meta = downloadUrl.split(':');
          googleDriveAttachments.push(
            new Attachment({
              msgId,
              name: meta[1],
              type: meta[0],
              url: `${meta[2]}:${meta[3]}`,
              treatAs: 'encryptedFile',
            })
          );
          // todo: start download
        } else {
          console.info('Missing Google Drive attachments download_url');
        }
      }
      await this.processAttachments(msgId, googleDriveAttachments, attachmentsContainerInner, messageInfo, {}, true);
    }
  };

  private filterAttachments = (potentialMatches: JQuery | HTMLElement, regExp: RegExp) => {
    return $(potentialMatches)
      .filter('span.aZo:visible, span.a5r:visible')
      .find('span.aV3')
      .filter(function () {
        // replace emoji images with text emojis
        const emojiRegex = /<img data-emoji="([^\"]+)"[^>]*>/g;
        const name = $(this)
          .html()
          .replace(emojiRegex, (_, emoji) => emoji as string);
        return regExp.test(name);
      })
      .closest('span.aZo, span.a5r');
  };

  private determineMsgId = (innerMsgEl: HTMLElement | JQuery) => {
    const parents = $(innerMsgEl).parents(this.sel.msgOuter);
    return parents.attr('data-legacy-message-id') || parents.attr('data-message-id') || '';
  };

  private getMsgBodyEl = (msgId: string) => {
    return $(this.sel.msgOuter).filter(`[data-legacy-message-id="${msgId}"]`).find(this.sel.msgInner);
  };

  private getFrom = (msgEl: HTMLElement | JQuery) => {
    const from = $(msgEl).closest('.gs').find('span.gD').attr('email')?.toLowerCase();
    return from ? Str.parseEmail(from) : undefined;
  };

  private getLastMsgReplyParams = (convoRootEl: JQuery, replyOption?: ReplyOption, replyBoxMessageId?: string | null): FactoryReplyParams => {
    return { replyMsgId: replyBoxMessageId ?? this.determineMsgId($(convoRootEl).find(this.sel.msgInner).last()), replyOption };
  };

  private getConvoRootEl = (anyInnerElement: HTMLElement) => {
    return $(anyInnerElement).closest('div.if, div.aHU, td.Bu').first();
  };

  private insertEncryptedReplyBox = (messageContainer: JQuery<Element>, replyOption: ReplyOption) => {
    const msgIdElement = messageContainer.find('[data-legacy-message-id], [data-message-id]');
    const msgId = msgIdElement.attr('data-legacy-message-id') || msgIdElement.attr('data-message-id');
    const replyParams: FactoryReplyParams = { replyMsgId: msgId, removeAfterClose: true, replyOption };
    const secureReplyBoxXssSafe = /* xss-safe-factory */ `<div class="remove_borders reply_message_iframe_container inserted">${this.factory.embeddedReply(
      replyParams,
      true,
      true
    )}</div>`;
    messageContainer.find('.adn.ads').parent().append(secureReplyBoxXssSafe); // xss-safe-factory
  };

  private replaceStandardReplyBox = async (msgId?: string, force = false) => {
    const legacyDraftReplyRegex = new RegExp(/\[(flowcrypt|cryptup):link:draft_reply:([0-9a-fr\-]+)]/);
    const newReplyBoxes = $('div.nr.tMHS5d, td.amr > div.nr, div.gA td.I5').not('.reply_message_evaluated').filter(':visible').get();
    if (newReplyBoxes.length) {
      // removing this line will cause unexpected draft creation bug reappear
      // https://github.com/FlowCrypt/flowcrypt-browser/issues/5616#issuecomment-1972897692
      this.replyOption = undefined;
      // Try to get message id from plain reply box
      // https://github.com/FlowCrypt/flowcrypt-browser/issues/5906
      const replyBoxMessageId = newReplyBoxes[0].closest('.gA.gt')?.previousElementSibling?.getAttribute('data-legacy-message-id');

      // cache for subseqent loop runs
      const convoRootEl = this.getConvoRootEl(newReplyBoxes[0]);
      const replyParams = this.getLastMsgReplyParams(convoRootEl, undefined, replyBoxMessageId);
      if (msgId) {
        replyParams.replyMsgId = msgId;
      }
      const hasDraft = newReplyBoxes.filter(replyBox => {
        const msgText = $(replyBox).find(this.sel.msgInnerText).text();
        return PgpArmor.isEncryptedMsg(msgText) || legacyDraftReplyRegex.exec(msgText.substring(0, 1000));
      }).length;
      const doReplace = Boolean(
        convoRootEl.find('iframe.pgp_block').filter(':visible').closest('.h7').is(':last-child') || (convoRootEl.is(':visible') && force) || hasDraft
      );
      let midConvoDraft = false;
      if (doReplace) {
        for (const replyBoxEl of newReplyBoxes.reverse()) {
          // looping in reverse
          const replyBox = $(replyBoxEl);
          const msgInnerText = replyBox.find(this.sel.msgInnerText);
          if (msgInnerText.length && !msgInnerText.find('[contenteditable]').length) {
            // div[contenteditable] is not loaded yet (e.g. when refreshing a thread), do nothing
            continue;
          }
          const replyBoxInnerText = msgInnerText.text().trim();
          const legacyDraftReplyLinkMatch = legacyDraftReplyRegex.exec(replyBoxInnerText.substring(0, 1000));
          if (legacyDraftReplyLinkMatch) {
            // legacy reply draft
            replyParams.draftId = legacyDraftReplyLinkMatch[2];
          } else if (PgpArmor.isEncryptedMsg(replyBoxInnerText)) {
            // reply draft
            replyParams.draftId = document.querySelector('[name=draft]')?.getAttribute('value')?.split(':')[1] ?? '';
          } else if (msgInnerText.length && !this.switchToEncryptedReply) {
            // plain reply
            this.showSwitchToEncryptedReplyWarningIfNeeded(replyBox);
            replyBox.addClass('reply_message_evaluated');
            continue;
          }
          if (this.removeNextReplyBoxBorders) {
            replyBox.addClass('remove_borders');
            this.removeNextReplyBoxBorders = false;
          }
          if (!midConvoDraft) {
            const replyOption = this.parseReplyOption(replyBox);
            if (replyOption) {
              this.replyOption = replyOption;
              this.lastReplyOption = replyOption;
            } else if (this.lastReplyOption) {
              this.replyOption = this.lastReplyOption;
              this.lastReplyOption = undefined;
            }
            replyParams.replyOption = this.replyOption;
            // either is a draft in the middle, or the convo already had (last) box replaced: should also be useless draft
            const isReplyButtonView = replyBoxEl.className.includes('nr');
            const replyBoxes = document.querySelectorAll('iframe.reply_message');
            const alreadyHasSecureReplyBox = replyBoxes.length > 0;
            const secureReplyBoxXssSafe = /* xss-safe-factory */ `
              <div class="remove_borders reply_message_iframe_container">
                ${this.factory.embeddedReply(replyParams, !isReplyButtonView || alreadyHasSecureReplyBox || this.lastSwitchToEncryptedReply)}
              </div>
            `;
            // Added `lastSwitchToEncryptedReply` logic to handle when a user switches from `plain reply` to `encrypted reply`
            // by clicking the `Switch to encrypted reply` button.
            // Initially, this action removes the `plain reply view` and replaces it with the `plain reply button view`,
            // which previously led to an incorrect status in `switchToEncryptedReply`.
            // https://github.com/FlowCrypt/flowcrypt-browser/pull/5778
            this.lastSwitchToEncryptedReply = false;
            if (hasDraft || alreadyHasSecureReplyBox) {
              replyBox.addClass('reply_message_evaluated remove_borders').parent().append(secureReplyBoxXssSafe); // xss-safe-factory
              replyBox.hide();
              this.lastReplyOption = undefined;
            } else if (isReplyButtonView) {
              replyBox.replaceWith(secureReplyBoxXssSafe); // xss-safe-factory
              this.lastReplyOption = undefined;
              this.replyOption = undefined;
            } else {
              const deleteReplyEl = document.querySelector('.oh.J-Z-I.J-J5-Ji.T-I-ax7');
              this.lastSwitchToEncryptedReply = this.switchToEncryptedReply;
              if (deleteReplyEl) {
                // Remove standard reply by clicking `delete` button
                (deleteReplyEl as HTMLElement).click();
              }
            }
            midConvoDraft = true; // last box was processed first (looping in reverse), and all the rest must be drafts
          }
        }
        this.switchToEncryptedReply = false;
      }
    }
  };

  // loaderEl is a loader reference in case we're processing an attachment
  // todo: we could also re-use a common method like this in Inbox
  private handleException = (e: unknown, loaderEl?: JQuery) => {
    if (ApiErr.isAuthErr(e)) {
      this.notifications.showAuthPopupNeeded(this.acctEmail);
      loaderEl?.text('Auth needed');
    } else if (ApiErr.isNetErr(e)) {
      loaderEl?.text('Network error');
      // todo:    } else if (ApiErr.isInPrivateMode(e)) {
      //      this.notifications.show(`FlowCrypt does not work in a Firefox Private Window (or when Firefox Containers are used). Please try in a standard window.`);
    } else {
      if (!ApiErr.isServerErr(e) && !ApiErr.isMailOrAcctDisabledOrPolicy(e) && !ApiErr.isNotFound(e)) {
        Catch.reportErr(e);
      }
      loaderEl?.text('Failed to load');
      // todo: show somenotification if this error happened when replacing armored blocks?
    }
  };

  private showSwitchToEncryptedReplyWarningIfNeeded = (replyBox: JQuery) => {
    const showSwitchToEncryptedReplyWarning = replyBox.closest('div.h7').find(this.sel.msgOuter).find('iframe.pgp_block').hasClass('encryptedMsg');

    if (showSwitchToEncryptedReplyWarning) {
      const isForward = this.parseReplyOption(replyBox) === 'a_forward';
      const notification = $(
        `<div class="error_notification">The last message was encrypted, but you are composing a ${isForward ? 'message' : 'reply'} without encryption. </div>`
      );
      const switchToEncryptedReply = $(`<a href id="switch_to_encrypted_reply">Switch to encrypted ${isForward ? 'compose' : 'reply'}</a>`);
      switchToEncryptedReply.on(
        'click',
        Ui.event.handle((el, ev: JQuery.Event) => {
          ev.preventDefault();
          $(el).closest('.reply_message_evaluated').removeClass('reply_message_evaluated');
          this.removeNextReplyBoxBorders = true;
          this.switchToEncryptedReply = true;
          notification.remove();
        })
      );
      notification.append(switchToEncryptedReply); // xss-direct
      replyBox.prepend(notification); // xss-direct
    }
  };

  private parseReplyOption = (replyBox: JQuery) => {
    const replyBoxTypeImgClass = replyBox.find(this.sel.replyOptionImg).find('img').attr('class');
    if (replyBoxTypeImgClass?.includes('mK')) {
      return 'a_reply_all';
    } else if (replyBoxTypeImgClass?.includes('mI')) {
      return 'a_forward';
    } else if (replyBoxTypeImgClass?.includes('mL')) {
      return 'a_reply';
    }

    return undefined;
  };

  private evaluateStandardComposeRecipients = async () => {
    if (!this.currentlyEvaluatingStandardComposeBoxRecipients) {
      this.currentlyEvaluatingStandardComposeBoxRecipients = true;
      for (const standardComposeWinEl of $(this.sel.standardComposeWin)) {
        const standardComposeWin = $(standardComposeWinEl);
        const recipients = standardComposeWin
          .find(this.sel.standardComposeRecipient)
          .get()
          .map(e => $(e).attr('email'))
          .filter(e => !!e);
        if (!recipients.length || $(this.sel.standardComposeWin).find('.close_gmail_compose_window').length === 1) {
          // draft, but not the secure one
          standardComposeWin.find('.recipients_use_encryption').remove();
        } else {
          let everyoneUsesEncryption = true;
          for (const email of recipients) {
            if (email) {
              const cache = this.recipientHasPgpCache[email];
              if (!Str.isEmailValid(email)) {
                everyoneUsesEncryption = false;
                break;
              }
              if (typeof cache === 'undefined') {
                try {
                  const contactWithPubKeys = await ContactStore.getOneWithAllPubkeys(undefined, email);
                  if (contactWithPubKeys?.sortedPubkeys && contactWithPubKeys.sortedPubkeys.length > 0) {
                    this.recipientHasPgpCache[email] = true;
                  } else if ((await this.pubLookup.lookupEmail(email)).pubkeys.length) {
                    this.recipientHasPgpCache[email] = true;
                  } else {
                    this.recipientHasPgpCache[email] = false;
                  }
                  if (!this.recipientHasPgpCache[email]) {
                    everyoneUsesEncryption = false;
                    break;
                  }
                } catch (e) {
                  ApiErr.reportIfSignificant(e);
                  // this is a low-importance request, so evaluate hasPgp as false on errors
                  // this way faulty requests wouldn't unnecessarily repeat and overwhelm Attester
                  this.recipientHasPgpCache[email] = false;
                  everyoneUsesEncryption = false;
                  break;
                }
              } else if (!cache) {
                everyoneUsesEncryption = false;
                break;
              }
            } else {
              everyoneUsesEncryption = false;
              break;
            }
          }
          if (everyoneUsesEncryption) {
            if (!standardComposeWin.find('.recipients_use_encryption').length) {
              const prependable = standardComposeWin.find('div.az9 span[email]').first().parents('form').first();
              prependable.prepend(this.factory.btnRecipientsUseEncryption('gmail')); // xss-safe-factory
              prependable.find('a').on(
                'click',
                Ui.event.handle(() => {
                  this.injector.openComposeWin();
                })
              );
            }
          } else {
            standardComposeWin.find('.recipients_use_encryption').remove();
          }
        }
      }
      this.currentlyEvaluatingStandardComposeBoxRecipients = false;
    }
  };

  private addSettingsBtn = () => {
    if (window.location.hash.startsWith('#settings')) {
      const settingsBtnContainer = $(this.sel.settingsBtnContainer);
      if (settingsBtnContainer.length && !settingsBtnContainer.find('#fc_settings_btn').length) {
        settingsBtnContainer.children().last().before(this.factory.btnSettings('gmail')); // xss-safe-factory
        settingsBtnContainer.find('#fc_settings_btn').on(
          'click',
          Ui.event.handle(() => BrowserMsg.send.bg.settings({ acctEmail: this.acctEmail }))
        );
      }
    }
  };

  private renderLocalDrafts = async () => {
    if (window.location.hash === '#drafts') {
      const storage = await GlobalStore.get(['local_drafts']);
      if (!storage.local_drafts) {
        return;
      }
      const offlineComposeDrafts: Dict<LocalDraft> = {};
      for (const draftId in storage.local_drafts) {
        if (draftId.startsWith('local-draft-compose-') && storage.local_drafts[draftId].acctEmail === this.acctEmail) {
          offlineComposeDrafts[draftId] = storage.local_drafts[draftId];
        }
      }
      let offlineDraftsContainer = $(this.sel.draftsList).find('#fc_offline_drafts');
      if (Object.keys(offlineComposeDrafts).length) {
        const offlineComposeDraftIds = Object.keys(offlineComposeDrafts);
        const draftIdsSortedByTimestamp = offlineComposeDraftIds.sort((a, b) => {
          return offlineComposeDrafts[b].timestamp - offlineComposeDrafts[a].timestamp;
        });
        if (offlineDraftsContainer.data('rendered-drafts') === draftIdsSortedByTimestamp.join(',')) {
          // already rendered
          return;
        }
        offlineDraftsContainer = $('<div id="fc_offline_drafts"><h4>FlowCrypt offline drafts:</h4></div>'); // xss-safe-value
        offlineDraftsContainer.data('rendered-drafts', draftIdsSortedByTimestamp.join(','));
        $(this.sel.draftsList).find('#fc_offline_drafts').remove();
        $(this.sel.draftsList).append(offlineDraftsContainer); // xss-safe-factory
        for (const draftId of draftIdsSortedByTimestamp) {
          const draft = offlineComposeDrafts[draftId];
          const draftLink = $(`<a href>${new Date(draft.timestamp).toLocaleString()}</a>`);
          draftLink.on('click', event => {
            event.preventDefault();
            this.injector.openComposeWin(draftId);
          });
          offlineDraftsContainer.append(draftLink); // xss-safe-value
        }
      } else {
        offlineDraftsContainer.remove();
      }
    }
  };

  private addSecureActionsToMessageMenu = () => {
    if ($('.action_menu_message_button').length) {
      return;
    }
    this.addMenuButton('a_reply', '#r');
    this.addMenuButton('a_reply_all', '#r2');
    this.addMenuButton('a_forward', '#r3');
  };
}
