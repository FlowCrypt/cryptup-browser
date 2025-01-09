/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { NewMsgData, ValidRecipientElement } from './compose-types.js';
import Squire from 'squire-rte';

import { Catch } from '../../../js/common/platform/catch.js';
import { ParsedRecipients } from '../../../js/common/api/email-provider/email-provider-api.js';
import { Str } from '../../../js/common/core/common.js';
import { Xss } from '../../../js/common/platform/xss.js';
import { ViewModule } from '../../../js/common/view-module.js';
import { Ui } from '../../../js/common/browser/ui.js';
import { ComposeView } from '../compose.js';
import { Lang } from '../../../js/common/lang.js';

declare global {
  interface Window {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    Squire: typeof Squire;
  }
}

interface SquireWillPasteEvent extends Event {
  detail: {
    fragment: DocumentFragment;
  };
}

export class ComposeInputModule extends ViewModule<ComposeView> {
  public squire!: Squire;

  public constructor(view: ComposeView) {
    super(view);
    this.initSquire(false);
  }

  public setHandlers = () => {
    this.configureRichTextFormatting();
    this.view.S.cached('add_intro').on(
      'click',
      this.view.setHandler(el => this.actionAddIntroHandler(el), this.view.errModule.handle(`add intro`))
    );
    // Set lastDraftBody to current empty squire content ex: <div><br></div>)
    // https://github.com/FlowCrypt/flowcrypt-browser/issues/5184
    this.view.draftModule.setLastDraftBody(this.squire.getHTML());
    if (this.view.debug) {
      this.insertDebugElements();
    }
  };

  public addRichTextFormatting = () => {
    this.initSquire(true);
  };

  public removeRichTextFormatting = () => {
    if (this.isRichText()) {
      this.initSquire(false, true);
    }
  };

  public inputTextHtmlSetSafely = (html: string) => {
    this.squire.setHTML(Xss.htmlSanitize(Xss.htmlSanitizeKeepBasicTags(html, 'IMG-KEEP')));
    this.view.draftModule.setLastDraftBody(this.squire.getHTML());
  };

  public extract = (type: 'text' | 'html', elSel: 'input_text' | 'input_intro', flag?: 'SKIP-ADDONS') => {
    let html = this.view.S.cached(elSel)[0].innerHTML;
    if (elSel === 'input_text' && flag !== 'SKIP-ADDONS') {
      html += this.view.quoteModule.getTripleDotSanitizedFormattedHtmlContent();
    }
    if (type === 'html') {
      return Xss.htmlSanitizeKeepBasicTags(html, 'IMG-KEEP');
    }
    return Xss.htmlUnescape(Xss.htmlSanitizeAndStripAllTags(html, '\n', false));
  };

  public extractAttachments = () => {
    return this.view.S.cached('fineuploader')
      .find('.qq-upload-file')
      .toArray()
      .map(el => $(el).text().trim());
  };

  public extractAll = async (): Promise<NewMsgData> => {
    const recipients = this.mapRecipients(this.view.recipientsModule.getValidRecipients());
    const subject = this.view.isReplyBox && this.view.replyParams ? this.view.replyParams.subject : String($('#input_subject').val() || '');
    const plaintext = this.extract('text', 'input_text');
    const plainhtml = this.extract('html', 'input_text');
    const password = this.view.S.cached('input_password').val();
    const pwd = typeof password === 'string' && password ? password : undefined;
    const from = await this.view.storageModule.getEmailWithOptionalName(this.view.senderModule.getSender());
    return { recipients, subject, plaintext, plainhtml, pwd, from };
  };

  public isRichText = () => {
    return this.view.sendBtnModule.popover.choices.richtext;
  };

  public willInputLimitBeExceeded = (textToPaste: string, targetInputField: HTMLElement, selectionLengthGetter: () => number | undefined) => {
    const limit = 50000;
    const toBeRemoved = selectionLengthGetter() || 0;
    const currentLength = targetInputField.innerText.trim().length;
    const isInputLimitExceeded = currentLength - toBeRemoved + textToPaste.length > limit;
    return isInputLimitExceeded;
  };

  private configureRichTextFormatting = () => {
    if (this.isRichText()) {
      this.addRichTextFormatting();
    } else {
      this.removeRichTextFormatting();
    }
  };

  private initSquire = (addLinks: boolean, removeExistingLinks = false) => {
    const squireHtml = this.squire?.getHTML();
    const el = this.view.S.cached('input_text').get(0);
    if (!el) {
      throw new Error('Input element not found');
    }
    this.squire?.destroy();
    this.squire = new window.Squire(el, { addLinks });
    this.initShortcuts();
    this.handlePaste();
    this.handleDragImages();
    this.handlePasteImages();
    this.resizeReplyBox();
    this.scrollIntoView();
    this.handleRTL();
    if (squireHtml) {
      const processedHtml = removeExistingLinks ? Xss.htmlSanitizeAndStripAllTags(squireHtml, '<br>', false) : squireHtml;
      this.squire.setHTML(processedHtml);
    }
  };

  private handlePaste = () => {
    this.squire.addEventListener('willPaste', async (e: SquireWillPasteEvent) => {
      const div = document.createElement('div');
      div.appendChild(e.detail.fragment);
      const html = div.innerHTML;
      const sanitized = this.isRichText() ? Xss.htmlSanitizeKeepBasicTags(html, 'IMG-KEEP') : Xss.htmlSanitizeAndStripAllTags(html, '<br>', false);
      if (this.willInputLimitBeExceeded(sanitized, this.squire.getRoot(), () => this.squire.getSelectedText().length)) {
        e.preventDefault();
        await Ui.modal.warning(Lang.compose.inputLimitExceededOnPaste);
        return;
      }
      Xss.setElementContentDANGEROUSLY(div, sanitized); // xss-sanitized
      e.detail.fragment.appendChild(div);
    });
  };

  private loadImageFromFile = (file: File, callback: (result: string) => void) => {
    const reader = new FileReader();
    reader.onload = () => callback(reader.result as string);
    reader.readAsDataURL(file);
  };

  private insertImageIntoSquire = (imageData: string, name: string) => {
    try {
      this.squire.insertImage(imageData, { name, title: name });
      this.view.draftModule.draftSave().catch(Catch.reportErr);
    } catch (e) {
      Catch.reportErr(e);
    }
  };

  private handleDragImages = () => {
    this.squire.addEventListener('drop', (ev: DragEvent) => {
      if (!this.isRichText() || !ev.dataTransfer?.files.length) {
        return;
      }
      const file = ev.dataTransfer.files[0];
      this.loadImageFromFile(file, imageData => {
        this.insertImageIntoSquire(imageData, file.name);
      });
    });
    this.squire.addEventListener('dragover', (e: DragEvent) => {
      e.preventDefault(); // this is needed for 'drop' event to fire
    });
  };

  private handlePasteImages = () => {
    this.squire.addEventListener('pasteImage', (ev: Event & { detail: { clipboardData: DataTransfer } }) => {
      if (!this.isRichText()) return;
      const items = Array.from(ev.detail.clipboardData?.items ?? []);
      const imageItem = items.find(item => item.type.includes('image'));

      const imageFile = imageItem?.getAsFile();
      if (imageItem && imageFile) {
        this.loadImageFromFile(imageFile, imageData => {
          this.insertImageIntoSquire(imageData, 'Pasted Image');
        });
      }
    });
  };

  private handleRTL = () => {
    const checkRTL = () => {
      let container = $(this.squire.getSelection().commonAncestorContainer);
      if (container.prop('tagName') !== 'DIV') {
        // commonAncestorContainer might be a text node
        container = container.closest('div');
      }
      const ltrCheck = new RegExp('^[' + Str.ltrChars + ']');
      const rtlCheck = new RegExp('^[' + Str.rtlChars + ']');
      if (ltrCheck.test(container.text()) && container.attr('dir') !== 'ltr') {
        // Switch to LTR
        container.attr('dir', 'ltr');
      } else if (rtlCheck.test(container.text()) && container.attr('dir') !== 'rtl') {
        // Switch to RTL
        container.attr('dir', 'rtl');
      } else {
        // keep the previous direction for digits, punctuation marks, and other characters
      }
    };
    this.squire.addEventListener('input', checkRTL);
  };

  private initShortcuts = () => {
    try {
      const isMac = navigator.userAgent.includes('Mac OS X');
      const ctrlKey = isMac ? 'Meta-' : 'Ctrl-';
      const mapKeyToFormat = (tag: string) => {
        return (self: Squire, event: Event) => {
          try {
            event.preventDefault();
            if (!this.isRichText()) {
              return;
            }
            const range = self.getSelection();
            if (self.hasFormat(tag)) {
              self.changeFormat(null, { tag }, range); // eslint-disable-line no-null/no-null
            } else {
              self.changeFormat({ tag }, null, range); // eslint-disable-line no-null/no-null
            }
          } catch (e) {
            Catch.reportErr(e);
          }
        };
      };
      const noop = (_self: Squire, event: Event) => {
        event.preventDefault();
      };
      const removeFormatting = (self: Squire) => {
        self.removeAllFormatting();
      };
      this.squire.setKeyHandler(ctrlKey + 'b', mapKeyToFormat('B'));
      this.squire.setKeyHandler(ctrlKey + 'u', mapKeyToFormat('U'));
      this.squire.setKeyHandler(ctrlKey + 'i', mapKeyToFormat('I'));
      this.squire.setKeyHandler(ctrlKey + '\\', removeFormatting);
      this.squire.setKeyHandler(ctrlKey + 'shift-7', noop); // default is 'S'
      this.squire.setKeyHandler(ctrlKey + 'shift-5', noop); // default is 'SUB', { tag: 'SUP' }
      this.squire.setKeyHandler(ctrlKey + 'shift-6', noop); // default is 'SUP', { tag: 'SUB' }
      this.squire.setKeyHandler(ctrlKey + 'shift-8', noop); // default is 'makeUnorderedList'
      this.squire.setKeyHandler(ctrlKey + 'shift-9', noop); // default is 'makeOrderedList'
      this.squire.setKeyHandler(ctrlKey + '[', noop); // default is 'decreaseQuoteLevel'
      this.squire.setKeyHandler(ctrlKey + ']', noop); // default is 'increaseQuot
    } catch (e) {
      Catch.reportErr(e);
    }
  };

  private resizeReplyBox = () => {
    this.squire.addEventListener('cursor', (e: Event & { detail: { range: Range } }) => {
      if (this.view.isReplyBox) {
        const cursorContainer = e.detail.range.commonAncestorContainer as HTMLElement;
        this.view.sizeModule.resizeComposeBox(0, cursorContainer?.offsetTop);
      }
    });
  };

  // https://github.com/FlowCrypt/flowcrypt-browser/issues/2400
  private scrollIntoView = () => {
    this.squire.addEventListener('cursor', () => {
      try {
        const inputText = this.view.S.cached('input_text').get(0);
        if (!inputText) {
          return;
        }
        const offsetBottom = this.squire.getCursorPosition().bottom - inputText.getBoundingClientRect().top;
        const editorRootHeight = this.view.S.cached('input_text').height() || 0;
        if (offsetBottom > editorRootHeight) {
          const scrollBy = offsetBottom - editorRootHeight;
          inputText.scrollBy(0, Math.round(scrollBy));
        }
      } catch (e) {
        Catch.reportErr(e);
      }
    });
  };

  private actionAddIntroHandler = (addIntroBtn: HTMLElement) => {
    $(addIntroBtn).css('display', 'none');
    this.view.S.cached('intro_container').css('display', 'table-row');
    this.view.S.cached('input_intro').trigger('focus');
    this.view.sizeModule.setInputTextHeightManuallyIfNeeded();
  };

  private mapRecipients = (recipients: ValidRecipientElement[]): ParsedRecipients => {
    const result: ParsedRecipients = { to: [], cc: [], bcc: [] };
    for (const recipient of recipients) {
      /* eslint-disable @typescript-eslint/no-non-null-assertion */
      // Setting recipient name to empty string as a hotfix - https://github.com/FlowCrypt/enterprise-server/issues/6264
      const defaultName = '';
      switch (recipient.sendingType) {
        case 'to':
          result.to!.push({ email: recipient.email, name: defaultName });
          break;
        case 'cc':
          result.cc!.push({ email: recipient.email, name: defaultName });
          break;
        case 'bcc':
          result.bcc!.push({ email: recipient.email, name: defaultName });
          break;
      }
      /* eslint-enable @typescript-eslint/no-non-null-assertion */
    }
    return result;
  };

  // We need this method to test images in drafts because we can't paste them dirctly in tests.
  private insertDebugElements = () => {
    this.view.S.cached('body').append('<input type="hidden" id="test_insertImage" data-test="action-insert-image" />'); // xss-direct
    $('#test_insertImage').on(
      'click',
      this.view.setHandler(async input => {
        this.squire.insertImage(String($(input).val()), {});
        await this.view.draftModule.draftSave();
      })
    );
  };
}
