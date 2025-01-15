/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { BrowserMsg } from '../../../common/browser/browser-msg.js';
import { Attachment, ThunderbirdAttachment } from '../../../common/core/attachment.js';
import { Buf } from '../../../common/core/buf.js';
import { KeyUtil } from '../../../common/core/crypto/key.js';
import { DecryptError, DecryptErrTypes, MsgUtil, VerifyRes } from '../../../common/core/crypto/pgp/msg-util.js';
import { OpenPGPKey } from '../../../common/core/crypto/pgp/openpgp-key.js';
import { PgpArmor } from '../../../common/core/crypto/pgp/pgp-armor';
import { ContactStore } from '../../../common/platform/store/contact-store.js';
import { KeyStore } from '../../../common/platform/store/key-store.js';
import { Xss } from '../../../common/platform/xss.js';
import { IntervalFunction, WebmailElementReplacer } from '../generic/webmail-element-replacer.js';
import * as openpgp from 'openpgp';

export class ThunderbirdElementReplacer extends WebmailElementReplacer {
  public setReplyBoxEditable: () => Promise<void>;
  public reinsertReplyBox: (replyMsgId: string) => void;
  public scrollToReplyBox: (replyMsgId: string) => void;
  public scrollToCursorInReplyBox: (replyMsgId: string, cursorOffsetTop: number) => void;
  private acctEmail: string;
  private emailBodyFromThunderbirdMail: string;

  public getIntervalFunctions = (): IntervalFunction[] => {
    return [{ interval: 2000, handler: () => this.handleThunderbirdMessageParsing() }];
  };

  public handleThunderbirdMessageParsing = async () => {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    this.acctEmail = (await BrowserMsg.send.bg.await.thunderbirdGetCurrentUser())!;
    const emailBodyToParse = $('div.moz-text-plain').text().trim() || $('div.moz-text-html').text().trim() || $('div.moz-text-flowed').text().trim();
    const { processableAttachments: fcAttachments, from: signerEmail } = await BrowserMsg.send.bg.await.thunderbirdGetDownloadableAttachment();
    const parsedPubs = (await ContactStore.getOneWithAllPubkeys(undefined, signerEmail))?.sortedPubkeys ?? [];
    const verificationPubs = parsedPubs.map(key => KeyUtil.armor(key.pubkey));
    if (this.resemblesAsciiArmoredMsg(emailBodyToParse)) {
      await this.messageDecrypt(verificationPubs, this.emailBodyFromThunderbirdMail);
    } else if (this.resemblesSignedMsg(emailBodyToParse)) {
      await this.messageVerify(verificationPubs);
    }
    if (fcAttachments.length) {
      for (const fcAttachment of fcAttachments) {
        await this.attachmentUiRenderer(fcAttachment, verificationPubs, emailBodyToParse);
      }
    }
    $('body').show();
  };

  private messageDecrypt = async (verificationPubs: string[], encryptedData: string | Buf) => {
    $('body').hide();
    const result = await MsgUtil.decryptMessage({
      kisWithPp: await KeyStore.getAllWithOptionalPassPhrase(this.acctEmail),
      encryptedData,
      verificationPubs,
    });
    if (result.success && result.content) {
      const pgpBlockContent = result.content.toUtfStr();
      const encryptionStatus = result.isEncrypted ? 'encrypted' : 'not encrypted';
      let verificationStatus = '';
      if (result?.signature) {
        if (result.signature.match) {
          verificationStatus = 'signed';
        } else if (result.signature.error) {
          verificationStatus = `could not verify signature: ${result.signature.error}`;
        } else {
          verificationStatus = 'not signed';
        }
      }
      const pgpBlock = this.generatePgpBlockTemplate(encryptionStatus, verificationStatus, pgpBlockContent);
      $('body').html(pgpBlock); // xss-sanitized
    } else {
      const decryptErr = result as DecryptError;
      let decryptionErrorMsg = '';
      if (decryptErr.error && decryptErr.error.type === DecryptErrTypes.needPassphrase) {
        const acctEmail = String(await BrowserMsg.send.bg.await.thunderbirdGetCurrentUser());
        const longids = decryptErr.longids.needPassphrase.join(',');
        decryptionErrorMsg = `decrypt error: private key needs to be unlocked by your passphrase.`;
        await BrowserMsg.send.bg.await.thunderbirdOpenPassphraseDiaglog({ acctEmail, longids });
      } else {
        decryptionErrorMsg = `decrypt error: ${(result as DecryptError).error.message}`;
      }
      const pgpBlock = this.generatePgpBlockTemplate(decryptionErrorMsg, 'not signed', this.emailBodyFromThunderbirdMail);
      $('body').html(pgpBlock); // xss-sanitized
    }
  };

  private messageVerify = async (verificationPubs: string[], detachedSignatureParams?: { plaintext: string; sigText: string }) => {
    $('body').hide();
    let result: VerifyRes;
    if (!detachedSignatureParams) {
      const message = await openpgp.readCleartextMessage({ cleartextMessage: this.emailBodyFromThunderbirdMail });
      result = await OpenPGPKey.verify(message, await ContactStore.getPubkeyInfos(undefined, verificationPubs));
    } else {
      result = await MsgUtil.verifyDetached({ plaintext: detachedSignatureParams.plaintext, sigText: detachedSignatureParams.sigText, verificationPubs });
    }
    let verificationStatus = '';
    let pgpBlockContent = '';
    if (result.content) {
      verificationStatus = result.match ? 'signed' : 'not signed';
      if (!result.signerLongids.length) {
        verificationStatus = `could not verify signature: missing pubkey ${result.signerLongids}`;
      }
      pgpBlockContent = result.content.toUtfStr();
    } else if (result.error) {
      verificationStatus = `could not verify signature: ${result.error}`;
      pgpBlockContent = detachedSignatureParams?.plaintext || this.emailBodyFromThunderbirdMail;
    }
    const pgpBlock = this.generatePgpBlockTemplate('not encrypted', verificationStatus, pgpBlockContent);
    $('body').html(pgpBlock); // xss-sanitized
  };

  private attachmentUiRenderer = async (fcAttachment: ThunderbirdAttachment, verificationPubs: string[], emailBodyToParse: string) => {
    if (fcAttachment.treatAs === 'encryptedFile' && emailBodyToParse) {
      const generatedPgpTemplate = this.generatePgpAttachmentTemplate(fcAttachment.name, fcAttachment.data);
      $('.pgp_attachments_block').append(generatedPgpTemplate); // xss-sanitized
    } else if (
      (fcAttachment.treatAs === 'encryptedMsg' || Attachment.encryptedMsgNames.some(a => fcAttachment.name.includes(a))) &&
      !this.emailBodyFromThunderbirdMail
    ) {
      await this.messageDecrypt(verificationPubs, fcAttachment.data);
      // detached signature verification
    } else if (fcAttachment.treatAs === 'signature') {
      const sigText = new TextDecoder('utf-8').decode(fcAttachment.data).trim();
      if (this.resemblesSignedMsg(sigText)) {
        await this.messageVerify(verificationPubs, { plaintext: emailBodyToParse, sigText: sigText.replace('\n=3D', '\n=') });
      }
    }
  };

  private generatePgpBlockTemplate = (encryptionStatus: string, verificationStatus: string, messageToRender: string): string => {
    return `
      <div ${encryptionStatus === 'encrypted' ? 'class="pgp_secure"' : 'class="pgp_neutral"'}>
        <div>
          <div id="pgp_encryption" class="pgp_badge short ${encryptionStatus === 'encrypted' ? 'green_label' : 'red_label'}">${encryptionStatus}</div>
          <div id="pgp_signature" class="pgp_badge short ${verificationStatus === 'signed' ? 'green_label' : 'red_label'}">${verificationStatus}</div>
        </div>
        <div class="pgp_block">
        <pre>${Xss.escape(messageToRender)}</pre>
        </div>
        <div class="pgp_attachments_block">
        </div>
      </div>`;
  };

  private generatePgpAttachmentTemplate = (originalFilename: string, attachmentData: Buf) => {
    const attachmentHtmlRoot = $('<div>').addClass('thunderbird_attachment_root');
    const attachmentFileTypeIcon = $('<img>').addClass('thunderbird_attachment_icon');
    const decryptedFileName = originalFilename.replace(/\.(pgp|gpg|asc)$/i, '');
    const uiFileExtensions = ['excel', 'word', 'png', 'jpg'];
    const matchedExtension = uiFileExtensions.find(fileExtension => decryptedFileName.endsWith(fileExtension));
    attachmentFileTypeIcon.attr('src', messenger.runtime.getURL(`/img/fileformat/${matchedExtension || 'generic'}.png`));
    const attachmentFilename = $('<div>').addClass('thunderbird_attachment_name').text(originalFilename);
    const attachmentDownloadBtn = $('<div>')
      .addClass('thunderbird_attachment_download')
      .on('click', async () => {
        await this.downloadThunderbirdAttachmentHandler(decryptedFileName, attachmentData);
      })
      .append($('<img>').attr('src', messenger.runtime.getURL('/img/svgs/download-link.svg'))); // xss-safe-value
    attachmentHtmlRoot.append(attachmentFileTypeIcon); // xss-escaped
    attachmentHtmlRoot.append(attachmentFilename); // xss-safe-value
    attachmentHtmlRoot.append(attachmentDownloadBtn); // xss-safe-value
    return attachmentHtmlRoot;
  };

  private downloadThunderbirdAttachmentHandler = async (decryptedFileName: string, encryptedData: Buf) => {
    const result = await MsgUtil.decryptMessage({
      kisWithPp: await KeyStore.getAllWithOptionalPassPhrase(this.acctEmail),
      encryptedData,
      verificationPubs: [], // todo: #4158 signature verification of attachments
    });
    if (result.success && result.content) {
      await BrowserMsg.send.bg.await.thunderbirdInitiateAttachmentDownload({ decryptedFileName, decryptedContent: result.content });
    }
    // no need to handle DecryptErrTypes.needPassphrase it was already handled by this.messageDecrypt()
  };

  private resemblesSignedMsg = (body: string) => {
    this.emailBodyFromThunderbirdMail = body;
    return (
      (body.startsWith(PgpArmor.ARMOR_HEADER_DICT.signedMsg.begin) &&
        body.includes(String(PgpArmor.ARMOR_HEADER_DICT.signedMsg.middle)) &&
        body.endsWith(String(PgpArmor.ARMOR_HEADER_DICT.signedMsg.end))) ||
      (body.startsWith(PgpArmor.ARMOR_HEADER_DICT.signature.begin) && body.endsWith(String(PgpArmor.ARMOR_HEADER_DICT.signature.end)))
    );
  };

  private resemblesAsciiArmoredMsg = (body: string): boolean => {
    const pgpRegex = /-----BEGIN PGP MESSAGE-----(.*?)-----END PGP MESSAGE-----/s;
    const pgpRegexMatch = new RegExp(pgpRegex).exec(body);
    if (pgpRegexMatch?.[0]) {
      this.emailBodyFromThunderbirdMail = pgpRegexMatch[0];
      return true;
    }
    return false;
  };
}
