/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Assert } from '../../js/common/assert.js';
import { BrowserMsg } from '../../js/common/browser/browser-msg.js';
import { Catch } from '../../js/common/platform/catch.js';
import { Key, KeyUtil } from '../../js/common/core/crypto/key.js';
import { PgpArmor } from '../../js/common/core/crypto/pgp/pgp-armor.js';
import { Str } from '../../js/common/core/common.js';
import { Ui } from '../../js/common/browser/ui.js';
import { Url } from '../../js/common/core/common.js';
import { View } from '../../js/common/view.js';
import { Xss } from '../../js/common/platform/xss.js';
import { ContactStore } from '../../js/common/platform/store/contact-store.js';
import { Buf } from '../../js/common/core/buf.js';
import { OpenPGPKey } from '../../js/common/core/crypto/pgp/openpgp-key.js';

// todo - this should use KeyImportUI for consistency.
View.run(
  class PgpPubkeyView extends View {
    private readonly acctEmail: string;
    private readonly parentTabId: string;
    private readonly armoredPubkey: string;
    private readonly frameId: string;
    private readonly compact: boolean; // means the details take up very little space.
    private readonly minimized: boolean; // means I have to click to see details.
    private parsedPublicKeys: Key[] | undefined;
    private firstParsedPublicKey: Key | undefined;
    private isExpired: boolean | undefined;

    public constructor() {
      super();
      const uncheckedUrlParams = Url.parse(['acctEmail', 'armoredPubkey', 'parentTabId', 'minimized', 'compact', 'frameId']);
      this.acctEmail = Assert.urlParamRequire.string(uncheckedUrlParams, 'acctEmail');
      this.parentTabId = Assert.urlParamRequire.string(uncheckedUrlParams, 'parentTabId');
      this.armoredPubkey = PgpArmor.normalize(Assert.urlParamRequire.string(uncheckedUrlParams, 'armoredPubkey'), 'publicKey');
      this.frameId = Assert.urlParamRequire.string(uncheckedUrlParams, 'frameId');
      this.compact = uncheckedUrlParams.compact === true;
      this.minimized = uncheckedUrlParams.minimized === true;
    }

    public render = async () => {
      Ui.event.protect();
      try {
        const pubKey = await KeyUtil.parse(this.armoredPubkey);
        this.isExpired = KeyUtil.expired(pubKey);
        if (pubKey.revoked) {
          await ContactStore.saveRevocation(undefined, pubKey);
        }
        this.parsedPublicKeys = [pubKey];
      } catch (e) {
        console.error('Unusable key: ' + e);
        this.parsedPublicKeys = [];
      }
      this.firstParsedPublicKey = this.parsedPublicKeys ? this.parsedPublicKeys[0] : undefined;
      $('.pubkey').text(this.armoredPubkey);
      if (this.compact) {
        $('.hide_if_compact').hide();
        $('body').css({ border: 'none', padding: 0 });
        $('.line').removeClass('line');
      }
      $('.line.fingerprints, .line.add_contact').css('display', this.minimized ? 'none' : 'block');
      if (this.parsedPublicKeys.length === 1) {
        $('.line.fingerprints .fingerprint').text(Str.spaced(this.firstParsedPublicKey?.id || 'err'));
      } else {
        $('.line.fingerprints').css({ display: 'none' });
      }
      if (this.firstParsedPublicKey) {
        if (
          !this.firstParsedPublicKey.usableForEncryptionButExpired &&
          !this.firstParsedPublicKey.usableForSigningButExpired &&
          !this.firstParsedPublicKey.usableForEncryption &&
          !this.firstParsedPublicKey.usableForSigning
        ) {
          await this.showKeyNotUsableError();
        } else {
          let emailText = '';
          if (this.parsedPublicKeys.length === 1) {
            const email = this.firstParsedPublicKey.emails[0];
            if (email) {
              emailText = email;
              $('.input_email').val(email); // checked above
            }
          } else {
            emailText = 'more than one person';
            $('.input_email').css({ display: 'none' });
            Xss.sanitizeAppend(
              '.add_contact',
              Xss.escape(
                ' for ' +
                  this.parsedPublicKeys
                    .map(pub => pub.emails[0])
                    .filter(e => !!e)
                    .join(', ')
              )
            );
          }
          Xss.sanitizePrepend(
            '#pgp_block.pgp_pubkey .result',
            `<span>This message includes a Public Key for <span class= "email">${Xss.escape(emailText)}</span>.</span>`
          );
          $('.pubkey').addClass('good');
          this.setBtnText().catch(Catch.reportErr);
        }
      } else {
        let fixed = this.armoredPubkey;
        while (/\n> |\n>\n/.test(fixed)) {
          fixed = fixed.replace(/\n> /g, '\n').replace(/\n>\n/g, '\n\n');
        }
        if (fixed !== this.armoredPubkey) {
          // try to re-render it after un-quoting, (minimized because it is probably their own pubkey quoted by the other guy)
          window.location.href = Url.create('pgp_pubkey.htm', {
            armoredPubkey: fixed,
            minimized: true,
            acctEmail: this.acctEmail,
            parentTabId: this.parentTabId,
            frameId: this.frameId,
          });
        } else {
          await this.showKeyNotUsableError();
        }
      }
      this.sendResizeMsg();
    };

    public setHandlers = () => {
      $('.action_add_contact').on(
        'click',
        this.setHandler(btn => this.addContactHandler(btn))
      );
      $('.input_email').on(
        'keyup',
        this.setHandler(() => this.setBtnText())
      );
      $('.action_show_full').on(
        'click',
        this.setHandler(btn => this.showFullKeyHandler(btn))
      );
    };

    private getErrorText = async () => {
      let errorStr = '';
      const { keys, errs } = await KeyUtil.readMany(Buf.fromUtfStr(this.armoredPubkey));
      errorStr = errs.join('\n');
      for (const key of keys) {
        const errorMessage = await OpenPGPKey.checkPublicKeyError(key);
        if (errorMessage) {
          const match = new RegExp(/Error encrypting message: (.+)$/).exec(errorMessage);
          // remove `error: error encrypting message: part`, so error message will begin directly from error reason
          if (match) {
            errorStr += match[1];
          } else {
            errorStr += errorMessage;
          }
        }
      }
      return errorStr;
    };

    private sendResizeMsg = () => {
      const origHeight = $('#pgp_block').height();
      if (!origHeight) {
        // https://github.com/FlowCrypt/flowcrypt-browser/issues/3519
        // unsure why this happens. Sometimes height will come in as exactly 0 after the iframe was already properly sized
        // that then causes to default to 30px for height, hiding contents of the iframe if it in fact is taller
        return;
      }
      const desiredHeight = origHeight + (this.compact ? 10 : 30);
      BrowserMsg.send.setCss(this.parentTabId, {
        selector: `iframe#${this.frameId}`,
        css: { height: `${desiredHeight}px` },
      });
    };

    private setBtnText = async () => {
      /* eslint-disable @typescript-eslint/no-non-null-assertion */
      if (this.parsedPublicKeys!.length > 1) {
        $('.action_add_contact').text('import ' + this.parsedPublicKeys!.length + ' public keys');
        /* eslint-enable @typescript-eslint/no-non-null-assertion */
      } else {
        const contactWithPubKeys = await ContactStore.getOneWithAllPubkeys(undefined, String($('.input_email').val()));
        const isExistingKey =
          contactWithPubKeys?.sortedPubkeys?.some(existing => this.parsedPublicKeys?.some(parsedPubkey => existing.pubkey.id === parsedPubkey.id)) ?? false;
        $('.action_add_contact')
          .text(isExistingKey ? 'update key' : `import ${this.isExpired ? 'expired ' : ''}key`)
          .css('background-color', this.isExpired ? '#989898' : '');
      }
    };

    private showKeyNotUsableError = async () => {
      $('.error_container').removeClass('hidden');
      $('.error_introduce_label').html(`This OpenPGP key is not usable.<br/><small>(${await this.getErrorText()})</small>`); // xss-escaped
      $('.hide_if_error').hide();
      $('.fingerprints, .add_contact, #manual_import_warning').remove();
      const email = this.firstParsedPublicKey?.emails[0];
      if (email) {
        $('.error_container .input_error_email').val(`${this.firstParsedPublicKey?.emails[0]}`);
      } else {
        $('.error_container .input_error_email').hide();
      }
      $('.pubkey').addClass('bad');
    };

    private addContactHandler = async (addContactBtn: HTMLElement) => {
      /* eslint-disable @typescript-eslint/no-non-null-assertion */
      if (this.parsedPublicKeys!.length > 1) {
        const emails = new Set<string>();
        for (const pubkey of this.parsedPublicKeys!) {
          /* eslint-enable @typescript-eslint/no-non-null-assertion */
          const email = pubkey.emails[0];
          if (email) {
            await ContactStore.update(undefined, email, { pubkey: KeyUtil.armor(pubkey) });
            emails.add(email);
          }
        }
        Xss.sanitizeReplace(addContactBtn, '<span class="good">added public keys</span>');
        BrowserMsg.send.addToContacts(this.parentTabId);
        for (const email of emails) {
          BrowserMsg.send.reRenderRecipient('broadcast', { email });
        }
        $('.input_email').remove();
        /* eslint-disable @typescript-eslint/no-non-null-assertion */
      } else if (this.parsedPublicKeys!.length) {
        if (Str.isEmailValid(String($('.input_email').val()))) {
          const email = String($('.input_email').val());
          await ContactStore.update(undefined, email, { pubkey: KeyUtil.armor(this.parsedPublicKeys![0]) });
          /* eslint-enable @typescript-eslint/no-non-null-assertion */
          BrowserMsg.send.addToContacts(this.parentTabId);
          Xss.sanitizeReplace(addContactBtn, `<span class="good">${Xss.escape(String($('.input_email').val()))} added</span>`);
          $('.input_email').remove();
          BrowserMsg.send.reRenderRecipient('broadcast', { email });
        } else {
          await Ui.modal.error('This email is invalid, please check for typos. Not added.');
          $('.input_email').trigger('focus');
        }
      }
    };

    private showFullKeyHandler = (showFullBtn: HTMLElement) => {
      $(showFullBtn).hide();
      $('pre.pubkey, .line.fingerprints, .line.add_contact').show();
      this.sendResizeMsg();
    };
  }
);
