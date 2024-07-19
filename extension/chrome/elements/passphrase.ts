/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { KeyUtil, KeyInfoWithIdentity } from '../../js/common/core/crypto/key.js';
import { StorageType } from '../../js/common/platform/store/abstract-store.js';
import { Assert } from '../../js/common/assert.js';
import { BrowserMsg } from '../../js/common/browser/browser-msg.js';
import { Catch } from '../../js/common/platform/catch.js';
import { Ui } from '../../js/common/browser/ui.js';
import { Url, Str, stringTuple } from '../../js/common/core/common.js';
import { View } from '../../js/common/view.js';
import { Xss } from '../../js/common/platform/xss.js';
import { initPassphraseToggle } from '../../js/common/ui/passphrase-ui.js';
import { KeyStore } from '../../js/common/platform/store/key-store.js';
import { PassphraseStore } from '../../js/common/platform/store/passphrase-store.js';
import { Settings } from '../../js/common/settings.js';
import { ClientConfiguration } from '../../js/common/client-configuration.js';
import { Lang } from '../../js/common/lang.js';
import { AcctStore } from '../../js/common/platform/store/acct-store.js';
import { BruteForceProtection } from '../../js/common/brute-force-protection.js';

const passPhraseTypes = stringTuple('embedded', 'sign', 'message', 'draft', 'attachment', 'quote', 'backup', 'update_key');
type PassPhraseType = (typeof passPhraseTypes)[number];

View.run(
  class PassphraseView extends View {
    public fesUrl?: string;
    public readonly parentTabId: string;
    private readonly acctEmail: string;
    private readonly longids: string[];
    private readonly type: PassPhraseType;
    private readonly initiatorFrameId?: string;
    private readonly bruteForceProtection: BruteForceProtection;
    private keysWeNeedPassPhraseFor: KeyInfoWithIdentity[] | undefined;
    private clientConfiguration!: ClientConfiguration;

    public constructor() {
      super();
      const uncheckedUrlParams = Url.parse(['acctEmail', 'parentTabId', 'longids', 'type', 'initiatorFrameId']);
      this.acctEmail = Assert.urlParamRequire.string(uncheckedUrlParams, 'acctEmail');
      this.parentTabId = Assert.urlParamRequire.string(uncheckedUrlParams, 'parentTabId');
      const longidsParam = Assert.urlParamRequire.string(uncheckedUrlParams, 'longids');
      this.longids = longidsParam ? longidsParam.split(',') : [];
      this.type = Assert.urlParamRequire.oneof(uncheckedUrlParams, 'type', passPhraseTypes);
      this.initiatorFrameId = Assert.urlParamRequire.optionalString(uncheckedUrlParams, 'initiatorFrameId');
      this.bruteForceProtection = new BruteForceProtection(this.acctEmail);
    }

    public render = async () => {
      Ui.event.protect();
      const storage = await AcctStore.get(this.acctEmail, ['fesUrl']);
      await this.bruteForceProtection.init();
      this.fesUrl = storage.fesUrl;
      this.clientConfiguration = await ClientConfiguration.newInstance(this.acctEmail);
      if (!this.clientConfiguration.forbidStoringPassPhrase()) {
        $('.forget-pass-phrase-label').removeClass('hidden');
      }
      if (this.clientConfiguration.usesKeyManager() || this.clientConfiguration.forbidStoringPassPhrase()) {
        $('#lost-pass-phrase').removeAttr('id').removeAttr('href');
        $('.lost-pass-phrase-with-ekm').show();
      } else {
        $('.lost-pass-phrase').show();
      }
      await initPassphraseToggle(['passphrase']);
      const allPrivateKeys = await KeyStore.get(this.acctEmail);
      if (this.longids.length === 0) {
        this.longids.push(...allPrivateKeys.map(ki => ki.longid));
      }
      this.keysWeNeedPassPhraseFor = allPrivateKeys.filter(ki => this.longids.includes(ki.longid));
      let passphraseText = '';
      switch (this.type) {
        case 'embedded':
          $('.passphrase_text_container').hide();
          $('div.separator').hide();
          $('body#settings > div#content.dialog').css({ width: 'inherit', background: '#fafafa' });
          $('.line.which_key').css({ display: 'none', position: 'absolute', visibility: 'hidden', left: '5000px' });
          break;
        case 'sign':
          passphraseText = Lang.passphraseRequired.sign;
          break;
        case 'draft':
          passphraseText = Lang.passphraseRequired.draft;
          break;
        case 'attachment':
          passphraseText = Lang.passphraseRequired.attachment;
          break;
        case 'quote':
          passphraseText = Lang.passphraseRequired.quote;
          break;
        case 'backup':
          passphraseText = Lang.passphraseRequired.backup;
          break;
        case 'update_key':
          passphraseText = Lang.passphraseRequired.updateKey;
          break;
        default:
          passphraseText = Lang.passphraseRequired.email;
          break;
      }
      $('.passphrase_text').text(passphraseText);
      $('#passphrase').trigger('focus');
      if (allPrivateKeys.length > 1) {
        let html: string;
        if (this.keysWeNeedPassPhraseFor.length === 1) {
          html = `For key Fingerprint: <span class="good">${Xss.escape(Str.spaced(this.keysWeNeedPassPhraseFor[0].fingerprints[0] || ''))}</span>`;
        } else {
          html = 'Pass phrase needed for any of the following keys:';
          for (const i of this.keysWeNeedPassPhraseFor.keys()) {
            html += `<div>Fingerprint ${String(i + 1)}: <span class="good">${Xss.escape(
              Str.spaced(this.keysWeNeedPassPhraseFor[i].fingerprints[0]) || ''
            )}</span></div>`;
          }
        }
        Xss.sanitizeRender('.which_key', html);
        $('.which_key').css('display', 'block');
      }
      Ui.setTestState('ready');
    };

    public setHandlers = () => {
      $('#passphrase').keyup(this.setHandler(() => this.renderNormalPpPrompt()));
      $('.action_close').on(
        'click',
        this.setHandler(() => this.closeDialog())
      );
      $('.action_ok').on(
        'click',
        this.setHandler(() => this.submitHandler())
      );
      $('#lost-pass-phrase').on(
        'click',
        this.setHandler((el, ev) => {
          ev.preventDefault();
          Ui.modal
            .info(
              `
        <div style="text-align: initial">
          <strong>Do you have at least one other working device where
          you can still read your encrypted email?</strong>
          <p><strong>If yes:</strong> open the working device and go to
          <code>FlowCrypt Settings</code> > <code>Security</code> >
          <code>Change Pass Phrase</code>.<br>
          It will let you change it without knowing the previous one. When done,
          <a href class="reset-flowcrypt">reset FlowCrypt on this device</a>
          and use the new pass phrase during the recovery step when
          you set up FlowCrypt on this device again.
          <p><strong>If no:</strong> unfortunately, you will not be able to read
          previously encrypted emails regardless of what you do.
          You can <a href class="reset-flowcrypt">reset FlowCrypt on this device</a>
          and then click <code>Lost your pass phrase?</code> during recovery step.
        </div>
      `,
              true
            )
            .catch(Catch.reportErr);
          $('.reset-flowcrypt').on(
            'click',
            this.setHandler(async (el, ev) => {
              ev.preventDefault();
              if (await Settings.resetAccount(this.acctEmail)) {
                this.closeDialog();
              }
            })
          );
        })
      );
      $('#passphrase').keydown(
        this.setHandler((el, ev) => {
          if (ev.key === 'Enter') {
            $('.action_ok').trigger('click');
          }
        })
      );
      $('body').on(
        'keydown',
        this.setHandler((el, ev) => {
          if (ev.key === 'Escape') {
            this.closeDialog();
          }
        })
      );
    };

    private renderNormalPpPrompt = () => {
      $('#passphrase').css('border-color', '');
      $('#passphrase').css('color', 'black');
      $('#passphrase').trigger('focus');
    };

    private renderFailedEntryPpPrompt = () => {
      $('#passphrase').val('');
      $('#passphrase').css('border-color', 'red');
      $('#passphrase').css('color', 'red');
      $('#passphrase').attr('placeholder', 'Please try again');
    };

    private closeDialog = (entered = false, initiatorFrameId?: string) => {
      BrowserMsg.send.passphraseEntry({ entered, initiatorFrameId }, () => BrowserMsg.send.closeDialog(this));
    };

    private submitHandler = async () => {
      if (await this.bruteForceProtection.shouldDisablePassphraseCheck()) {
        return;
      }
      const pass = String($('#passphrase').val());
      const storageType: StorageType =
        $('.forget-pass-phrase-checkbox').prop('checked') || this.clientConfiguration.forbidStoringPassPhrase() ? 'session' : 'local';
      let atLeastOneMatched = false;
      let unlockCount = 0; // may include non-matching keys
      const allPrivateKeys = await KeyStore.get(this.acctEmail);
      for (const keyinfo of allPrivateKeys) {
        // if passphrase matches more keys, it will save the pass phrase for all keys
        const prv = await KeyUtil.parse(keyinfo.private);
        try {
          if (await KeyUtil.decrypt(prv, pass)) {
            unlockCount++;
            await PassphraseStore.set(storageType, this.acctEmail, keyinfo, pass);
            if (this.longids.includes(keyinfo.longid)) {
              atLeastOneMatched = true;
            }
            if (storageType === 'session') {
              // TODO: change to 'broadcast' when issue with 'broadcast' is fixed
              BrowserMsg.send.addEndSessionBtn(this.parentTabId);
            }
          }
        } catch (e) {
          if (e instanceof Error && e.message === 'Unknown s2k type.') {
            let msg = `Your key with fingerprint ${keyinfo.fingerprints[0]} is not supported yet (${String(e)}).`;
            msg += `\n\nPlease ${Lang.general.contactMinimalSubsentence(!!this.fesUrl)} with details about how this key was created.`;
            await Ui.modal.error(msg);
          } else {
            throw e;
          }
        }
      }
      if (unlockCount && allPrivateKeys.length > 1) {
        Ui.toast(`${unlockCount} of ${allPrivateKeys.length} keys ${unlockCount > 1 ? 'were' : 'was'} unlocked by this pass phrase`);
      }
      if (atLeastOneMatched) {
        await this.bruteForceProtection.passphraseCheckSucceed();
        this.closeDialog(true, this.initiatorFrameId);
      } else {
        await this.bruteForceProtection.passphraseCheckFailed();
        this.renderFailedEntryPpPrompt();
        Catch.setHandledTimeout(() => this.renderNormalPpPrompt(), 1500);
      }
    };
  }
);
