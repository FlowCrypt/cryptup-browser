/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import { Gmail } from '../../../common/api/email-provider/gmail/gmail';
import { Env } from '../../../common/browser/env';
import { Time } from '../../../common/browser/time';
import { ClientConfiguration } from '../../../common/client-configuration';
import { Str } from '../../../common/core/common';
import { Injector } from '../../../common/inject';
import { MessageRenderer } from '../../../common/message-renderer';
import { Notifications } from '../../../common/notifications';
import { Catch } from '../../../common/platform/catch';
import { RelayManager } from '../../../common/relay-manager';
import { XssSafeFactory } from '../../../common/xss-safe-factory';
import { WebmailVariantObject, contentScriptSetupIfVacant } from '../generic/setup-webmail-content-script';
import { WebmailElementReplacer } from '../generic/webmail-element-replacer';
import { GmailElementReplacer } from './gmail-element-replacer';

export class GmailWebmailStartup {
  private replacer: WebmailElementReplacer;

  public asyncConstructor = async () => {
    this.injectFCVarScript();
    await Time.sleep(100); // Wait until injected dom is added
    const webmailVariant = this.determineWebmailVariant();
    await contentScriptSetupIfVacant({
      name: 'gmail',
      variant: webmailVariant.gmailVariant,
      getUserAccountEmail: () => this.getUserAccountEmail(webmailVariant),
      getUserFullName: () => $('div.gb_hb div.gb_lb').text() || $('div.gb_Fb.gb_Hb').text(),
      getReplacer: () => this.replacer,
      start: this.start,
    });
  };

  private start = async (
    acctEmail: string,
    clientConfiguration: ClientConfiguration,
    injector: Injector,
    notifications: Notifications,
    factory: XssSafeFactory,
    relayManager: RelayManager
  ) => {
    this.hijackGmailHotkeys();
    injector.btns();
    const messageRenderer = await MessageRenderer.newInstance(acctEmail, new Gmail(acctEmail), relayManager, factory);
    this.replacer = new GmailElementReplacer(factory, clientConfiguration, acctEmail, messageRenderer, injector, notifications, relayManager);
    await notifications.showInitial(acctEmail);
    this.replacer.runIntervalFunctionsPeriodically();
  };

  private getUserAccountEmail = (hostPageInfo: WebmailVariantObject): undefined | string => {
    if (!window.location.search.includes('&view=btop&')) {
      // when view=btop present, FlowCrypt should not be activated
      if (hostPageInfo.email) {
        return hostPageInfo.email;
      }
      const emailRegex = /[a-z0-9._\-]+@[^…< ]+/gi;
      const acctEmailLoadingMatch = $('#loading div.msg').text().match(emailRegex);
      if (acctEmailLoadingMatch) {
        // try parse from loading div
        return acctEmailLoadingMatch[0].trim().toLowerCase();
      }
      const emailFromAccountDropdown = $('div.gb_Cb > div.gb_Ib').text()?.trim()?.toLowerCase();
      if (Str.isEmailValid(emailFromAccountDropdown)) {
        return emailFromAccountDropdown;
      }
      const titleMatch = document.title.match(emailRegex);
      if (titleMatch) {
        return titleMatch[0].trim().toLowerCase();
      }
      const emailFromAccountModal = $('div.gb_Dc > div').last()?.text()?.trim()?.toLowerCase();
      if (Str.isEmailValid(emailFromAccountModal)) {
        return emailFromAccountModal;
      }
      // eslint-disable-next-line no-underscore-dangle, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      const emailFromConfigVariable = window.gbar_?.CONFIG?.[0]?.[4]?.ka?.[5];
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      if (Str.isEmailValid(emailFromConfigVariable)) {
        return String(emailFromConfigVariable);
      }
      const emailFromUserNameAndEmail = $('.gb_2e .gb_Fc :last-child').text();
      if (Str.isEmailValid(emailFromUserNameAndEmail)) {
        return emailFromUserNameAndEmail;
      }
    }
    return undefined;
  };

  private injectFCVarScript = () => {
    const scriptElement = document.createElement('script');

    scriptElement.src = chrome.runtime.getURL('/js/common/core/feature-config-injector.js');
    (document.head || document.documentElement).appendChild(scriptElement);
  };

  private determineWebmailVariant = (): WebmailVariantObject => {
    const insights: WebmailVariantObject = {
      newDataLayer: undefined,
      newUi: undefined,
      email: undefined,
      gmailVariant: undefined,
    };

    try {
      const extracted = (JSON.parse($('body > div#FC_VAR_PASS').text()) as unknown[]).map(String);
      if (extracted[0] === 'true') {
        insights.newDataLayer = true;
      } else if (extracted[0] === 'false') {
        insights.newDataLayer = false;
      }
      if (extracted[1] === 'true') {
        insights.newUi = true;
      } else if (extracted[1] === 'false') {
        insights.newUi = false;
      }
      if (Str.isEmailValid(extracted[2])) {
        insights.email = extracted[2].trim().toLowerCase();
      }
      if (typeof insights.newDataLayer === 'undefined' && typeof insights.newUi === 'undefined' && typeof insights.email === 'undefined') {
        insights.gmailVariant = 'html';
      } else if (insights.newUi === false) {
        insights.gmailVariant = 'standard';
      } else if (insights.newUi === true) {
        insights.gmailVariant = 'new';
      }
    } catch {
      // no need to handle
    }
    return insights;
  };

  private hijackGmailHotkeys = () => {
    const keys = Env.keyCodes();
    const unsecureReplyKeyShortcuts = [keys.a, keys.r, keys.A, keys.R, keys.f, keys.F];
    $(document).on('keypress', e => {
      Catch.try(() => {
        const causesUnsecureReply = unsecureReplyKeyShortcuts.includes(e.which);
        if (
          causesUnsecureReply &&
          !$(document.activeElement!).is('input, select, textarea, div[contenteditable="true"]') && // eslint-disable-line @typescript-eslint/no-non-null-assertion
          $('iframe.reply_message').length
        ) {
          e.stopImmediatePropagation();
          this.replacer.setReplyBoxEditable().catch(Catch.reportErr);
        }
      })();
    });
  };
}
