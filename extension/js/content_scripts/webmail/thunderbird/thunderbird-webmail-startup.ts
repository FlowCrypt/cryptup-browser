/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */
import { BrowserMsg } from '../../../common/browser/browser-msg';
import { contentScriptSetupIfVacant } from '../generic/setup-webmail-content-script';
import { ThunderbirdElementReplacer } from './thunderbird-element-replacer';

export class ThunderbirdWebmailStartup {
  private replacer: ThunderbirdElementReplacer;

  public asyncConstructor = async () => {
    await contentScriptSetupIfVacant({
      name: 'thunderbird',
      variant: undefined,
      getUserAccountEmail: async () => String(await BrowserMsg.send.bg.await.thunderbirdGetCurrentUser()),
      getUserFullName: () => undefined, // todo, but can start with undefined
      getReplacer: () => this.replacer,
      start: this.start,
    });
  };

  private start = async () => {
    this.replacer = new ThunderbirdElementReplacer();
    // doesn't need hearbeat-like content replacer as the extension noticeably slows the Thunderbird client.
    await this.replacer.handleThunderbirdMessageParsing();
    // todo: show notification using Thunderbird Notification as contentscript notification or such does not work.
    // await notifications.showInitial(acctEmail);
    // notifications.show(
    //   'FlowCrypt Thunderbird support is still in early development, and not expected to function properly yet. Support will be gradually added in upcoming versions.'
    // );
  };
}
