/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import { ReplyOption } from '../../../../chrome/elements/compose-modules/compose-reply-btn-popover-module';
import { ContentScriptWindow } from '../../../common/browser/browser-window';
import { notifyMurdered } from './setup-webmail-content-script';

export type IntervalFunction = { interval: number; handler: () => void };

export abstract class WebmailElementReplacer {
  private replacePgpElsInterval: number;

  public abstract getIntervalFunctions: () => IntervalFunction[];
  public abstract setReplyBoxEditable: (replyOption?: ReplyOption) => Promise<void>;
  public abstract reinsertReplyBox: (replyMsgId: string) => void;
  public abstract scrollToReplyBox: (replyMsgId: string) => void;
  public abstract scrollToCursorInReplyBox: (replyMsgId: string, cursorOffsetTop: number) => void;

  public runIntervalFunctionsPeriodically = () => {
    const intervalFunctions = this.getIntervalFunctions();
    for (const intervalFunction of intervalFunctions) {
      intervalFunction.handler();
      this.replacePgpElsInterval = (window as unknown as ContentScriptWindow).TrySetDestroyableInterval(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
        if (typeof (window as any).$ === 'function') {
          intervalFunction.handler();
        } else {
          // firefox will unload jquery when extension is restarted or updated
          clearInterval(this.replacePgpElsInterval);
          notifyMurdered();
        }
      }, intervalFunction.interval);
    }
  };
}
