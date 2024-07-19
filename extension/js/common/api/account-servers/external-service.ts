/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */
'use strict';

import { Api, ProgressCb, ProgressCbs } from '../shared/api.js';
import { AcctStore } from '../../platform/store/acct-store.js';
import { Dict, Str } from '../../core/common.js';
import { ErrorReport } from '../../platform/catch.js';
import { ApiErr, BackendAuthErr } from '../shared/api-error.js';
import { FLAVOR, InMemoryStoreKeys } from '../../core/const.js';
import { Attachment } from '../../core/attachment.js';
import { ParsedRecipients } from '../email-provider/email-provider-api.js';
import { Buf } from '../../core/buf.js';
import { ClientConfigurationError, ClientConfigurationJson } from '../../client-configuration.js';
import { InMemoryStore } from '../../platform/store/in-memory-store.js';
import { Serializable } from '../../platform/store/abstract-store.js';
import { AuthenticationConfiguration } from '../../authentication-configuration.js';
import { Xss } from '../../platform/xss.js';

// todo - decide which tags to use
type EventTag = 'compose' | 'decrypt' | 'setup' | 'settings' | 'import-pub' | 'import-prv';

export namespace FesRes {
  export type ReplyToken = { replyToken: string };
  export type MessageUpload = {
    url: string; // LEGACY
    externalId: string; // LEGACY
    emailToExternalIdAndUrl?: { [email: string]: { url: string; externalId: string } };
  };
  export type ServiceInfo = { vendor: string; service: string; orgId: string; version: string; apiVersion: string };
  export type ClientConfiguration = { clientConfiguration: ClientConfigurationJson };
  export type DomainConfiguration = { authentication: AuthenticationConfiguration; clientConfiguration: ClientConfigurationJson };
}

/**
 * FlowCrypt External Service (FES) may be deployed on-prem by enterprise customers.
 * This gives them more control. All Client Configurations, log collectors, etc (as implemented) would then be handled by the FES.
 * This allows customers to be fully independent of flowcrypt.com/shared-tenant-fes
 */
// ts-prune-ignore-next
export class ExternalService extends Api {
  public url: string;

  private domain: string;
  private apiVersion = 'v1';
  private domainsThatUseLaxFesCheckEvenOnEnterprise = ['dmFsZW8uY29t'];

  public constructor(private acctEmail: string) {
    super();
    this.domain = acctEmail.toLowerCase().split('@').pop()!; // eslint-disable-line @typescript-eslint/no-non-null-assertion
    this.url = `https://fes.${this.domain}`;
  }

  /**
   * This is run during user/extension setup to figure out if this extension should be using FES or not.
   */
  public isFesInstalledAndAvailable = async (): Promise<boolean> => {
    if (['gmail.com', 'yahoo.com', 'outlook.com', 'live.com', 'googlemail.com'].includes(this.domain)) {
      // no FES expected on fes.gmail.com and similar
      return false;
    }
    try {
      // regardless if this is enterprise or consumer flavor, if FES is available, return yes
      const allowedServices = ['external-service', 'enterprise-server'];
      const serverService = (await this.getServiceInfo()).service;
      return allowedServices.includes(serverService);
    } catch (e) {
      // FES not available
      if (ApiErr.isNotFound(e)) {
        return false; // a 404 returned where FES should be is an affirmative no - FES will not be used
      }
      if (FLAVOR === 'consumer') {
        // this is a consumer flavor. Consumers are not expected to run FES, therefore
        //   a server not responding (or returning an error) is considered as no FES
        return false;
      } else if (this.domainsThatUseLaxFesCheckEvenOnEnterprise.includes(btoa(this.domain)) && ApiErr.isNetErr(e)) {
        // on some domains we don't expect FES running. This allows even enterprise flavor
        //   extension to skip FES integration on these domains.
        return false;
      } else if (this.domain.endsWith('.test')) {
        // enterprise flavor on a test domain should not require FES running (to satisfy tests)
        return false;
      } else {
        throw e;
      }
    }
  };

  public getServiceInfo = async (): Promise<FesRes.ServiceInfo> => {
    return await this.request<FesRes.ServiceInfo>(`/api/`);
  };

  public fetchAndSaveClientConfiguration = async (): Promise<ClientConfigurationJson> => {
    const auth = await this.request<AuthenticationConfiguration>(`/api/${this.apiVersion}/client-configuration/authentication?domain=${this.domain}`);
    await AcctStore.set(this.acctEmail, { authentication: auth });
    const r = await this.request<FesRes.ClientConfiguration>(`/api/${this.apiVersion}/client-configuration?domain=${this.domain}`);
    if (r.clientConfiguration && !r.clientConfiguration.flags) {
      throw new ClientConfigurationError('missing_flags');
    }
    await AcctStore.set(this.acctEmail, { rules: r.clientConfiguration });
    return r.clientConfiguration;
  };

  public reportException = async (errorReport: ErrorReport): Promise<void> => {
    await this.request(`/api/${this.apiVersion}/log-collector/exception`, { fmt: 'JSON', data: errorReport });
  };

  public helpFeedback = async (email: string, message: string): Promise<unknown> => {
    return await this.request(`/api/${this.apiVersion}/account/feedback`, { fmt: 'JSON', data: { email, message } });
  };

  public reportEvent = async (tags: EventTag[], message: string, details?: string): Promise<void> => {
    await this.request(`/api/${this.apiVersion}/log-collector/exception`, {
      fmt: 'JSON',
      data: {
        tags,
        message,
        details,
      },
    });
  };

  public webPortalMessageNewReplyToken = async (): Promise<FesRes.ReplyToken> => {
    return await this.request<FesRes.ReplyToken>(`/api/${this.apiVersion}/message/new-reply-token`, { fmt: 'JSON', data: {} });
  };

  public webPortalMessageUpload = async (
    encrypted: Uint8Array,
    associateReplyToken: string,
    from: string,
    recipients: ParsedRecipients,
    progressCb: ProgressCb
  ): Promise<FesRes.MessageUpload> => {
    const content = new Attachment({
      name: 'encrypted.asc',
      type: 'text/plain',
      data: encrypted,
    });
    const details = new Attachment({
      name: 'details.json',
      type: 'application/json',
      data: Buf.fromUtfStr(
        JSON.stringify({
          associateReplyToken,
          from,
          to: (recipients.to || []).map(Str.formatEmailWithOptionalName).map(Xss.stripEmojis),
          cc: (recipients.cc || []).map(Str.formatEmailWithOptionalName).map(Xss.stripEmojis),
          bcc: (recipients.bcc || []).map(Str.formatEmailWithOptionalName).map(Xss.stripEmojis),
        })
      ),
    });
    const multipartBody = { content, details };
    return await this.request<FesRes.MessageUpload>(`/api/${this.apiVersion}/message`, { fmt: 'FORM', data: multipartBody }, { upload: progressCb });
  };

  public messageGatewayUpdate = async (externalId: string, emailGatewayMessageId: string) => {
    await this.request(`/api/${this.apiVersion}/message/${externalId}/gateway`, {
      fmt: 'JSON',
      data: {
        emailGatewayMessageId,
      },
    });
  };

  private authHdr = async (): Promise<{ authorization: string }> => {
    const idToken = await InMemoryStore.getUntilAvailable(this.acctEmail, InMemoryStoreKeys.ID_TOKEN);
    if (idToken) {
      return { authorization: `Bearer ${idToken}` };
    }
    // user will not actually see this message, they'll see a generic login prompt
    throw new BackendAuthErr('Missing id token, please re-authenticate');
  };

  private request = async <RT>(
    path: string,
    vals?:
      | {
          data: Dict<string | Attachment>;
          fmt: 'FORM';
        }
      | { data: Dict<Serializable>; fmt: 'JSON' },
    progress?: ProgressCbs
  ): Promise<RT> => {
    const values:
      | {
          data: Dict<string | Attachment>;
          fmt: 'FORM';
          method: 'POST';
        }
      | { data: Dict<Serializable>; fmt: 'JSON'; method: 'POST' }
      | undefined = vals
      ? {
          ...vals,
          method: 'POST',
        }
      : undefined;
    return await ExternalService.apiCall(this.url, path, values, progress, await this.authHdr(), 'json');
  };
}
