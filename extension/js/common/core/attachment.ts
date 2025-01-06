/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Buf } from './buf.js';
import { Str } from './common.js';

export type Attachment$treatAs =
  | 'publicKey'
  | 'privateKey'
  | 'encryptedMsg' /* may be signed-only (known as 'signedMsg' in MsgBlockType) as well,
  should probably be renamed to 'cryptoMsg' to not be confused with 'encryptedMsg' in MsgBlockType */
  | 'hidden'
  | 'signature'
  | 'encryptedFile'
  | 'plainFile'
  | 'inlineImage'
  | 'needChunk'
  | 'maybePgp';
type ContentTransferEncoding = '7bit' | 'quoted-printable' | 'base64';
export type AttachmentId = { id: string; msgId: string } | { url: string }; // a way to extract data
export type AttachmentProperties = {
  type?: string;
  name?: string;
  length?: number;
  inline?: boolean;
  treatAs?: Attachment$treatAs;
  cid?: string;
  contentDescription?: string;
  contentTransferEncoding?: ContentTransferEncoding;
};
export type ThunderbirdAttachment = {
  name: string;
  contentType: string;
  data: Buf;
  treatAs: Attachment$treatAs;
};
export type AttachmentMeta = (AttachmentId | { data: Uint8Array }) & AttachmentProperties;

export type FcAttachmentLinkData = { name: string; type: string; size: number };

export type TransferableAttachment = (AttachmentId | { data: /* base64 see #2587 */ string }) & AttachmentProperties;

export class Attachment {
  // Regex to trigger message download and processing based on attachment file names
  // todo: it'd be better to compile this regex based on the data we have in `treatAs` method
  public static readonly webmailNamePattern =
    /^(((cryptup|flowcrypt)-backup-[a-z0-9]+\.(key|asc))|(.+\.pgp)|(.+\.gpg)|(.+\.asc)|(OpenPGP_signature(.asc)?)|(noname)|(message)|(PGPMIME version identification)|(ATT[0-9]{5})|())$/m;
  public static readonly encryptedMsgNames = [
    'msg.asc',
    'message.asc',
    'encrypted.asc',
    'encrypted.eml.pgp',
    'Message.pgp',
    'openpgp-encrypted-message.asc',
    '.asc.pgp',
  ];

  public length = NaN;
  public type: string;
  public name: string;
  public url: string | undefined;
  public id: string | undefined;
  public msgId: string | undefined;
  public inline: boolean;
  public cid: string | undefined;
  public contentDescription: string | undefined;
  public contentTransferEncoding?: ContentTransferEncoding;

  private bytes: Uint8Array | undefined;
  private treatAsValue: Attachment$treatAs | undefined; // this field is to disable on-the-fly detection by this.treatAs()

  public constructor(attachmentMeta: AttachmentMeta) {
    if ('data' in attachmentMeta) {
      this.bytes = attachmentMeta.data;
      this.length = attachmentMeta.data.length;
    } else {
      this.length = Number(attachmentMeta.length);
    }
    this.name = attachmentMeta.name || '';
    this.type = attachmentMeta.type || 'application/octet-stream';
    this.url = 'url' in attachmentMeta ? attachmentMeta.url : undefined;
    this.inline = !!attachmentMeta.inline;
    this.id = 'id' in attachmentMeta ? attachmentMeta.id : undefined;
    this.msgId = 'msgId' in attachmentMeta ? attachmentMeta.msgId : undefined;
    this.treatAsValue = attachmentMeta.treatAs;
    this.cid = attachmentMeta.cid;
    this.contentDescription = attachmentMeta.contentDescription;
    this.contentTransferEncoding = attachmentMeta.contentTransferEncoding;
  }

  public static treatAsForPgpEncryptedAttachments = (mimeType: string | undefined, pgpEncryptedIndex: number | undefined) => {
    let treatAs: 'hidden' | 'encryptedMsg' | undefined;
    if (mimeType === 'application/pgp-encrypted' && pgpEncryptedIndex === 0) {
      treatAs = 'hidden';
    }
    if (mimeType === 'application/octet-stream' && pgpEncryptedIndex === 1) {
      treatAs = 'encryptedMsg';
    }
    return treatAs;
  };

  public static keyinfoAsPubkeyAttachment = (ki: { public: string; longid: string }) => {
    const data = Buf.fromUtfStr(ki.public);
    return new Attachment({
      data,
      type: 'application/pgp-keys',
      contentTransferEncoding: Str.is7bit(data) ? '7bit' : 'quoted-printable',
      name: `0x${ki.longid}.asc`,
    });
  };

  public static sanitizeName = (name: string): string => {
    const trimmed = name.trim();
    if (trimmed === '') {
      return '_';
    }
    return trimmed.replace(/[\u0000\u002f\u005c]/g, '_').replace(/__+/g, '_');
  };

  public static attachmentId = (): string => {
    return `f_${Str.sloppyRandom(30)}@flowcrypt`;
  };

  public static toTransferableAttachment = (attachmentMeta: AttachmentMeta): TransferableAttachment => {
    return 'data' in attachmentMeta
      ? {
          ...attachmentMeta,
          data: Buf.fromUint8(attachmentMeta.data).toBase64Str(), // should we better convert to url?
        }
      : attachmentMeta;
  };

  public static fromTransferableAttachment = (t: TransferableAttachment): Attachment => {
    return new Attachment(
      'data' in t
        ? {
            ...t,
            data: Buf.fromBase64Str(t.data),
          }
        : t
    );
  };

  public isPublicKey = (): boolean => {
    if (this.treatAsValue) {
      return this.treatAsValue === 'publicKey';
    }
    return (
      (this.type === 'application/pgp-keys' && !this.isPrivateKey()) ||
      /^(0|0x)?([A-F0-9]{16}|[A-F0-9]{8}([A-F0-9]{8})?)\.asc(\.pgp)?$/i.test(this.name) || // Key ID (8 or 16 characters) with .asc extension (optional .pgp)
      (this.name.toLowerCase().includes('public') && /[A-F0-9]{8}.*\.asc$/g.test(this.name)) || // name contains the word "public", any key id and ends with .asc
      (this.name.endsWith('.asc') && this.hasData() && Buf.with(this.getData().subarray(0, 100)).toUtfStr().includes('-----BEGIN PGP PUBLIC KEY BLOCK-----'))
    );
  };

  public hasData = () => {
    return this.bytes instanceof Uint8Array;
  };

  public setData = (bytes: Uint8Array) => {
    if (this.hasData()) {
      throw new Error('Attachment bytes already set');
    }
    this.bytes = bytes;
  };

  public getData = (): Buf => {
    if (this.bytes instanceof Buf) {
      return this.bytes;
    }
    if (this.bytes instanceof Uint8Array) {
      return new Buf(this.bytes);
    }
    throw new Error('Attachment has no data set');
  };

  public isImage = () => {
    return this.type.startsWith('image/') || this.type.startsWith('img/');
  };

  public treatAs = (attachments: Attachment[], isBodyEmpty = false): Attachment$treatAs => {
    if (this.treatAsValue) {
      // pre-set
      return this.treatAsValue;
    } else if (['PGPexch.htm.pgp', 'PGPMIME version identification', 'Version.txt', 'PGPMIME Versions Identification'].includes(this.name)) {
      return 'hidden'; // PGPexch.htm.pgp is html alternative of textual body content produced by PGP Desktop and GPG4o
    } else if (this.name === 'signature.asc') {
      return 'signature';
    } else if (this.type === 'application/pgp-signature') {
      // this may be a signature for an attachment following these patterns:
      // sample.name.sig for sample.name.pgp #3448
      // or sample.name.sig for sample.name
      if (attachments.length > 1) {
        const nameWithoutExtension = Str.getFilenameWithoutExtension(this.name);
        if (attachments.some(a => a !== this && (a.name === nameWithoutExtension || Str.getFilenameWithoutExtension(a.name) === nameWithoutExtension))) {
          return 'hidden';
        }
      }
      return 'signature';
    } else if (this.inline && this.isImage()) {
      return 'inlineImage';
    } else if (!this.name && !this.isImage() && !['application/octet-stream', 'multipart/mixed', 'message/global'].includes(this.type)) {
      // this.name may be '' or undefined - catch either
      return this.length < 100 ? 'hidden' : 'encryptedMsg';
    } else if (this.name === 'msg.asc' && this.length < 100 && this.type === 'application/pgp-encrypted') {
      return 'hidden'; // mail.ch does this - although it looks like encrypted msg, it will just contain PGP version eg "Version: 1"
    } else if (Attachment.encryptedMsgNames.includes(this.name)) {
      return 'encryptedMsg';
    } else if (this.name === 'message' && isBodyEmpty) {
      // treat message as encryptedMsg when empty body for the 'message' attachment
      return 'encryptedMsg';
    } else if (this.name.match(/(\.pgp$)|(\.gpg$)|(\.[a-zA-Z0-9]{3,4}\.asc$)/g)) {
      // ends with one of .gpg, .pgp, .???.asc, .????.asc
      return 'encryptedFile';
      // todo: after #4906 is done we should "decrypt" the encryptedFile here to see if it's a binary 'publicKey' (as in message 1869220e0c8f16dd)
    } else if (this.isPublicKey()) {
      return 'publicKey';
    } else if (this.isPrivateKey()) {
      return 'privateKey';
    } else {
      const isAmbiguousAscFile = this.name.endsWith('.asc'); // ambiguous .asc name
      const isAmbiguousNonameFile = !this.name || this.name === 'noname'; // may not even be OpenPGP related
      if (!this.inline && this.length < 100000 && (isAmbiguousAscFile || isAmbiguousNonameFile) && !this.isImage()) {
        if (isAmbiguousNonameFile && ['application/octet-stream', 'message/global'].includes(this.type)) {
          return 'plainFile';
        }
        return this.hasData() ? 'maybePgp' : 'needChunk';
      }
      return 'plainFile';
    }
  };

  public isPgpMimeVersion = () => {
    return this.type === 'application/pgp-encrypted' && this.name.length === 0 && this.getData().toUtfStr() === 'Version: 1';
  };

  public shouldBeHidden = () => {
    return (
      this.type === 'application/pgp-keys' || this.isPublicKey() || this.inline || Attachment.encryptedMsgNames.some(filename => this.name.includes(filename))
    );
  };

  public isExecutableFile = () => {
    return [
      'ade',
      'adp',
      'apk',
      'appx',
      'appxbundle',
      'bat',
      'cab',
      'chm',
      'cmd',
      'com',
      'cpl',
      'diagcab',
      'diagcfg',
      'diagpack',
      'dll',
      'dmg',
      'ex',
      'ex_',
      'exe',
      'hta',
      'img',
      'ins',
      'iso',
      'isp',
      'jar',
      'jnlp',
      'js',
      'jse',
      'lib',
      'lnk',
      'mde',
      'msc',
      'msi',
      'msix',
      'msixbundle',
      'msp',
      'mst',
      'nsh',
      'pif',
      'ps1',
      'scr',
      'sct',
      'shb',
      'sys',
      'vb',
      'vbe',
      'vbs',
      'vhd',
      'vxd',
      'wsc',
      'wsf',
      'wsh',
      'xll',
    ].some(exeFileExtension => this.name.endsWith('.' + exeFileExtension));
  };

  private isPrivateKey = (): boolean => {
    return (
      Boolean(this.name.match(/(cryptup|flowcrypt)-backup-([a-z0-9]+(?:\-[A-F0-9]{40})?)\.(key|asc)$/g)) ||
      (/\.(asc|key)$/.test(this.name) &&
        this.hasData() &&
        Buf.with(this.getData().subarray(0, 100)).toUtfStr().includes('-----BEGIN PGP PRIVATE KEY BLOCK-----'))
    );
  };
}
