/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Buf } from '../buf.js';
import { Catch } from '../../platform/catch.js';
import { MsgBlockParser } from '../msg-block-parser.js';
import { PgpArmor } from './pgp/pgp-armor.js';
import { opgp } from './pgp/openpgpjs-custom.js';
import { OpenPGPKey } from './pgp/openpgp-key.js';
import type * as OpenPGP from 'openpgp';
import { SmimeKey } from './smime/smime-key.js';
import { MsgBlock } from '../msg-block.js';
import { EmailParts, Str } from '../common.js';

/**
 * This is a common Key interface for both OpenPGP and X.509 keys.
 *
 * Since Key objects are frequently JSON serialized (e.g. via message passing)
 * all dates are expressed as number of milliseconds since Unix Epoch.
 * This is what `Date.now()` returns and `new Date(x)` accepts.
 */

type KeyStatus = {
  state: 'active' | 'revoked' | 'expired' | 'sign only' | 'unusable';
  statusIndicator: 'light-gray' | 'green' | 'orange' | 'yellow' | 'red';
};

export interface Key extends KeyIdentity {
  allIds: string[]; // a list of fingerprints, including those for subkeys
  created: number;
  revoked: boolean;
  lastModified: number | undefined; // date of last signature, or undefined if never had valid signature
  expiration: number | undefined; // number of millis of expiration or undefined if never expires
  usableForEncryption: boolean;
  usableForSigning: boolean;
  usableForEncryptionButExpired: boolean;
  usableForSigningButExpired: boolean;
  missingPrivateKeyForSigning: boolean;
  missingPrivateKeyForDecryption: boolean;
  emails: string[];
  identities: string[];
  fullyDecrypted: boolean;
  fullyEncrypted: boolean;
  isPublic: boolean; // isPublic and isPrivate are mutually exclusive
  isPrivate: boolean; // only one should be set to true
  algo: {
    algorithm: string;
    curve?: string;
    bits?: number;
    algorithmId: number;
  };
  issuerAndSerialNumber?: string | undefined; // DER-encoded IssuerAndSerialNumber of X.509 Certificate as raw string
}

export type PubkeyResult = { pubkey: Key; email: string; isMine: boolean };

export interface StoredKeyInfo {
  private: string;
  public: string; // this cannot be Pubkey has it's being passed to localstorage
  longid: string;
  fingerprints: string[];
  emails?: string[]; // todo - used to be missing - but migration was supposed to add it? setting back to optional for now
}

export interface PubkeyInfo {
  pubkey: Key;
  // IMPORTANT NOTE:
  // It might look like we can format PubkeyInfo[] out of Key[], but that's not good,
  // because in the storage we have the table Revocations that stores fingerprints
  // of revoked keys that may not exist in the database (Pubkeys table),
  // that is pre-emptive external revocation. So (in a rare case) the lookup method
  // receives a valid key, saves it to the storage, and after re-querying the storage,
  // this key maybe returned as revoked. This is why PubkeyInfo has revoked property
  // regardless of the fact that Key itself also has it.
  revoked: boolean;
}

export type ContactInfo = EmailParts;

export interface ContactInfoWithSortedPubkeys {
  info: ContactInfo;
  sortedPubkeys: PubkeyInfoWithLastCheck[];
}

export interface PubkeyInfoWithLastCheck extends PubkeyInfo {
  lastCheck?: number | undefined;
}

export type KeyFamily = 'openpgp' | 'x509';

export interface KeyIdentity {
  id: string; // a fingerprint of the primary key in OpenPGP, and similarly a fingerprint of the actual cryptographic key (eg RSA fingerprint) in S/MIME
  family: KeyFamily;
}

export interface KeyInfoWithIdentity extends StoredKeyInfo, KeyIdentity {}

export interface KeyInfoWithIdentityAndOptionalPp extends KeyInfoWithIdentity {
  passphrase?: string;
}

export type KeyAlgo = 'curve25519' | 'rsa2048' | 'rsa3072' | 'rsa4096';

export type PrvPacket = OpenPGP.SecretKeyPacket | OpenPGP.SecretSubkeyPacket;

export class UnexpectedKeyTypeError extends Error {}

export interface ArmoredKeyIdentityWithEmails extends KeyIdentity {
  armored: string;
  emails: string[];
}

export class KeyUtil {
  public static identityEquals(keyIdentity1: KeyIdentity, keyIdentity2: KeyIdentity) {
    return keyIdentity1.id === keyIdentity2.id && keyIdentity1.family === keyIdentity2.family;
  }

  public static filterKeysByIdentity<T extends KeyIdentity>(kis: T[], ids: KeyIdentity[]): T[] {
    return kis.filter(ki => ids.some(i => KeyUtil.identityEquals(i, ki)));
  }

  public static filterKeysByTypeAndSenderEmail(keys: KeyInfoWithIdentity[], email: string, type: 'openpgp' | 'x509' | undefined): KeyInfoWithIdentity[] {
    let foundKeys: KeyInfoWithIdentity[] = [];
    if (type) {
      foundKeys = keys.filter(key => key.emails?.includes(email.toLowerCase()) && key.family === type);
      if (!foundKeys.length) {
        foundKeys = keys.filter(key => key.family === type);
      }
    } else {
      foundKeys = keys.filter(key => key.emails?.includes(email.toLowerCase()));
      if (!foundKeys.length) {
        foundKeys = [...keys];
      }
    }
    return foundKeys;
  }

  public static groupByType<T extends { type: string }>(items: T[]): { [type: string]: T[] } {
    return items.reduce((rv: { [type: string]: T[] }, x: T) => {
      (rv[x.type] = rv[x.type] || []).push(x);
      return rv;
    }, {});
  }

  public static async isWithoutSelfCertifications(key: Key) {
    // all non-OpenPGP keys are automatically considered to be not
    // "without self certifications"
    if (key.family !== 'openpgp') {
      return false;
    }
    return await OpenPGPKey.isWithoutSelfCertifications(key);
  }

  /**
   * Read many keys, could be armored or binary, in single armor or separately, useful for importing keychains of various formats
   */
  public static async readMany(fileData: Buf): Promise<{ keys: Key[]; errs: Error[] }> {
    const allKeys: Key[] = [];
    const allErrs: Error[] = [];
    const { blocks } = MsgBlockParser.detectBlocks(fileData.toUtfStr('ignore'));
    const isImportable = (block: MsgBlock) => block.type === 'publicKey' || block.type === 'privateKey' || block.type === 'certificate';
    const armoredPublicKeyBlocks = blocks.filter(isImportable);
    const pushKeysAndErrs = async (content: string | Buf, isArmored: boolean) => {
      try {
        if (isArmored) {
          allKeys.push(...(await KeyUtil.parseMany(Str.with(content))));
        } else {
          const buf = typeof content === 'string' ? Buf.fromUtfStr(content) : content;
          const { keys, err } = await KeyUtil.readBinary(buf);
          allKeys.push(...keys);
          allErrs.push(...err);
        }
      } catch (e) {
        allErrs.push(e instanceof Error ? e : new Error(String(e)));
      }
    };
    if (armoredPublicKeyBlocks.length) {
      for (const block of blocks) {
        await pushKeysAndErrs(block.content, true);
      }
    } else {
      await pushKeysAndErrs(fileData, false);
    }
    return { keys: allKeys, errs: allErrs };
  }

  public static async parse(text: string): Promise<Key> {
    const keys = await KeyUtil.parseMany(text);
    const keysLength = keys.length;
    if (keysLength > 1) {
      throw new Error(`Found ${keysLength} keys, expected one`);
    }
    return keys[0];
  }

  public static async parseMany(text: string): Promise<Key[]> {
    const keyType = KeyUtil.getKeyFamily(text);
    if (keyType === 'openpgp') {
      return await OpenPGPKey.parseMany(text);
    } else if (keyType === 'x509') {
      // TODO: No support for parsing multiple S/MIME keys for now
      return [SmimeKey.parse(text)];
    }
    throw new UnexpectedKeyTypeError(`Key type is ${keyType}, expecting OpenPGP or x509 S/MIME`);
  }

  public static async readBinary(key: Uint8Array, passPhrase?: string): Promise<{ keys: Key[]; err: Error[] }> {
    const allKeys: Key[] = [],
      allErr: Error[] = [];
    let uncheckedOpgpKeyCount = 0;
    try {
      const keys = await opgp.readKeys({ binaryKeys: key }); // todo: opgp.readKey ?
      uncheckedOpgpKeyCount = keys.length;
      for (const key of keys) {
        try {
          // we should decrypt them all here to have consistent behavior between pkcs12 files and PGP
          // pkcs12 files must be decrypted during parsing
          // then rename this method to parseDecryptBinary
          await OpenPGPKey.validateAllDecryptedPackets(key);
          const parsed = await OpenPGPKey.convertExternalLibraryObjToKey(key);
          // if (await KeyUtil.decrypt(parsed, passPhrase, undefined, 'OK-IF-ALREADY-DECRYPTED')) {
          allKeys.push(parsed);
          // } else {
          //   allErr.push(new Error(`Wrong pass phrase for OpenPGP key ${parsed.id} (${parsed.emails[0]})`));
          // }
        } catch (e) {
          allErr.push(e as Error);
        }
      }
      /* todo: re-throw? if (err) {
        allErr.push(...err);
      } */
    } catch (e) {
      allErr.push(e as Error);
    }
    if (!uncheckedOpgpKeyCount) {
      try {
        allKeys.push(SmimeKey.parseDecryptBinary(key, passPhrase ?? ''));
        return { keys: allKeys, err: [] };
      } catch (e) {
        allErr.push(e as Error);
      }
    }
    return { keys: allKeys, err: allErr };
  }

  public static async parseBinary(key: Uint8Array, passPhrase?: string): Promise<Key[]> {
    const { keys, err } = await KeyUtil.readBinary(key, passPhrase);
    if (keys.length > 0) {
      return keys;
    }
    throw new Error(err.length ? err.map((e, i) => i + 1 + '. ' + e.message).join('\n') : 'Should not happen: no keys and no errors.');
  }

  public static armor(key: Key): string {
    const armored = (key as unknown as { rawArmored: string }).rawArmored;
    if (!armored) {
      throw new Error('The Key object has no rawArmored field.');
    }
    return armored;
  }

  // remove crypto-library objects (useful when sending the object to/from background)
  public static pack(key: Key): void {
    if (key.family === 'openpgp') {
      OpenPGPKey.pack(key);
    }
  }

  public static async diagnose(key: Key, passphrase: string): Promise<Map<string, string>> {
    let result = new Map<string, string>();
    result.set(`Key type`, key.family);
    if (key.family === 'openpgp') {
      const opgpresult = await OpenPGPKey.diagnose(key, passphrase);
      result = new Map<string, string>([...result, ...opgpresult]);
    }
    result.set(`expiration`, KeyUtil.formatResult(key.expiration));
    result.set(`internal dateBeforeExpiration`, await KeyUtil.formatResultAsync(async () => KeyUtil.dateBeforeExpirationIfAlreadyExpired(key)));
    result.set(`internal usableForEncryption`, KeyUtil.formatResult(key.usableForEncryption));
    result.set(`internal usableForSigning`, KeyUtil.formatResult(key.usableForSigning));
    result.set(`internal usableForEncryptionButExpired`, KeyUtil.formatResult(key.usableForEncryptionButExpired));
    result.set(`internal usableForSigningButExpired`, KeyUtil.formatResult(key.usableForSigningButExpired));
    return result;
  }

  public static async formatResultAsync(f: () => Promise<unknown>): Promise<string> {
    try {
      return KeyUtil.formatResult(await f());
    } catch (e) {
      return `[${String(e)}]`;
    }
  }

  public static formatResult(value: unknown): string {
    return `[-] ${String(value)}`;
  }

  public static async asPublicKey(key: Key): Promise<Key> {
    if (key.family === 'openpgp') {
      return await OpenPGPKey.asPublicKey(key);
    } else if (key.family === 'x509') {
      return SmimeKey.asPublicKey(key);
    }
    throw new UnexpectedKeyTypeError(`Key type is ${key.family}, expecting OpenPGP or x509 S/MIME`);
  }

  public static expired(key: Key): boolean {
    const exp = key.expiration;
    if (!exp) {
      return false;
    }
    return Date.now() > exp;
  }

  public static status(key: Key | undefined): KeyStatus {
    if (!key) {
      return { state: 'unusable', statusIndicator: 'red' };
    }
    let keyStatus: KeyStatus;
    if (key.revoked) {
      keyStatus = { state: 'revoked', statusIndicator: 'light-gray' };
    } else if (key.usableForEncryption) {
      keyStatus = { state: 'active', statusIndicator: 'green' };
    } else if (key.usableForEncryptionButExpired) {
      keyStatus = { state: 'expired', statusIndicator: 'orange' };
    } else if (key.usableForSigning) {
      keyStatus = { state: 'sign only', statusIndicator: 'yellow' };
    } else {
      keyStatus = { state: 'unusable', statusIndicator: 'red' };
    }
    return keyStatus;
  }

  public static statusHtml(keyid: string, key: Key | undefined): string {
    const keyStatus = KeyUtil.status(key);
    return `<span class="fc-badge fc-badge-${keyStatus.statusIndicator}" data-test="container-key-status-${keyid}">${keyStatus.state}</span>`;
  }

  public static dateBeforeExpirationIfAlreadyExpired(key: Key): Date | undefined {
    const expiration = key.expiration;
    return expiration && KeyUtil.expired(key) ? new Date(expiration - 1000) : undefined;
  }

  // todo - this should be made to tolerate smime keys
  public static async normalize(type: 'publicKey' | 'privateKey', armored: string): Promise<{ normalized: string; keys: OpenPGP.Key[] }> {
    try {
      let keys: OpenPGP.Key[] = [];
      armored = PgpArmor.normalize(armored, 'key');
      if (RegExp(PgpArmor.headers('publicKey', 're').begin).test(armored)) {
        keys = await opgp.readKeys({ armoredKeys: armored });
      } else if (RegExp(PgpArmor.headers('privateKey', 're').begin).test(armored)) {
        keys = await opgp.readKeys({ armoredKeys: armored });
      } else if (RegExp(PgpArmor.headers('encryptedMsg', 're').begin).test(armored)) {
        const packets = (await opgp.readMessage({ armoredMessage: armored })).packets;
        keys = [type === 'publicKey' ? new opgp.PublicKey(packets) : new opgp.PrivateKey(packets)];
      }
      for (const k of keys) {
        for (const u of k.users) {
          u.otherCertifications = []; // prevent key bloat
        }
      }
      return { normalized: keys.map(k => k.armor()).join('\n'), keys };
    } catch (error) {
      Catch.reportErr(error);
      return { normalized: '', keys: [] };
    }
  }

  public static async checkPassPhrase(pkey: string, passphrase: string): Promise<boolean> {
    // decrypt will change the key in place so it's important to parse the key here
    // because passing an object from the caller could have unexpected consequences
    const key = await KeyUtil.parse(pkey);
    return await KeyUtil.decrypt(key, passphrase);
  }

  public static getKeyFamily(pubkey: string): KeyFamily | 'unknown' {
    if (pubkey.includes(PgpArmor.headers('certificate').begin)) {
      return 'x509';
    } else if (pubkey.startsWith(PgpArmor.headers('pkcs12').begin)) {
      return 'x509';
    } else if (pubkey.startsWith(PgpArmor.headers('publicKey').begin)) {
      return 'openpgp';
    } else if (pubkey.startsWith(PgpArmor.headers('privateKey').begin)) {
      return 'openpgp';
    } else {
      return 'unknown';
    }
  }

  public static async decrypt(key: Key, passphrase: string, optionalKeyid?: OpenPGP.KeyID, optionalBehaviorFlag?: 'OK-IF-ALREADY-DECRYPTED'): Promise<boolean> {
    if (key.family === 'openpgp') {
      return await OpenPGPKey.decryptKey(key, passphrase, optionalKeyid, optionalBehaviorFlag);
    } else if (key.family === 'x509') {
      return await SmimeKey.decryptKey(key, passphrase, optionalBehaviorFlag);
    } else {
      throw new Error(`KeyUtil.decrypt does not support key family ${key.family}`);
    }
  }

  public static async encrypt(key: Key, passphrase: string) {
    if (key.family === 'openpgp') {
      return await OpenPGPKey.encryptKey(key, passphrase);
    } else if (key.family === 'x509') {
      return await SmimeKey.encryptKey(key, passphrase);
    } else {
      throw new Error(`KeyUtil.encrypt does not support key family ${key.family}`);
    }
  }

  public static async reformatKey(
    privateKey: Key,
    passphrase: string | undefined,
    userIds: { email: string | undefined; name: string }[],
    expireSeconds: number
  ) {
    if (privateKey.family === 'openpgp') {
      return await OpenPGPKey.reformatKey(privateKey, passphrase, userIds, expireSeconds);
    } else {
      throw new Error(`KeyUtil.reformatKey does not support key family ${privateKey.family}`);
    }
  }

  public static async getOrCreateRevocationCertificate(key: Key): Promise<string | undefined> {
    if (key.family === 'openpgp') {
      return await OpenPGPKey.getOrCreateRevocationCertificate(key);
    } else {
      throw new Error(`KeyUtil.getOrCreateRevocationCertificate does not support key family ${key.family}`);
    }
  }

  public static async keyInfoObj(prv: Key): Promise<KeyInfoWithIdentity> {
    if (!prv.isPrivate) {
      throw new Error('Key passed into KeyUtil.keyInfoObj must be a Private Key');
    }
    const pubkey = await KeyUtil.asPublicKey(prv);
    return {
      private: KeyUtil.armor(prv),
      public: KeyUtil.armor(pubkey),
      longid: KeyUtil.getPrimaryLongid(pubkey),
      emails: prv.emails,
      fingerprints: prv.allIds,
      id: prv.id,
      family: prv.family,
    };
  }

  public static getPubkeyLongids(pubkey: Key): string[] {
    if (pubkey.family !== 'x509') {
      return pubkey.allIds.map(id => OpenPGPKey.fingerprintToLongid(id));
    }
    return [KeyUtil.getPrimaryLongid(pubkey)];
  }

  public static getPrimaryLongid(pubkey: Key): string {
    if (pubkey.family !== 'x509') {
      return OpenPGPKey.fingerprintToLongid(pubkey.id);
    }
    return SmimeKey.getKeyLongid(pubkey);
  }

  public static getKeyInfoLongids(ki: KeyInfoWithIdentityAndOptionalPp): string[] {
    if (ki.family !== 'x509') {
      return ki.fingerprints.map(fp => OpenPGPKey.fingerprintToLongid(fp));
    }
    return [ki.longid];
  }

  /**
   * Used for comparing public keys that were fetched vs the stored ones
   * Soon also for private keys: https://github.com/FlowCrypt/flowcrypt-browser/issues/2602
   */
  public static isFetchedNewer({ stored, fetched }: { stored: Key; fetched: Key }) {
    if (!stored.lastModified) {
      return !!fetched.lastModified;
    }
    if (!fetched.lastModified) {
      return false;
    }
    return fetched.lastModified > stored.lastModified;
  }

  public static sortPubkeyInfos(pubkeyInfos: PubkeyInfo[]): PubkeyInfo[] {
    return pubkeyInfos.sort((a, b) => KeyUtil.getSortValue(b) - KeyUtil.getSortValue(a));
  }

  public static async parseAndArmorKeys(binaryKeysData: Uint8Array): Promise<ArmoredKeyIdentityWithEmails[]> {
    const { keys } = await KeyUtil.readMany(Buf.fromUint8(binaryKeysData));
    return keys.map(k => ({ id: k.id, emails: k.emails, armored: KeyUtil.armor(k), family: k.family }));
  }

  public static validateChecksum = (armoredText: string): boolean => {
    const lines = armoredText.split('\n').map(l => l.trim());

    // Filter out known non-data lines
    const dataCandidates = lines.filter(line => line.length > 0 && !line.startsWith('-----') && !line.startsWith('Version:') && !line.startsWith('Comment:'));

    // Find checksum line
    const checksumIndex = dataCandidates.findIndex(line => line.startsWith('='));
    if (checksumIndex === -1) return false;

    const checksumLine = dataCandidates[checksumIndex].slice(1);
    const dataLines = dataCandidates.slice(0, checksumIndex);

    // Decode checksum
    let providedBytes: string;
    try {
      providedBytes = atob(checksumLine);
    } catch {
      return false;
    }
    if (providedBytes.length !== 3) return false;

    const providedCRC = (providedBytes.charCodeAt(0) << 16) | (providedBytes.charCodeAt(1) << 8) | providedBytes.charCodeAt(2);

    // Attempt to decode all data lines (some may not be base64)
    const decodedChunks: string[] = [];
    for (const line of dataLines) {
      try {
        decodedChunks.push(atob(line));
      } catch {
        // Not a valid base64 line, skip it
      }
    }

    if (decodedChunks.length === 0) return false;

    const rawData = decodedChunks.join('');
    // eslint-disable-next-line @typescript-eslint/no-misused-spread
    const dataBytes = new Uint8Array([...rawData].map(c => c.charCodeAt(0)));

    return KeyUtil.crc24(dataBytes) === providedCRC;
  };

  private static crc24 = (dataBytes: Uint8Array): number => {
    let crc = 0xb704ce;
    for (const dataByte of dataBytes) {
      crc ^= dataByte << 16;
      for (let j = 0; j < 8; j++) {
        crc <<= 1;
        if (crc & 0x1000000) crc ^= 0x1864cfb;
      }
    }
    return crc & 0xffffff;
  };

  private static getSortValue(pubinfo: PubkeyInfo): number {
    const expirationSortValue = typeof pubinfo.pubkey.expiration === 'undefined' ? Infinity : pubinfo.pubkey.expiration;
    // sort non-revoked first, then non-expired
    return pubinfo.revoked || pubinfo.pubkey.revoked ? -Infinity : expirationSortValue;
  }
}
