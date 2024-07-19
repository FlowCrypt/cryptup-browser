/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import { Bm } from './browser/browser-msg.js';
import { Buf } from './core/buf.js';
import { EncryptionKeyStore } from './platform/store/encryption-key-store.js';
import { secureRandomBytes } from './platform/util.js';

export interface SymEncryptedMessage {
  to: string;
  uid: string;
  encryptedData: string;
  propagateToParent?: boolean;
}

export class SymmetricMessageEncryption {
  private static algoName = 'AES-GCM' as const;
  private static cryptoKeyBytesLength = 32 as const; // 256 bit
  private static ivBytesLength = 12 as const; // 96 bit

  private static cryptoKey: CryptoKey | undefined;
  public static generateIV = (): string => {
    return Buf.fromUint8(secureRandomBytes(SymmetricMessageEncryption.ivBytesLength)).toBase64Str();
  };
  public static encrypt = async (msg: Bm.RawWithWindowExtensions): Promise<SymEncryptedMessage> => {
    if (!SymmetricMessageEncryption.cryptoKey) {
      SymmetricMessageEncryption.cryptoKey = await SymmetricMessageEncryption.fromBytes(
        await EncryptionKeyStore.get(SymmetricMessageEncryption.cryptoKeyBytesLength)
      );
    }
    const iv = Buf.fromBase64Str(msg.uid);
    const data = Buf.with(JSON.stringify(msg));
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: SymmetricMessageEncryption.algoName,
        iv,
      },
      SymmetricMessageEncryption.cryptoKey,
      data
    );
    return { to: msg.to, uid: msg.uid, encryptedData: new Buf(encryptedData).toBase64Str() };
  };

  public static decrypt = async (msg: SymEncryptedMessage): Promise<Bm.RawWithWindowExtensions> => {
    if (!SymmetricMessageEncryption.cryptoKey) {
      const keyBytes = await EncryptionKeyStore.get();
      if (keyBytes.length !== SymmetricMessageEncryption.cryptoKeyBytesLength) {
        throw new Error(`Crypto key is ${keyBytes.length} bytes length (${this.cryptoKeyBytesLength} expected)`);
      }
      SymmetricMessageEncryption.cryptoKey = await SymmetricMessageEncryption.fromBytes(keyBytes);
    }
    const iv = Buf.fromBase64Str(msg.uid);
    if (iv.length !== SymmetricMessageEncryption.ivBytesLength) {
      throw new Error(`IV is ${iv.length} bytes length (${this.ivBytesLength} expected)`);
    }
    const decryptedBytes = await this.doDecrypt(iv, Buf.fromBase64Str(msg.encryptedData), SymmetricMessageEncryption.cryptoKey);
    const bm = JSON.parse(new Buf(decryptedBytes).toUtfStr()) as Bm.RawWithWindowExtensions;
    return bm;
  };

  private static doDecrypt = (iv: Buf, encryptedData: Buf, cryptoKey: CryptoKey) => {
    return crypto.subtle.decrypt(
      {
        name: SymmetricMessageEncryption.algoName,
        iv,
      },
      cryptoKey,
      encryptedData
    );
  };

  private static fromBytes = async (encryptionKeyBuffer: ArrayBuffer) => {
    return await crypto.subtle.importKey(
      'raw', // Format of the input key material
      encryptionKeyBuffer, // ArrayBuffer containing the key material
      {
        // Key algorithm parameters
        name: SymmetricMessageEncryption.algoName,
        length: new Uint8Array(encryptionKeyBuffer).length * 8, // Key length in bits
      },
      false, // Whether the key is extractable (can be exported)
      ['encrypt', 'decrypt'] // Key usages
    );
  };
}
