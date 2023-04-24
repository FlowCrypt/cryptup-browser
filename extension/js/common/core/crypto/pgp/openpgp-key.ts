/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */
import { Key, PrvPacket, KeyAlgo, KeyUtil, UnexpectedKeyTypeError, PubkeyInfo } from '../key.js';
import { opgp } from './openpgpjs-custom.js';
import { Catch } from '../../../platform/catch.js';
import { Str, Value } from '../../common.js';
import { Buf } from '../../buf.js';
import type * as OpenPGP from 'openpgp';
import { PgpMsgMethod, VerifyRes } from './msg-util.js';
import * as Stream from '@openpgp/web-stream-tools';

type OpenpgpMsgOrCleartext = OpenPGP.Message<OpenPGP.Data> | OpenPGP.CleartextMessage;
interface KeyWithPrivateFields extends Key {
  internal: OpenPGP.Key | string; // usable key without weak packets
  rawArmored: string;
}

export class OpenPGPKey {
  private static readonly encryptionText = 'This is the text we are encrypting!';

  // mapping of algo names to required param count, lazy initialized
  private static paramCountByAlgo: { [key: number]: { pub: number; priv: number } };

  public static parse = async (text: string): Promise<Key> => {
    const keys = await OpenPGPKey.parseMany(text);
    const keysLength = keys.length;
    if (keysLength > 1) {
      throw new Error(`Found ${keysLength} OpenPGP keys, expected one`);
    }
    return keys[0];
  };

  public static parseMany = async (text: string): Promise<Key[]> => {
    const resultKeys = await opgp.readKeys({ armoredKeys: text });
    /* todo: test exception and re-wrap?
    if (result.err) {
      throw new Error('Cannot parse OpenPGP key: ' + result.err + ' for: ' + text);
    }
    */
    const keys: Key[] = [];
    for (const key of resultKeys) {
      await OpenPGPKey.validateAllDecryptedPackets(key);
      keys.push(await OpenPGPKey.convertExternalLibraryObjToKey(key));
    }
    return keys;
  };

  // remove crypto-library objects (useful when sending the object to/from background)
  public static pack = (key: Key) => {
    const keyWithPrivateFields = key as unknown as KeyWithPrivateFields;
    if (typeof keyWithPrivateFields.internal !== 'string') {
      keyWithPrivateFields.internal = new Buf(keyWithPrivateFields.internal.write()).toRawBytesStr();
    }
  };

  public static validateAllDecryptedPackets = async (key: OpenPGP.Key): Promise<void> => {
    const decryptedPackets = key
      .toPacketList()
      .filter(OpenPGPKey.isPacketPrivate)
      .filter(packet => packet.isDecrypted());
    for (const prvPacket of decryptedPackets) {
      await prvPacket.validate(); // gnu-dummy never raises an exception, invalid keys raise exceptions
    }
  };

  public static asPublicKey = async (pubkey: Key): Promise<Key> => {
    if (pubkey.family !== 'openpgp') {
      throw new UnexpectedKeyTypeError(`Key type is ${pubkey.family}, expecting OpenPGP`);
    }
    if (pubkey.isPrivate) {
      return await OpenPGPKey.convertExternalLibraryObjToKey((await OpenPGPKey.extractExternalLibraryObjFromKey(pubkey)).toPublic());
    }
    return pubkey;
  };

  public static decryptKey = async (
    key: Key,
    passphrase: string,
    optionalKeyid?: OpenPGP.KeyID,
    optionalBehaviorFlag?: 'OK-IF-ALREADY-DECRYPTED'
  ): Promise<boolean> => {
    const prv = await OpenPGPKey.extractExternalLibraryObjFromKey(key);
    if (!prv.isPrivate()) {
      throw new Error('Nothing to decrypt in a public key');
    }
    if (!(await OpenPGPKey.decryptPrivateKey(prv, passphrase, optionalKeyid, optionalBehaviorFlag))) {
      return false;
    }
    await OpenPGPKey.convertExternalLibraryObjToKey(prv, key);
    return true;
  };

  public static encryptKey = async (key: Key, passphrase: string) => {
    const prv = await OpenPGPKey.extractExternalLibraryObjFromKey(key);
    if (!passphrase || passphrase === 'undefined' || passphrase === 'null') {
      throw new Error(`Encryption passphrase should not be empty:${typeof passphrase}:${passphrase}`);
    }
    if (!prv.isPrivate()) {
      throw new Error(`No private key packets in key to encrypt. Is this a private key?`);
    }
    const secretPackets = prv
      .getKeys()
      .map(k => k.keyPacket)
      .filter(OpenPGPKey.isPacketPrivate);
    const encryptedPacketCount = secretPackets.filter(p => !p.isDecrypted()).length;
    if (!secretPackets.length) {
      throw new Error(`No private key packets in key to encrypt. Is this a private key?`);
    }
    if (encryptedPacketCount) {
      throw new Error(`Cannot encrypt a key that has ${encryptedPacketCount} of ${secretPackets.length} private packets still encrypted`);
    }
    const encryptedPrv = await opgp.encryptKey({ privateKey: prv, passphrase });
    if (!OpenPGPKey.isFullyEncrypted(encryptedPrv)) {
      throw new Error('Expected key to be fully encrypted after prv.encrypt');
    }
    await OpenPGPKey.convertExternalLibraryObjToKey(encryptedPrv, key);
  };

  public static decryptMessage = async (message: OpenPGP.Message<OpenPGP.Data>, privateKeys: Key[], passwords?: string[]) => {
    const opgpKeys = await Promise.all(privateKeys.map(key => OpenPGPKey.extractExternalLibraryObjFromKey(key)));
    return await message.decrypt(
      opgpKeys.filter(key => key.isPrivate()).map(key => key as OpenPGP.PrivateKey),
      passwords
    );
  };

  public static encryptMessage: PgpMsgMethod.Encrypt = async ({ pubkeys, signingPrv, pwd, data, filename, armor, date }) => {
    if (!pubkeys && !pwd) {
      throw new Error('no-pubkeys-no-challenge');
    }
    const message = await opgp.createMessage({ binary: data, filename, date });
    const encryptionKeys = await Promise.all(pubkeys?.map(OpenPGPKey.extractExternalLibraryObjFromKey) ?? []);
    // TODO: Investigate unwrapping?
    const signingKeys: OpenPGP.PrivateKey[] = [];
    if (signingPrv) {
      const openPgpPrv = await OpenPGPKey.extractExternalLibraryObjFromKey(signingPrv);
      if (openPgpPrv?.isPrivate()) {
        signingKeys.push(openPgpPrv);
      }
    }
    if (armor) {
      return {
        type: 'openpgp',
        data: Buf.fromRawBytesStr(await opgp.encrypt({ format: 'armored', message, date, encryptionKeys, passwords: pwd ? [pwd] : undefined, signingKeys })),
      };
    } else {
      return {
        type: 'openpgp',
        data: await opgp.encrypt({ format: 'binary', message, date, encryptionKeys, passwords: pwd ? [pwd] : undefined, signingKeys }),
      };
    }
  };

  public static isWithoutSelfCertifications = async (key: Key) => {
    const opgpPrv = await OpenPGPKey.extractExternalLibraryObjFromKey(key);
    return await Catch.doesReject(opgpPrv.verifyPrimaryKey(), ['No self-certifications', 'Could not find valid self-signature']);
  };

  public static reformatKey = async (
    privateKey: Key,
    passphrase: string | undefined,
    userIDs: { email: string | undefined; name: string }[],
    expireSeconds: number
  ) => {
    const opgpPrv = (await OpenPGPKey.extractExternalLibraryObjFromKey(privateKey)) as OpenPGP.PrivateKey; // todo: check isPrivate()?
    const keyPair = await opgp.reformatKey({
      privateKey: opgpPrv,
      passphrase,
      userIDs,
      keyExpirationTime: expireSeconds,
    });
    return await OpenPGPKey.parse(keyPair.privateKey);
  };

  /**
   * TODO: should be private, will change when readMany is rewritten
   * @param opgpKey - original OpenPGP.js key
   * @param keyToUpdate - an existing Key object to update, optional. Useful in encryptKey and decryptKey, because the operation
   *    is done on the original supplied object.
   */
  public static convertExternalLibraryObjToKey = async (opgpKey: OpenPGP.Key, keyToUpdate?: Key): Promise<Key> => {
    const { identities, emails } = await OpenPGPKey.getSortedUserids(opgpKey);
    let lastModified: undefined | number;
    try {
      lastModified = await OpenPGPKey.getLastSigTime(opgpKey);
    } catch (e) {
      // never had any valid signature
    }
    const fingerprint = opgpKey.getFingerprint();
    if (!fingerprint) {
      throw new Error('Key does not have a fingerprint and cannot be parsed.');
    }
    const algoInfo = opgpKey.keyPacket.getAlgorithmInfo();
    const {
      encryptionKey = undefined,
      encryptionKeyIgnoringExpiration = undefined,
      signingKey = undefined,
      signingKeyIgnoringExpiration = undefined,
      expiration = undefined,
    } = await OpenPGPKey.getSigningAndEncryptionKeys(opgpKey);
    const missingPrivateKeyForSigning = signingKeyIgnoringExpiration?.keyPacket
      ? OpenPGPKey.arePrivateParamsMissing(signingKeyIgnoringExpiration.keyPacket)
      : false;
    const missingPrivateKeyForDecryption = encryptionKeyIgnoringExpiration?.keyPacket
      ? OpenPGPKey.arePrivateParamsMissing(encryptionKeyIgnoringExpiration.keyPacket)
      : false;
    const fullyDecrypted = opgpKey.isPrivate() ? OpenPGPKey.isFullyDecrypted(opgpKey) : true; /* public keys are always decrypted */
    const fullyEncrypted = opgpKey.isPrivate() ? OpenPGPKey.isFullyEncrypted(opgpKey) : false; /* public keys are never encrypted */
    const key = keyToUpdate || ({} as Key); // if no key to update, use empty object, will get props assigned below
    Object.assign(key, {
      family: 'openpgp',
      id: fingerprint.toUpperCase(),
      allIds: opgpKey.getKeys().map(k => k.getFingerprint().toUpperCase()),
      usableForEncryption: encryptionKey ? true : false,
      usableForEncryptionButExpired: !encryptionKey && !!encryptionKeyIgnoringExpiration,
      usableForSigning: signingKey ? true : false,
      usableForSigningButExpired: !signingKey && !!signingKeyIgnoringExpiration,
      missingPrivateKeyForSigning,
      missingPrivateKeyForDecryption,
      // valid emails extracted from uids
      emails,
      // full uids that have valid emails in them
      identities,
      lastModified,
      expiration,
      created: opgpKey.getCreationTime().getTime(),
      fullyDecrypted,
      fullyEncrypted,
      isPublic: !opgpKey.isPrivate(),
      isPrivate: opgpKey.isPrivate(),
      algo: {
        algorithm: algoInfo.algorithm,
        bits: algoInfo.bits,
        curve: algoInfo.curve,
        algorithmId: opgp.enums.publicKey[algoInfo.algorithm],
      },
      revoked: opgpKey.revocationSignatures.length > 0,
    } as Key);
    const keyWithPrivateFields = key as KeyWithPrivateFields;
    keyWithPrivateFields.internal = opgpKey;
    keyWithPrivateFields.rawArmored = opgpKey.armor();
    return key;
  };

  /**
   * Returns cleartext signed message if detached=false
   * Returns signature if detached=true, armored
   */
  public static sign = async (signingPrivate: Key, text: string, detached = false): Promise<string> => {
    const signingPrv = (await OpenPGPKey.extractExternalLibraryObjFromKey(signingPrivate)) as OpenPGP.PrivateKey; // todo: throw?
    if (detached) {
      const message = await opgp.createMessage({ text });
      return await opgp.sign({ message, format: 'armored', signingKeys: [signingPrv], detached });
    }
    const message = await opgp.createCleartextMessage({ text });
    return await opgp.sign({ message, signingKeys: [signingPrv] });
  };

  public static getOrCreateRevocationCertificate = async (key: Key): Promise<string | undefined> => {
    let opgpKey = await OpenPGPKey.extractExternalLibraryObjFromKey(key);
    if (!(await opgpKey.isRevoked())) {
      if (!opgpKey.isPrivate()) {
        throw new Error(`Key ${key.id} is not a private key`);
      }
      opgpKey = (await opgp.revokeKey({ key: opgpKey, format: 'object' })).privateKey;
    }
    const certificate = await opgpKey.getRevocationCertificate();
    if (!certificate) {
      return undefined;
    } else {
      return await Stream.readToEnd(certificate);
    }
  };

  public static applyRevocationCertificate = async (key: Key, revocationCertificate: string): Promise<Key> => {
    const keyObj = await OpenPGPKey.extractExternalLibraryObjFromKey(key);
    if (keyObj.isPrivate()) {
      return await OpenPGPKey.convertExternalLibraryObjToKey((await opgp.revokeKey({ key: keyObj, revocationCertificate, format: 'object' })).privateKey);
    } else {
      return await OpenPGPKey.convertExternalLibraryObjToKey((await opgp.revokeKey({ key: keyObj, revocationCertificate, format: 'object' })).publicKey);
    }
  };

  public static keyFlagsToString = (flags: OpenPGP.enums.keyFlags): string => {
    const strs: string[] = [];
    if (flags & opgp.enums.keyFlags.encryptCommunication) {
      strs.push('encrypt_communication');
    }
    if (flags & opgp.enums.keyFlags.encryptStorage) {
      strs.push('encrypt_storage');
    }
    if (flags & opgp.enums.keyFlags.signData) {
      strs.push('sign_data');
    }
    if (flags & opgp.enums.keyFlags.certifyKeys) {
      strs.push('certify_keys');
    }
    return '[' + strs.join(', ') + ']';
  };

  public static diagnose = async (pubkey: Key, passphrase: string): Promise<Map<string, string>> => {
    const key = await OpenPGPKey.extractExternalLibraryObjFromKey(pubkey);
    const result = new Map<string, string>();
    result.set(`Is Private?`, KeyUtil.formatResult(key.isPrivate()));
    const users = await key.verifyAllUsers();
    for (let i = 0; i < users.length; i++) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      result.set(`User id ${i}`, (users[i].valid ? '' : '* REVOKED, INVALID OR MISSING SIGNATURE * ') + users[i].userID);
    }
    const user = await key.getPrimaryUser();
    result.set(`Primary User`, user?.user?.userID?.userID || 'No primary user');
    result.set(`Fingerprint`, Str.spaced(key.getFingerprint().toUpperCase() || 'err'));
    const subKeys = key.subkeys;
    result.set(`Subkeys`, KeyUtil.formatResult(subKeys ? subKeys.length : subKeys));
    result.set(`Primary key algo`, KeyUtil.formatResult(opgp.enums.read(opgp.enums.publicKey, key.keyPacket.algorithm)));
    const flags = await OpenPGPKey.getPrimaryKeyFlags(key);
    result.set(`Usage flags`, KeyUtil.formatResult(OpenPGPKey.keyFlagsToString(flags)));
    if (key.isPrivate() && !OpenPGPKey.isFullyDecrypted(key)) {
      result.set(
        `key decrypt`,
        await KeyUtil.formatResultAsync(async () => {
          return (await OpenPGPKey.decryptPrivateKey(key, passphrase)) ? 'success' : 'INCORRECT PASSPHRASE';
        })
      );
      result.set(`isFullyDecrypted`, KeyUtil.formatResult(OpenPGPKey.isFullyDecrypted(key)));
      result.set(`isFullyEncrypted`, KeyUtil.formatResult(OpenPGPKey.isFullyEncrypted(key)));
    }
    result.set(
      `Primary key verify`,
      await KeyUtil.formatResultAsync(async () => {
        await key.verifyPrimaryKey(); // throws
        return `valid`;
      })
    );
    result.set(`Primary key creation?`, await KeyUtil.formatResultAsync(async () => OpenPGPKey.formatDate(key.getCreationTime())));
    result.set(`Primary key expiration?`, await KeyUtil.formatResultAsync(async () => OpenPGPKey.formatDate(await key.getExpirationTime())));
    result.set(`Primary key getBitSize?`, await KeyUtil.formatResultAsync(async () => await key.getAlgorithmInfo().bits));
    const encryptResult = await OpenPGPKey.testEncryptDecrypt(key);
    await Promise.all(encryptResult.map(msg => result.set(`Encrypt/Decrypt test: ${msg}`, '')));
    if (key.isPrivate()) {
      result.set(`Sign/Verify test`, await KeyUtil.formatResultAsync(async () => await OpenPGPKey.testSignVerify(key)));
    }
    for (let subKeyIndex = 0; subKeyIndex < subKeys.length; subKeyIndex++) {
      const subKey = subKeys[subKeyIndex];
      const skn = `SK ${subKeyIndex} >`;
      result.set(`${skn} LongId`, await KeyUtil.formatResultAsync(async () => OpenPGPKey.bytesToLongid(subKey.getKeyID().bytes)));
      result.set(`${skn} Created`, await KeyUtil.formatResultAsync(async () => OpenPGPKey.formatDate(subKey.keyPacket.created)));
      result.set(`${skn} Algo`, await KeyUtil.formatResultAsync(async () => `${subKey.getAlgorithmInfo().algorithm}`));
      const flags = (await OpenPGPKey.getSubKeySigningFlags(key, subKey)) | (await OpenPGPKey.getSubKeyEncryptionFlags(key, subKey));
      result.set(`${skn} Usage flags`, KeyUtil.formatResult(OpenPGPKey.keyFlagsToString(flags)));
      result.set(
        `${skn} Verify`,
        await KeyUtil.formatResultAsync(async () => {
          await subKey.verify();
          return 'OK';
        })
      );
      result.set(
        `${skn} Subkey object type`,
        await KeyUtil.formatResultAsync(async () => (subKey.keyPacket instanceof opgp.SecretSubkeyPacket ? 'SecretSubkeyPacket' : 'PublicSubkeyPacket'))
      );
      result.set(`${skn} Subkey getBitSize`, await KeyUtil.formatResultAsync(async () => subKey.getAlgorithmInfo().bits)); // No longer exists on object
      result.set(`${skn} Subkey decrypted`, KeyUtil.formatResult(subKey.isDecrypted()));
      result.set(`${skn} Binding signature length`, await KeyUtil.formatResultAsync(async () => subKey.bindingSignatures.length));
      for (let sigIndex = 0; sigIndex < subKey.bindingSignatures.length; sigIndex++) {
        const sig = subKey.bindingSignatures[sigIndex];
        const sgn = `${skn} SIG ${sigIndex} >`;
        result.set(`${sgn} Key flags`, await KeyUtil.formatResultAsync(async () => sig.keyFlags));
        result.set(`${sgn} Version`, await KeyUtil.formatResultAsync(async () => sig.version));
        result.set(`${sgn} Public key algorithm`, await KeyUtil.formatResultAsync(async () => sig.publicKeyAlgorithm));
        result.set(`${sgn} Sig creation time`, KeyUtil.formatResult(OpenPGPKey.formatDate(sig.created)));
        result.set(
          `${sgn} Sig expiration time`,
          await KeyUtil.formatResultAsync(async () => {
            if (!subKey.keyPacket.created) {
              return 'unknown key creation time';
            }
            return OpenPGPKey.formatDate(subKey.keyPacket.created, sig.keyExpirationTime);
          })
        );
        result.set(
          `${sgn} Verify`,
          await KeyUtil.formatResultAsync(async () => {
            const dataToVerify = { key: key.keyPacket, bind: subKey.keyPacket };
            await sig.verify(key.keyPacket, opgp.enums.signature.subkeyBinding, dataToVerify); // throws
            return `valid`;
          })
        );
      }
    }
    return result;
  };

  public static bytesToLongid = (binaryString: string) => {
    if (binaryString.length !== 8) {
      throw new Error(`Unexpected keyid bytes format (len: ${binaryString.length}): "${binaryString}"`);
    }
    return Buf.fromRawBytesStr(binaryString).toHexStr(true);
  };

  public static fingerprintToLongid = (fingerprint: string) => {
    if (fingerprint.length === 40) {
      // pgp keys
      return fingerprint.substr(-16).toUpperCase();
    }
    throw new Error(`Unexpected fingerprint format (len: ${fingerprint.length}): "${fingerprint}"`);
  };

  public static isFullyDecrypted = (key: OpenPGP.PrivateKey): boolean => {
    const nonDummyPrvPackets = OpenPGPKey.getPrvPackets(key);
    return nonDummyPrvPackets.every(p => p.isDecrypted() === true);
  };

  public static isFullyEncrypted = (key: OpenPGP.PrivateKey): boolean => {
    const nonDummyPrvPackets = OpenPGPKey.getPrvPackets(key);
    return nonDummyPrvPackets.every(p => p.isDecrypted() === false);
  };

  /**
   * todo - could return a Key
   */
  public static create = async (
    userIDs: { name: string; email: string }[],
    variant: KeyAlgo,
    passphrase: string,
    expireInMonths: number | undefined
  ): Promise<{ private: string; public: string }> => {
    const opt: OpenPGP.KeyOptions = { userIDs, passphrase };
    if (variant === 'curve25519') {
      opt.type = 'ecc';
      opt.curve = 'curve25519';
    } else if (variant === 'rsa2048') {
      opt.type = 'rsa';
      opt.rsaBits = 2048;
    } else if (variant === 'rsa3072') {
      opt.type = 'rsa';
      opt.rsaBits = 3072;
    } else {
      opt.type = 'rsa';
      opt.rsaBits = 4096;
    }
    if (expireInMonths) {
      opt.keyExpirationTime = 60 * 60 * 24 * 30 * expireInMonths; // seconds from now
    }
    const k = await opgp.generateKey({ ...opt, format: 'armored' });
    return { public: k.publicKey, private: k.privateKey };
  };

  public static isPacketPrivate = (p: OpenPGP.BasePacket): p is PrvPacket => {
    return p instanceof opgp.SecretKeyPacket || p instanceof opgp.SecretSubkeyPacket;
  };

  public static isBaseKeyPacket = (p: OpenPGP.BasePacket): p is OpenPGP.BasePublicKeyPacket => {
    return (
      p instanceof opgp.SecretKeyPacket || p instanceof opgp.SecretSubkeyPacket || p instanceof opgp.PublicKeyPacket || p instanceof opgp.PublicSubkeyPacket
    );
  };

  public static isPacketDecrypted = async (pubkey: Key, keyid: OpenPGP.KeyID) => {
    const [k] = (await OpenPGPKey.extractExternalLibraryObjFromKey(pubkey)).getKeys(keyid); // keyPacket.isDecrypted(keyID);
    if (!k) {
      throw new Error('KeyID not found');
    }
    const keyPacket = k.keyPacket;
    if (!OpenPGPKey.isPacketPrivate(keyPacket)) {
      throw new Error('Cannot check packet encryption status of secret key in a Public Key');
    }
    return keyPacket.isDecrypted() === true;
  };

  public static verify = async (msg: OpenpgpMsgOrCleartext, pubs: PubkeyInfo[]): Promise<VerifyRes> => {
    // todo: double-check if S/MIME ever gets here
    const validKeys = pubs.filter(x => !x.revoked && x.pubkey.family === 'openpgp').map(x => x.pubkey);
    // todo: #4172 revoked longid may result in incorrect "Missing pubkey..." output
    const verifyRes: VerifyRes = {
      match: null, // eslint-disable-line no-null/no-null
      signerLongids: [],
      suppliedLongids: validKeys.map(x => x.allIds.map(fp => OpenPGPKey.fingerprintToLongid(fp))).reduce((a, b) => a.concat(b), []),
    };
    const opgpKeys = await Promise.all(validKeys.map(x => OpenPGPKey.extractExternalLibraryObjFromKey(x)));
    // todo: expired?
    try {
      const signerLongids = msg.getSigningKeyIDs().map(kid => OpenPGPKey.bytesToLongid(kid.bytes));
      const text = msg instanceof opgp.CleartextMessage ? msg.getText() : msg.getLiteralData(); // todo: is this important?
      if (text) {
        // encrypted message
        verifyRes.content = typeof text === 'string' ? Buf.fromUtfStr(text) : Buf.fromUint8(text);
      }
      // is there an intersection?
      if (signerLongids.some(longid => verifyRes.suppliedLongids.includes(longid))) {
        const verifications = await msg.verify(opgpKeys);
        await Promise.all(verifications.map(verification => verification.verified)); // throws on invalid signature
        // todo - a valid signature is a valid signature, and should be surfaced. Currently, if any of the signatures are not valid, it's showing all as invalid
        // .. as it is now this could allow an attacker to append bogus signatures to validly signed messages, making otherwise correct messages seem incorrect
        // .. which is not really an issue - an attacker that can append signatures could have also just slightly changed the message, causing the same experience
        // .. so for now #wontfix unless a reasonable usecase surfaces
        verifyRes.match = verifications.length > 0;
      }
      verifyRes.signerLongids = Value.arr.unique(signerLongids);
    } catch (verifyErr) {
      verifyRes.match = null; // eslint-disable-line no-null/no-null
      if (verifyErr instanceof Error && verifyErr.message === 'Can only verify message with one literal data packet.') {
        verifyRes.error = 'FlowCrypt is not equipped to verify this message';
        verifyRes.isErrFatal = true; // don't try to re-fetch the message from API
      } else if (verifyErr instanceof Error && verifyErr.message.startsWith('Insecure message hash algorithm:')) {
        verifyRes.error = `${verifyErr.message}. Sender is using old, insecure OpenPGP software.`;
        verifyRes.isErrFatal = true; // don't try to re-fetch the message from API
      } else if (verifyErr instanceof Error && verifyErr.message === 'Signature is expired') {
        verifyRes.error = verifyErr.message;
        verifyRes.isErrFatal = true; // don't try to re-fetch the message from API
      } else if (verifyErr instanceof Error && verifyErr.message.endsWith('digest did not match')) {
        verifyRes.error = verifyErr.message;
        verifyRes.match = false;
      } else {
        verifyRes.error = `Error verifying this message: ${String(verifyErr)}`;
        Catch.reportErr(verifyErr);
      }
    }
    return verifyRes;
  };

  private static getExpirationAsDateOrUndefined = (expirationTime: Date | typeof Infinity | null) => {
    return expirationTime instanceof Date ? expirationTime : undefined; // we don't differ between Infinity and null
  };

  private static getSortedUserids = async (key: OpenPGP.Key) => {
    const primaryUser = await Catch.undefinedOnException(key.getPrimaryUser());
    // if there is no good enough user id to serve as primary identity, we assume other user ids are even worse
    if (primaryUser?.user?.userID?.userID) {
      const primaryUserId = primaryUser.user.userID.userID;
      const identities = [
        primaryUserId, // put the "primary" identity first
        // other identities go in indeterministic order
        ...Value.arr.unique((await key.verifyAllUsers()).filter(x => x.valid && x.userID !== primaryUserId).map(x => x.userID)),
      ];
      const emails = identities.map(userid => Str.parseEmail(userid).email).filter(Boolean);
      if (emails.length === identities.length) {
        // OpenPGP.js uses RFC 5322 `email-addresses` parser, so we expect all identities to contain a valid e-mail address
        return { emails, identities };
      }
    }
    return { emails: [], identities: [] };
  };

  // mimicks OpenPGP.helper.getLatestValidSignature
  private static getLatestValidSignature = async (
    signatures: OpenPGP.SignaturePacket[],
    primaryKey: OpenPGP.BasePublicKeyPacket,
    signatureType: OpenPGP.enums.signature,
    dataToVerify: object | Uint8Array
  ): Promise<OpenPGP.SignaturePacket | undefined> => {
    let signature: OpenPGP.SignaturePacket | undefined;
    for (let i = signatures.length - 1; i >= 0; i--) {
      try {
        if (
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          (!signature || signatures[i].created! >= signature.created!) &&
          // check binding signature is not expired (ie, check for V4 expiration time)
          !signatures[i].isExpired()
        ) {
          await signatures[i].verify(primaryKey, signatureType, dataToVerify);
          signature = signatures[i];
        }
      } catch (e) {
        // skip signature with failed verification
      }
    }
    return signature;
  };

  private static getValidEncryptionKeyPacketFlags = (key: OpenPGP.Key | OpenPGP.Subkey, verifiedSignature: OpenPGP.SignaturePacket): OpenPGP.enums.keyFlags => {
    if (!verifiedSignature.keyFlags || verifiedSignature.revoked !== false) {
      // Sanity check
      return 0;
    }
    if (
      [
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.dsa),
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.rsaSign),
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.ecdsa),
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.eddsa),
      ].includes(key.getAlgorithmInfo().algorithm)
    ) {
      return 0; // disallow encryption for these algorithms
    }
    return verifiedSignature.keyFlags[0] & (opgp.enums.keyFlags.encryptCommunication | opgp.enums.keyFlags.encryptStorage);
  };

  private static getValidSigningKeyPacketFlags = (key: OpenPGP.Key | OpenPGP.Subkey, verifiedSignature: OpenPGP.SignaturePacket): OpenPGP.enums.keyFlags => {
    if (!verifiedSignature.keyFlags || verifiedSignature.revoked !== false) {
      // Sanity check
      return 0;
    }
    if (
      [
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.rsaEncrypt),
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.elgamal),
        opgp.enums.read(opgp.enums.publicKey, opgp.enums.publicKey.ecdh),
      ].includes(key.getAlgorithmInfo().algorithm)
    ) {
      return 0; // disallow signing for these algorithms
    }
    return verifiedSignature.keyFlags[0] & (opgp.enums.keyFlags.signData | opgp.enums.keyFlags.certifyKeys);
  };

  private static getSubKeySigningFlags = async (key: OpenPGP.Key, subKey: OpenPGP.Subkey): Promise<OpenPGP.enums.keyFlags> => {
    const primaryKey = key.keyPacket;
    // await subKey.verify(primaryKey);
    const dataToVerify = { key: primaryKey, bind: subKey.keyPacket };
    const bindingSignature = await OpenPGPKey.getLatestValidSignature(subKey.bindingSignatures, primaryKey, opgp.enums.signature.subkeyBinding, dataToVerify);
    if (
      bindingSignature &&
      bindingSignature.embeddedSignature &&
      (await OpenPGPKey.getLatestValidSignature([bindingSignature.embeddedSignature], subKey.keyPacket, opgp.enums.signature.keyBinding, dataToVerify))
    ) {
      return OpenPGPKey.getValidSigningKeyPacketFlags(subKey, bindingSignature);
    }
    return 0;
  };

  private static getSubKeyEncryptionFlags = async (key: OpenPGP.Key, subKey: OpenPGP.Subkey): Promise<OpenPGP.enums.keyFlags> => {
    const primaryKey = key.keyPacket;
    // await subKey.verify(primaryKey);
    const dataToVerify = { key: primaryKey, bind: subKey.keyPacket };
    const bindingSignature = await OpenPGPKey.getLatestValidSignature(subKey.bindingSignatures, primaryKey, opgp.enums.signature.subkeyBinding, dataToVerify);
    if (bindingSignature) {
      return OpenPGPKey.getValidEncryptionKeyPacketFlags(subKey, bindingSignature);
    }
    return 0;
  };

  private static getPrimaryKeyFlags = async (key: OpenPGP.Key): Promise<OpenPGP.enums.keyFlags> => {
    // Note: The selected selfCertification (and hence the flags) will differ based on the current date
    const primaryUser = await Catch.undefinedOnException(key.getPrimaryUser());
    const selfCertification = primaryUser?.selfCertification;
    if (!selfCertification) {
      return 0;
    }
    return OpenPGPKey.getValidEncryptionKeyPacketFlags(key, selfCertification) | OpenPGPKey.getValidSigningKeyPacketFlags(key, selfCertification);
  };

  /**
   * Get latest self-signature date, in utc millis.
   * This is used to figure out how recently was key updated, and if one key is newer than other.
   */
  private static getLastSigTime = async (key: OpenPGP.Key): Promise<number> => {
    const primaryKey = key.keyPacket;
    const allVerifiedSignatures: OpenPGP.SignaturePacket[] = [];
    for (const user of key.users) {
      const dataToVerify = { userID: user.userID, key: primaryKey };
      const selfCertification = await OpenPGPKey.getLatestValidSignature(
        user.selfCertifications,
        key.keyPacket,
        opgp.enums.signature.certGeneric,
        dataToVerify
      );
      if (selfCertification) {
        allVerifiedSignatures.push(selfCertification);
      }
    }
    for (const subKey of key.subkeys) {
      const dataToVerify = { key: primaryKey, bind: subKey.keyPacket };
      const bindingSignature = await OpenPGPKey.getLatestValidSignature(subKey.bindingSignatures, primaryKey, opgp.enums.signature.subkeyBinding, dataToVerify);
      if (bindingSignature) {
        allVerifiedSignatures.push(bindingSignature);
      }
    }
    if (allVerifiedSignatures.length > 0) {
      return Math.max(...allVerifiedSignatures.map(x => (x.created ? x.created.getTime() : 0)));
    }
    throw new Error('No valid signature found in key');
  };

  private static extractExternalLibraryObjFromKey = async (key: Key): Promise<OpenPGP.Key> => {
    if (key.family !== 'openpgp') {
      throw new UnexpectedKeyTypeError(`Key type is ${key.family}, expecting OpenPGP`);
    }
    const keyWithPrivateFields = key as KeyWithPrivateFields;
    const internal = keyWithPrivateFields.internal;
    if (!internal) {
      throw new Error('Object has type == "openpgp" but no internal key.');
    } else if (typeof internal === 'string') {
      keyWithPrivateFields.internal = await opgp.readKey({ binaryKey: Buf.fromRawBytesStr(internal) });
      return keyWithPrivateFields.internal;
    }
    return internal;
  };

  private static getSigningAndEncryptionKeys = async (key: OpenPGP.Key) => {
    // As per discussion https://github.com/FlowCrypt/flowcrypt-browser/pull/4725/files#r1096675897
    // We're using getSigningKey and getEncryptionKey calls instead of trying to replicate OpenPGP.js behaviour when selecting keys,
    // but it isn't very simple.
    // Using a null value for the `date` parameter (meaning: ignore date) instead of undefined value (meaning: take current date)
    // it is possible to find a (sub)key that was usable for singing/encryption at some date, but some edge cases are not covered by this mechanism:
    //    1) the subkey may have `created` property after primary key's expiration, and shouldn't be considered usable, (see: `key was never usable` unit test),
    //    2) the subkey may tell us an incorrect "overall" expiration date, as there may be another subkey with later expiration that didn't show up
    // because OpenPGP.js sorts subkeys by ascending values of `created` property.
    //
    // So this algo is implemented:
    // - for already expired keys:
    //    1) create a list of all the subkey's expiration dates (prior to the primary key's expiration)
    //    2) call getEncryptionKey/getSigningKey with dates from the list in descending order until we get a usable key.
    // - for usable keys:
    //    call getEncryptionKey with the expiration date of the found usable key to find a next usable encryption key
    //    until we reach a date when no usable encryption key is found.
    const encryptionKey = await Catch.undefinedOnException(key.getEncryptionKey());
    const signingKey = await Catch.undefinedOnException(key.getSigningKey());
    const possibleExpirations: number[] = [];
    const primaryKeyExpiration = OpenPGPKey.getExpirationAsDateOrUndefined(await key.getExpirationTime())?.getTime();
    if (!encryptionKey || !signingKey) {
      possibleExpirations.push(
        // todo: we can make it faster by manually collecting expirations from signatures?
        ...(await Promise.all(key.subkeys.map(async subkey => OpenPGPKey.getExpirationAsDateOrUndefined(await subkey.getExpirationTime()))))
          .filter(Boolean)
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          .map(expirationTime => expirationTime!.getTime())
          .filter(expiration => !primaryKeyExpiration || expiration < primaryKeyExpiration)
      );
      if (primaryKeyExpiration) {
        possibleExpirations.push(primaryKeyExpiration);
      }
    }
    let encryptionKeyIgnoringExpiration: OpenPGP.Key | OpenPGP.Subkey | undefined;
    let expiration: number | undefined;
    if (encryptionKey) {
      encryptionKeyIgnoringExpiration = encryptionKey;
      // find the key with latest expiration by trying dates of current key's expiration
      while (true) {
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        expiration = OpenPGPKey.getExpirationAsDateOrUndefined(await encryptionKeyIgnoringExpiration!.getExpirationTime())?.getTime();
        if (!expiration || (primaryKeyExpiration && expiration >= primaryKeyExpiration)) break; // found a never-expiring key or a key with expiration beyond primary
        const nextCandidateKey: OpenPGP.Key | OpenPGP.Subkey | undefined = await Catch.undefinedOnException(
          key.getEncryptionKey(undefined, new Date(expiration))
        );
        if (!nextCandidateKey) break;
        encryptionKeyIgnoringExpiration = nextCandidateKey;
      }
    } else {
      encryptionKeyIgnoringExpiration = await OpenPGPKey.getKeyByDate(
        (date: Date | null | undefined) => key.getEncryptionKey(undefined, date),
        possibleExpirations
      );
      if (encryptionKeyIgnoringExpiration) {
        expiration = OpenPGPKey.getExpirationAsDateOrUndefined(await encryptionKeyIgnoringExpiration.getExpirationTime())?.getTime();
      }
    }
    if (primaryKeyExpiration && (!expiration || expiration > primaryKeyExpiration)) {
      expiration = primaryKeyExpiration;
    }
    let signingKeyIgnoringExpiration: OpenPGP.Key | OpenPGP.Subkey | undefined;
    if (signingKey) {
      signingKeyIgnoringExpiration = signingKey; // no need to search for signing expiration
    } else {
      signingKeyIgnoringExpiration = await OpenPGPKey.getKeyByDate((date: Date | null | undefined) => key.getSigningKey(undefined, date), possibleExpirations);
    }
    return { encryptionKey, encryptionKeyIgnoringExpiration, expiration, signingKey, signingKeyIgnoringExpiration };
  };

  private static getKeyByDate = async (extractor: (date?: Date | null) => Promise<OpenPGP.Key | OpenPGP.Subkey>, dates: number[]) => {
    if (dates.length > 0) {
      for (const date of Value.arr.unique(dates).sort((a, b) => b - a)) {
        const key = await Catch.undefinedOnException(extractor(new Date(date - 1000)));
        if (key) {
          return key;
        }
      }
    } else {
      // `null` value for the date parameter means to ignore it
      return await Catch.undefinedOnException(extractor(null)); // eslint-disable-line no-null/no-null
    }
    return undefined;
  };
  private static arePrivateParamsMissing = (packet: OpenPGP.BasePublicKeyPacket): boolean => {
    // detection of missing private params to solve #2887
    if (!OpenPGPKey.paramCountByAlgo) {
      OpenPGPKey.paramCountByAlgo = {
        // Adjusted for the OpenPGP.js v5.
        // See parsePublicKeyParams() and parsePrivateKeyParams()
        // in the openpgp.js source code for details.
        [opgp.enums.publicKey.rsaEncrypt]: { pub: 2, priv: 4 }, // (n, e), (d, p, q, u)
        [opgp.enums.publicKey.rsaEncryptSign]: { pub: 2, priv: 4 }, // (n, e), (d, p, q, u)
        [opgp.enums.publicKey.rsaSign]: { pub: 2, priv: 4 }, // (n, e), (d, p, q, u)
        [opgp.enums.publicKey.dsa]: { pub: 4, priv: 1 }, // (p, q, g, y), (x)
        [opgp.enums.publicKey.elgamal]: { pub: 3, priv: 1 }, // (p, g, y), (x)
        [opgp.enums.publicKey.ecdsa]: { pub: 2, priv: 1 }, // (oid, Q), (d)
        [opgp.enums.publicKey.ecdh]: { pub: 2, priv: 1 }, // (oid, Q, kdfParams), (d)
        [opgp.enums.publicKey.eddsa]: { pub: 2, priv: 1 }, // (oid, Q), (seed)
      };
    }
    return (
      !('privateParams' in packet) ||
      (packet.algorithm &&
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        !(packet as any).isEncrypted && // isDecrypted() returns false when isEncrypted is null
        (!packet.privateParams || OpenPGPKey.paramCountByAlgo[packet.algorithm].priv > Object.keys(packet.privateParams).length))
    );
  };

  private static testEncryptDecrypt = async (key: OpenPGP.Key): Promise<string[]> => {
    const output: string[] = [];
    try {
      const encryptedMsg = await opgp.encrypt({
        message: await opgp.createMessage({ text: OpenPGPKey.encryptionText }),
        encryptionKeys: key.toPublic(),
        format: 'armored',
      });
      output.push(`Encryption with key was successful`);
      if (key.isPrivate() && OpenPGPKey.isFullyDecrypted(key)) {
        const decryptedMsg = await opgp.decrypt({
          message: await opgp.readMessage({ armoredMessage: encryptedMsg }),
          decryptionKeys: key,
        });
        output.push(`Decryption with key ${decryptedMsg.data === OpenPGPKey.encryptionText ? 'succeeded' : 'failed!'}`);
      } else {
        output.push(
          `Skipping decryption because isPrivate:${key.isPrivate()} isFullyDecrypted:${key.isPrivate() ? OpenPGPKey.isFullyDecrypted(key) : 'unknown'}`
        );
      }
    } catch (err) {
      output.push(`Got error performing encryption/decryption test: ${err}`);
    }
    return output;
  };

  private static testSignVerify = async (key: OpenPGP.PrivateKey): Promise<string> => {
    const output: string[] = [];
    try {
      if (!OpenPGPKey.isFullyDecrypted(key)) {
        return 'skipped, not fully decrypted';
      }
      const signedMessage = await (await opgp.createMessage({ text: OpenPGPKey.encryptionText })).sign([key]);
      output.push('sign msg ok');
      const verifyResult = await OpenPGPKey.verify(signedMessage, [{ pubkey: await OpenPGPKey.convertExternalLibraryObjToKey(key), revoked: false }]);
      // eslint-disable-next-line no-null/no-null
      if (verifyResult.error !== null && typeof verifyResult.error !== 'undefined') {
        output.push(`verify failed: ${verifyResult.error}`);
      } else {
        if (verifyResult.match && verifyResult.signerLongids.includes(OpenPGPKey.bytesToLongid(key.getKeyID().bytes))) {
          output.push('verify ok');
        } else {
          output.push(`verify mismatch: match[${verifyResult.match}]`);
        }
      }
    } catch (e) {
      output.push(`Exception: ${String(e)}`);
    }
    return output.join('|');
  };

  private static formatDate = (date: Date | number | null, expiresInSecondsFromDate?: number | null) => {
    if (date === Infinity) {
      return '-';
    }
    if (typeof date === 'number') {
      return `UNEXPECTED FORMAT: ${date}`;
    }
    // eslint-disable-next-line no-null/no-null
    if (date === null) {
      return `null (not applicable)`;
    }
    if (typeof expiresInSecondsFromDate === 'undefined') {
      return `${date.getTime() / 1000} or ${date.toISOString()}`;
    }
    // eslint-disable-next-line no-null/no-null
    if (expiresInSecondsFromDate === null) {
      return '-'; // no expiration
    }
    const expDate = new Date(date.getTime() + expiresInSecondsFromDate * 1000);
    return `${date.getTime() / 1000} + ${expiresInSecondsFromDate} seconds, which is: ${expDate.getTime() / 1000} or ${expDate.toISOString()}`;
  };

  private static decryptPrivateKey = async (
    prv: OpenPGP.PrivateKey,
    passphrase: string,
    optionalKeyid?: OpenPGP.KeyID,
    optionalBehaviorFlag?: 'OK-IF-ALREADY-DECRYPTED'
  ) => {
    const chosenPrvPackets = prv
      .getKeys(optionalKeyid)
      .map(k => k.keyPacket)
      .filter(OpenPGPKey.isPacketPrivate) as PrvPacket[];
    if (!chosenPrvPackets.length) {
      throw new Error(
        `No private key packets selected of ${
          prv
            .getKeys()
            .map(k => k.keyPacket)
            .filter(OpenPGPKey.isPacketPrivate).length
        } prv packets available`
      );
    }
    for (const prvPacket of chosenPrvPackets) {
      if (prvPacket.isDecrypted()) {
        if (optionalBehaviorFlag === 'OK-IF-ALREADY-DECRYPTED') {
          continue;
        } else {
          throw new Error('Decryption failed - key packet was already decrypted');
        }
      }
      try {
        await prvPacket.decrypt(passphrase); // throws on password mismatch
        await prvPacket.validate(); // throws
      } catch (e) {
        if (e instanceof Error && e.message.toLowerCase().includes('incorrect key passphrase')) {
          return false;
        }
        throw e;
      }
    }
    return true;
  };

  private static getPrvPackets = (k: OpenPGP.Key): PrvPacket[] => {
    if (!k.isPrivate()) {
      throw new Error('Cannot check encryption status of secret keys in a Public Key');
    }
    const prvPackets = k
      .getKeys()
      .map(k => k.keyPacket)
      .filter(OpenPGPKey.isPacketPrivate) as PrvPacket[];
    if (!prvPackets.length) {
      throw new Error('This key has no private packets. Is it a Private Key?');
    }
    const nonDummyPrvPackets = prvPackets.filter(p => !p.isDummy());
    if (!nonDummyPrvPackets.length) {
      throw new Error('This key only has a gnu-dummy private packet, with no actual secret keys.');
    }
    return nonDummyPrvPackets;
  };
}
