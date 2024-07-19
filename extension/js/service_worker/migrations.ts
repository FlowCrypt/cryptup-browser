/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { storageGetAll, storageRemove } from '../common/browser/chrome.js';
import { KeyInfoWithIdentity, KeyUtil } from '../common/core/crypto/key.js';
import { SmimeKey } from '../common/core/crypto/smime/smime-key.js';
import { Str } from '../common/core/common.js';
import { ContactStore, Email, Pubkey } from '../common/platform/store/contact-store.js';
import { GlobalStore, LocalDraft } from '../common/platform/store/global-store.js';
import { KeyStore } from '../common/platform/store/key-store.js';

/* eslint-disable @typescript-eslint/naming-convention */
// contact entity prior to version 4
type ContactV3 = {
  email: string;
  name: string | null;
  pubkey: { rawArmored: string; raw: string } | string | null;
  has_pgp: 0 | 1;
  fingerprint: string | null;
  last_use: number | null;
  pubkey_last_check: number | null;
  expiresOn: number | null;
};
/* eslint-enable @typescript-eslint/naming-convention */

type PubkeyMigrationData = {
  emailsToUpdate: { [email: string]: Email };
  pubkeysToDelete: string[];
  pubkeysToSave: Pubkey[];
};

const addKeyInfoFingerprints = async () => {
  for (const acctEmail of await GlobalStore.acctEmailsGet()) {
    const originalKis = await KeyStore.get(acctEmail);
    const updated: KeyInfoWithIdentity[] = [];
    for (const originalKi of originalKis) {
      updated.push(await KeyUtil.keyInfoObj(await KeyUtil.parse(originalKi.private)));
    }
    await KeyStore.set(acctEmail, updated);
  }
};

export const migrateGlobal = async () => {
  const globalStore = await GlobalStore.get(['key_info_store_fingerprints_added', 'local_drafts']);
  if (!globalStore.key_info_store_fingerprints_added) {
    console.info('migrating KeyStorage to add fingerprints and emails of each key...');
    await addKeyInfoFingerprints();
    // eslint-disable-next-line @typescript-eslint/naming-convention
    await GlobalStore.set({ key_info_store_fingerprints_added: true });
    console.info('done migrating');
  }
  // migrate local drafts (https://github.com/FlowCrypt/flowcrypt-browser/pull/3986)
  if (typeof globalStore.local_drafts === 'undefined') {
    console.info('migrating local drafts in old format...');
    globalStore.local_drafts = {};
    const storageLocal = await storageGetAll('local');
    const oldDrafts = [];
    for (const key of Object.keys(storageLocal)) {
      if (key.startsWith('local-draft-')) {
        console.info(`migrating local draft ${key}`);
        globalStore.local_drafts[key] = storageLocal[key] as LocalDraft;
        oldDrafts.push(key);
      }
    }
    if (oldDrafts.length) {
      // eslint-disable-next-line @typescript-eslint/naming-convention
      await GlobalStore.set({ local_drafts: globalStore.local_drafts });
      await storageRemove('local', oldDrafts);
    }
  }
  // migrate local compose draft (https://github.com/FlowCrypt/flowcrypt-browser/pull/4026)
  if (globalStore.local_drafts['local-draft-']) {
    console.info('migrating local compose draft...');
    const newComposeDraftId = `local-draft-compose-${Str.sloppyRandom(10)}`;
    console.info(`new local compose draft id: ${newComposeDraftId}`);
    globalStore.local_drafts[newComposeDraftId] = globalStore.local_drafts['local-draft-'];
    globalStore.local_drafts[newComposeDraftId].timestamp = new Date().getTime();
    delete globalStore.local_drafts['local-draft-'];
    // eslint-disable-next-line @typescript-eslint/naming-convention
    await GlobalStore.set({ local_drafts: globalStore.local_drafts });
  }
};

const processSmimeKey = (pubkey: Pubkey, tx: IDBTransaction, data: PubkeyMigrationData, next: () => void) => {
  if (KeyUtil.getKeyFamily(pubkey.armoredKey) !== 'x509') {
    next();
    return;
  }
  const key = SmimeKey.parse(pubkey.armoredKey);
  const newPubkeyEntity = ContactStore.pubkeyObj(key, pubkey.lastCheck);
  data.pubkeysToDelete.push(pubkey.fingerprint);
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const req = tx.objectStore('emails').index('index_fingerprints').getAll(pubkey.fingerprint);
  ContactStore.setReqPipe(req, (emailEntities: Email[]) => {
    if (emailEntities.length) {
      data.pubkeysToSave.push(newPubkeyEntity);
    }
    for (const emailEntity of emailEntities) {
      const cachedEmail = data.emailsToUpdate[emailEntity.email];
      if (!cachedEmail) {
        data.emailsToUpdate[emailEntity.email] = emailEntity;
      }
      const entityToUpdate = cachedEmail ?? emailEntity;
      entityToUpdate.fingerprints = entityToUpdate.fingerprints.filter(fp => fp !== pubkey.fingerprint && fp !== newPubkeyEntity.fingerprint);
      entityToUpdate.fingerprints.push(newPubkeyEntity.fingerprint);
    }
    next();
  });
};

export const updateX509FingerprintsAndLongids = async (db: IDBDatabase): Promise<void> => {
  const globalStore = await GlobalStore.get(['contact_store_x509_fingerprints_and_longids_updated']);
  if (globalStore.contact_store_x509_fingerprints_and_longids_updated) {
    return;
  }
  console.info('updating ContactStorage to correct longids and fingerprints of X.509 certificates...');
  const tx = db.transaction(['emails', 'pubkeys'], 'readwrite');
  await new Promise((resolve, reject) => {
    ContactStore.setTxHandlers(tx, resolve, reject);
    const data: PubkeyMigrationData = { emailsToUpdate: {}, pubkeysToDelete: [], pubkeysToSave: [] };
    const search = tx.objectStore('pubkeys').openCursor();
    ContactStore.setReqPipe(search, (cursor: IDBCursorWithValue) => {
      if (!cursor) {
        // do updates
        for (const fp of data.pubkeysToDelete.filter(fp => !data.pubkeysToSave.some(x => x.fingerprint === fp))) {
          // console.log(`Deleting pubkey ${fp}`);
          tx.objectStore('pubkeys').delete(fp);
        }
        for (const pubkey of data.pubkeysToSave) {
          // console.log(`Updating pubkey ${pubkey.fingerprint}`);
          tx.objectStore('pubkeys').put(pubkey);
        }
        for (const email of Object.values(data.emailsToUpdate)) {
          // console.log(`Updating email ${email.email}`);
          tx.objectStore('emails').put(email);
        }
      } else {
        processSmimeKey(cursor.value as Pubkey, tx, data, () => {
          cursor.continue();
        });
      }
    });
  });
  // eslint-disable-next-line @typescript-eslint/naming-convention
  await GlobalStore.set({ contact_store_x509_fingerprints_and_longids_updated: true });
  console.info('done updating');
};

export const updateSearchables = async (db: IDBDatabase): Promise<void> => {
  const globalStore = await GlobalStore.get(['contact_store_searchable_pruned']);
  if (globalStore.contact_store_searchable_pruned) {
    return;
  }
  console.info('updating ContactStorage to re-generate searchable values...');
  const tx = db.transaction(['emails'], 'readwrite');
  await new Promise((resolve, reject) => {
    ContactStore.setTxHandlers(tx, resolve, reject);
    const emailsStore = tx.objectStore('emails');
    const search = emailsStore.openCursor();
    ContactStore.setReqPipe(search, (cursor: IDBCursorWithValue) => {
      if (cursor) {
        const email = cursor.value as Email;
        ContactStore.updateSearchable(email);
        cursor.update(email);
        cursor.continue();
      }
    });
  });
  // eslint-disable-next-line @typescript-eslint/naming-convention
  await GlobalStore.set({ contact_store_searchable_pruned: true });
  console.info('done updating');
};

export const updateOpgpRevocations = async (db: IDBDatabase): Promise<void> => {
  const globalStore = await GlobalStore.get(['contact_store_opgp_revoked_flags_updated']);
  if (globalStore.contact_store_opgp_revoked_flags_updated) {
    return;
  }
  console.info('updating ContactStorage to revoked flags of OpenPGP keys...');
  const tx = db.transaction(['pubkeys'], 'readonly');
  const pubkeys: Pubkey[] = await new Promise((resolve, reject) => {
    const search = tx.objectStore('pubkeys').getAll();
    ContactStore.setReqPipe(search, resolve, reject);
  });
  const revokedKeys = (
    await Promise.all(
      pubkeys.filter(entity => KeyUtil.getKeyFamily(entity.armoredKey) === 'openpgp').map(async entity => await KeyUtil.parse(entity.armoredKey))
    )
  ).filter(k => k.revoked);
  const txUpdate = db.transaction(['revocations'], 'readwrite');
  await new Promise((resolve, reject) => {
    ContactStore.setTxHandlers(txUpdate, resolve, reject);
    const revocationsStore = txUpdate.objectStore('revocations');
    for (const revokedKey of revokedKeys) {
      revocationsStore.put(ContactStore.revocationObj(revokedKey));
    }
  });
  // eslint-disable-next-line @typescript-eslint/naming-convention
  await GlobalStore.set({ contact_store_opgp_revoked_flags_updated: true });
  console.info('done updating');
};

export const moveContactsToEmailsAndPubkeys = async (db: IDBDatabase): Promise<void> => {
  if (!db.objectStoreNames.contains('contacts')) {
    return;
  }
  console.info('migrating contacts of ContactStore to emails and pubkeys...');
  const batchSize = 50;
  try {
    while (await moveContactsBatchToEmailsAndPubkeys(db, batchSize)) {
      console.info('proceeding to the next batch');
    }
    console.info('migrating contacts of ContactStore is complete');
  } catch (e) {
    console.error(`Error happened when converting contacts: ${e instanceof Error ? e.message : String(e)}`);
  }
};

const moveContactsBatchToEmailsAndPubkeys = async (db: IDBDatabase, count?: number | undefined): Promise<number> => {
  const entries: ContactV3[] = [];
  {
    const tx = db.transaction(['contacts'], 'readonly');
    await new Promise((resolve, reject) => {
      ContactStore.setTxHandlers(tx, resolve, reject);
      const contacts = tx.objectStore('contacts');
      const search = contacts.getAll(undefined, count);
      ContactStore.setReqPipe(search, (result: ContactV3[]) => {
        entries.push(...result);
      });
    });
    if (!entries.length) {
      return 0;
    }
  }
  console.info(`Processing a batch of ${entries.length}.`);
  // transform
  const converted = await Promise.all(
    entries.map(async entry => {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const armoredPubkey = entry.pubkey && typeof entry.pubkey === 'object' ? (entry.pubkey.rawArmored ?? entry.pubkey.raw) : entry.pubkey!;
      // parse again to re-calculate expiration-related fields etc.
      const pubkey = armoredPubkey ? await KeyUtil.parse(armoredPubkey) : undefined;
      return {
        email: entry.email,
        update: {
          name: entry.name,
          pubkey,
          lastUse: entry.last_use,
          pubkeyLastCheck: pubkey ? entry.pubkey_last_check : undefined,
        },
      };
    })
  );
  {
    const tx = db.transaction(['contacts', 'emails', 'pubkeys', 'revocations'], 'readwrite');
    await new Promise((resolve, reject) => {
      ContactStore.setTxHandlers(tx, resolve, reject);
      for (const item of converted) {
        ContactStore.updateTx(tx, item.email, item.update);
        tx.objectStore('contacts').delete(item.email);
      }
    });
  }
  return converted.length;
};
