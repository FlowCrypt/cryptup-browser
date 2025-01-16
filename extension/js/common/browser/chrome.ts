/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { Catch } from '../platform/catch.js';
import { ContentScriptWindow } from './browser-window.js';
import { Env } from './env.js';
import { Ui } from './ui.js';
import { Url, Dict } from '../core/common.js';
import { AbstractStore } from '../platform/store/abstract-store.js';

type ChromeStorageType = 'local' | 'session';

const handleFatalErr = async (reason: 'storage_undefined', error: Error) => {
  try {
    if (await Env.isBackgroundPage()) {
      throw error;
    } else if (Env.isContentScript()) {
      console.error('Incomplete extension environment in content script', error);
    } else if (!chrome.runtime) {
      console.error('Chrome.runtime missing, cannot continue', error);
    } else {
      // extension pages

      window.location.href = chrome.runtime.getURL(Url.create(`chrome/settings/fatal.htm`, { reason, stack: error.stack }));
    }
  } catch (e) {
    if (e && e instanceof Error && e.message === 'Extension context invalidated.') {
      console.info(`FlowCrypt cannot handle fatal error because: Extension context invalidated. Destroying.`, error);
      (window as unknown as ContentScriptWindow).destroy();
    } else {
      throw e;
    }
  }
};

export const windowsCreate = async (q: chrome.windows.CreateData): Promise<chrome.windows.Window | undefined> => {
  return await new Promise(resolve => {
    if (typeof chrome.windows !== 'undefined') {
      chrome.windows.create(q, resolve);
    } else {
      Ui.modal.error('Your platform is not supported: browser does not support extension windows').catch(Catch.reportErr);
    }
  });
};

export const storageGet = async (storageType: ChromeStorageType, keys: string[]): Promise<Dict<unknown>> => {
  return await new Promise((resolve, reject) => {
    if (typeof chrome.storage === 'undefined') {
      void handleFatalErr('storage_undefined', new Error('storage is undefined'));
    } else {
      const storage = chrome.storage[storageType];
      storage.get(keys, result => {
        if (typeof result !== 'undefined') {
          resolve(result);
        } else if (chrome.runtime.lastError) {
          reject(AbstractStore.errCategorize(chrome.runtime.lastError));
        } else {
          reject(new Error(`storageGet(${storageType}, ${keys.join(',')}) produced undefined result without an error`));
        }
      });
    }
  });
};

export const storageGetAll = async (storageType: ChromeStorageType): Promise<{ [key: string]: unknown }> => {
  return await new Promise(resolve => {
    if (typeof chrome.storage === 'undefined') {
      void handleFatalErr('storage_undefined', new Error('storage is undefined'));
    } else {
      const storage = chrome.storage[storageType];
      void storage.get(resolve);
    }
  });
};

export const storageSet = async (storageType: ChromeStorageType, values: Dict<unknown>): Promise<void> => {
  return await new Promise(resolve => {
    if (typeof chrome.storage === 'undefined') {
      void handleFatalErr('storage_undefined', new Error('storage is undefined'));
    } else {
      const storage = chrome.storage[storageType];
      storage.set(values, resolve);
    }
  });
};

export const storageRemove = async (storageType: ChromeStorageType, keys: string[]): Promise<void> => {
  return await new Promise(resolve => {
    if (typeof chrome.storage === 'undefined') {
      void handleFatalErr('storage_undefined', new Error('storage is undefined'));
    } else {
      const storage = chrome.storage[storageType];
      storage.remove(keys, resolve);
    }
  });
};
