/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

'use strict';

import { base64decode, base64encode } from '../platform/util.js';
import { Xss } from '../platform/xss.js';
import { Buf } from './buf.js';

export type Dict<T> = { [key: string]: T };
export type UrlParam = string | number | null | undefined | boolean | string[];
export type UrlParams = Dict<UrlParam>;
export type PromiseCancellation = { cancel: boolean };
export type EmailParts = { email: string; name?: string };

export const CID_PATTERN = /^cid:(.+)/;

export const HTTP_STATUS_TEXTS: { [code: number]: string } = {
  [100]: 'Continue',
  [101]: 'Switching Protocols',
  [102]: 'Processing',
  [103]: 'Early Hints',
  [200]: 'OK',
  [201]: 'Created',
  [202]: 'Accepted',
  [203]: 'Non-Authoritative Information',
  [204]: 'No Content',
  [205]: 'Reset Content',
  [206]: 'Partial Content',
  [207]: 'Multi-Status',
  [208]: 'Already Reported',
  [226]: 'IM Used',
  [300]: 'Multiple Choices',
  [301]: 'Moved Permanently',
  [302]: 'Found',
  [303]: 'See Other',
  [304]: 'Not Modified',
  [305]: 'Use Proxy',
  [306]: 'Switch Proxy',
  [307]: 'Temporary Redirect',
  [308]: 'Permanent Redirect',
  [400]: 'Bad Request',
  [401]: 'Unauthorized',
  [402]: 'Payment Required',
  [403]: 'Forbidden',
  [404]: 'Not Found',
  [405]: 'Method Not Allowed',
  [406]: 'Not Acceptable',
  [407]: 'Proxy Authentication Required',
  [408]: 'Request Timeout',
  [409]: 'Conflict',
  [410]: 'Gone',
  [411]: 'Length Required',
  [412]: 'Precondition Failed',
  [413]: 'Payload Too Large',
  [414]: 'URI Too Long',
  [415]: 'Unsupported Media Type',
  [416]: 'Range Not Satisfiable',
  [417]: 'Expectation Failed',
  [418]: "I'm a teapot",
  [421]: 'Misdirected Request',
  [422]: 'Unprocessable Entity',
  [423]: 'Locked',
  [424]: 'Failed Dependency',
  [425]: 'Too Early',
  [426]: 'Upgrade Required',
  [428]: 'Precondition Required',
  [429]: 'Too Many Requests',
  [431]: 'Request Header Fields Too Large',
  [451]: 'Unavailable For Legal Reasons',
  [500]: 'Internal Server Error',
  [501]: 'Not Implemented',
  [502]: 'Bad Gateway',
  [503]: 'Service Unavailable',
  [504]: 'Gateway Timeout',
  [505]: 'HTTP Version Not Supported',
  [506]: 'Variant Also Negotiates',
  [507]: 'Insufficient Storage',
  [508]: 'Loop Detected',
  [510]: 'Not Extended',
  [511]: 'Network Authentication Required',
};

export class Str {
  // ranges are taken from https://stackoverflow.com/a/14824756
  // with the '\u0300' -> '\u0370' modification, because from '\u0300' to '\u0370' there are only punctuation marks
  // see https://www.utf8-chartable.de/unicode-utf8-table.pl
  public static readonly ltrChars = 'A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02B8\u0370-\u0590\u0800-\u1FFF\u2C00-\uFB1C\uFDFE-\uFE6F\uFEFD-\uFFFF';
  public static readonly rtlChars = '\u0591-\u07FF\uFB1D-\uFDFD\uFE70-\uFEFC';

  public static parseEmail = (full: string, flag: 'VALIDATE' | 'DO-NOT-VALIDATE' = 'VALIDATE') => {
    let email: string | undefined;
    let name: string | undefined;
    if (full.includes('<') && full.includes('>')) {
      email = full
        .substring(full.indexOf('<') + 1, full.indexOf('>'))
        .replace(/["']/g, '')
        .trim()
        .toLowerCase();
      name = full.substring(0, full.indexOf('<')).replace(/["']/g, '').trim();
    } else {
      email = full.replace(/["']/g, '').trim().toLowerCase();
    }
    if (flag === 'VALIDATE' && !Str.isEmailValid(email)) {
      email = undefined;
    }
    return { email, name, full };
  };

  public static getDomainFromEmailAddress = (emailAddr: string) => {
    // todo: parseEmail()?
    return emailAddr.toLowerCase().split('@')[1];
  };

  public static rmSpecialCharsKeepUtf = (str: string, mode: 'ALLOW-SOME' | 'ALLOW-NONE'): string => {
    // not a whitelist because we still want utf chars
    str = str.replace(/[@&#`();:'",<>\{\}\[\]\\\/\n\t\r]/gi, '');
    if (mode === 'ALLOW-SOME') {
      return str;
    }
    return str.replace(/[.~!$%^*=?]/gi, '');
  };

  public static formatEmailWithOptionalName = (emailParts: EmailParts): string => {
    return Str.formatEmailWithOptionalNameEx(emailParts);
  };

  public static formatEmailList = (list: EmailParts[], forceBrackets?: boolean): string => {
    return list.map(x => Str.formatEmailWithOptionalNameEx(x, forceBrackets)).join(', ');
  };

  public static prettyPrint = (obj: unknown) => {
    return typeof obj === 'object' ? JSON.stringify(obj, undefined, 2).replace(/ /g, '&nbsp;').replace(/\n/g, '<br />') : String(obj);
  };

  public static normalizeSpaces = (str: string) => {
    return str.replace(RegExp(String.fromCharCode(160), 'g'), String.fromCharCode(32));
  };

  public static normalizeDashes = (str: string) => {
    return str.replace(/^—–|—–$/gm, '-----');
  };

  public static normalize = (str: string) => {
    return Str.normalizeSpaces(Str.normalizeDashes(str));
  };

  public static spaced = (longidOrFingerprint: string) => {
    return longidOrFingerprint.replace(/(.{4})/g, '$1 ').trim();
  };

  public static truncate = (text: string, length: number): string => {
    return text.length <= length ? text : text.substring(0, length) + '...';
  };

  public static isEmailValid = (email: string | undefined) => {
    if (!email) {
      return false;
    }
    if (email.includes(' ')) {
      return false;
    }
    email = email.replace(/\:8001$/, ''); // for MOCK tests, todo: remove from production
    // `localhost` is a valid top-level domain for an email address, otherwise we require a second-level domain to be present
    return /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|localhost|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(
      email
    );
  };

  public static is7bit = (content: string | Uint8Array): boolean => {
    for (let i = 0; i < content.length; i++) {
      const code = typeof content === 'string' ? content.charCodeAt(i) : (content[i] ?? 0);
      if (!(code >= 0 && code <= 127)) {
        return false;
      }
    }
    return true;
  };

  public static with = (data: Uint8Array | string): string => {
    return typeof data === 'string' ? data : Buf.with(data).toUtfStr();
  };

  public static monthName = (monthIndex: number) => {
    return ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'][monthIndex];
  };

  public static sloppyRandom = (length = 5) => {
    let id = '';
    const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    for (let i = 0; i < length; i++) {
      id += possible.charAt(Math.floor(Math.random() * possible.length));
    }
    return id;
  };

  // splits the string to matches,
  // each match is extended till the end of the original string
  public static splitExtended = (str: string, regexp: RegExp): string[] => {
    const result: string[] = [];
    while (true) {
      const match = regexp.exec(str);
      // eslint-disable-next-line no-null/no-null
      if (match === null) {
        break;
      }
      result.push(str.substring(match.index));
    }
    return result;
  };

  // splits the string to alphanumeric chunks,
  // each chunk is extended till the end of the original string
  public static splitAlphanumericExtended = (str: string): string[] => {
    return Str.splitExtended(str, /[a-z0-9]+/g);
  };

  public static regexEscape = (toBeUsedInRegex: string) => {
    return toBeUsedInRegex.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  };

  public static escapeTextAsRenderableHtml = (text: string) => {
    const rtlRegexp = new RegExp(`^([${Str.rtlChars}].*)$`, 'gm');
    return Xss.escape(text)
      .replace(rtlRegexp, '<div dir="rtl">$1</div>') // RTL lines
      .replace(/\n/g, '<br>\n') // leave newline so that following replaces work
      .replace(/^ +/gm, spaces => spaces.replace(/ /g, '&nbsp;'))
      .replace(/\n/g, ''); // strip newlines, already have <br>
  };

  public static htmlAttrEncode = (values: Dict<unknown>): string => {
    return Str.base64urlUtfEncode(JSON.stringify(values));
  };

  public static htmlAttrDecode = (encoded: string): unknown => {
    try {
      return JSON.parse(Str.base64urlUtfDecode(encoded));
    } catch (e) {
      return undefined;
    }
  };

  public static capitalize = (string: string): string => {
    return string
      .trim()
      .split(' ')
      .map(s => s.charAt(0).toUpperCase() + s.slice(1))
      .join(' ');
  };

  public static pluralize = (count: number, noun: string, suffix = 's'): string => {
    return `${count} ${noun}${count > 1 ? suffix : ''}`;
  };

  public static toUtcTimestamp = (datetimeStr: string, asStr = false) => {
    return asStr ? String(Date.parse(datetimeStr)) : Date.parse(datetimeStr);
  };

  public static datetimeToDate = (date: string) => {
    return date.substr(0, 10).replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;');
  };

  public static fromDate = (date: Date) => {
    return date
      .toISOString()
      .replace(/T/, ' ')
      .replace(/:[^:]+$/, '');
  };

  public static mostlyRTL = (string: string): boolean => {
    const rtlCount = string.match(new RegExp('[' + Str.rtlChars + ']', 'g'))?.length || 0;
    const lrtCount = string.match(new RegExp('[' + Str.ltrChars + ']', 'g'))?.length || 0;
    return rtlCount > lrtCount;
  };

  // the regex has the most votes https://stackoverflow.com/a/4250408
  public static getFilenameWithoutExtension = (filename: string): string => {
    return filename.replace(/\.[^/.]+$/, '');
  };

  public static stripPgpOrGpgExtensionIfPresent = (filename: string) => {
    return filename.replace(/\.(pgp|gpg)$/i, '');
  };
  private static formatEmailWithOptionalNameEx = ({ email, name }: EmailParts, forceBrackets?: boolean): string => {
    if (name) {
      return `${Str.rmSpecialCharsKeepUtf(name, 'ALLOW-SOME')} <${email}>`;
    }
    return forceBrackets ? `<${email}>` : email;
  };

  private static base64urlUtfEncode = (str: string) => {
    // https://stackoverflow.com/questions/30106476/using-javascripts-atob-to-decode-base64-doesnt-properly-decode-utf-8-strings
    if (typeof str === 'undefined') {
      return str;
    }
    return base64encode(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (match, p1) => String.fromCharCode(parseInt(String(p1), 16))))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  };

  private static base64urlUtfDecode = (str: string) => {
    // https://stackoverflow.com/questions/30106476/using-javascripts-atob-to-decode-base64-doesnt-properly-decode-utf-8-strings
    if (typeof str === 'undefined') {
      return str;
    }

    return decodeURIComponent(
      Array.prototype.map
        .call(base64decode(str.replace(/-/g, '+').replace(/_/g, '/')), (c: string) => {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        })
        .join('')
    );
  };
}

export class DateUtility {
  public static asNumber = (date: number | null | undefined): number | null => {
    if (typeof date === 'number') {
      return date;
    } else if (!date) {
      return null; // eslint-disable-line no-null/no-null
    } else {
      return new Date(date).getTime();
    }
  };
}

export class Value {
  public static arr = {
    unique: <T>(array: T[]): T[] => {
      const unique: T[] = [];
      for (const v of array) {
        if (!unique.includes(v)) {
          unique.push(v);
        }
      }
      return unique;
    },
    withoutKey: <T>(array: T[], i: number) => array.splice(0, i).concat(array.splice(i + 1, array.length)),
    withoutVal: <T>(array: T[], withoutVal: T) => {
      const result: T[] = [];
      for (const value of array) {
        if (value !== withoutVal) {
          result.push(value);
        }
      }
      return result;
    },
    contains: <T>(arr: T[] | string, value: T): boolean => Boolean(arr && typeof arr.indexOf === 'function' && (arr as unknown[]).includes(value)),
    intersection: <T>(array1: T[], array2: T[]): T[] => array1.filter(value => array2.includes(value)),
    hasIntersection: <T>(array1: T[], array2: T[]): boolean => array1.some(value => array2.includes(value)),
    sum: (arr: number[]) => arr.reduce((a, b) => a + b, 0),
    average: (arr: number[]) => Value.arr.sum(arr) / arr.length,
    zeroes: (length: number): number[] => new Array(length).map(() => 0),
  };

  public static obj = {
    keyByValue: <T>(obj: Dict<T>, v: T) => {
      for (const k of Object.keys(obj)) {
        if (obj[k] === v) {
          return k;
        }
      }
      return undefined;
    },
  };

  public static int = {
    lousyRandom: (minVal: number, maxVal: number) => minVal + Math.round(Math.random() * (maxVal - minVal)),
    getFutureTimestampInMonths: (monthsToAdd: number) => new Date().getTime() + 1000 * 3600 * 24 * 30 * monthsToAdd,
    hoursAsMiliseconds: (h: number) => h * 1000 * 60 * 60,
  };

  public static getPercentage = (percent: number | undefined, loaded: number, total: number, expectedTransferSize: number) => {
    if (typeof percent === 'undefined') {
      if (total || expectedTransferSize) {
        percent = Math.round((loaded / (total || expectedTransferSize)) * 100);
      }
    }
    return percent;
  };

  public static noop = (): void => undefined;
}

export class Url {
  /* eslint-disable @typescript-eslint/naming-convention */
  private static URL_PARAM_DICT: Dict<boolean | null> = {
    ___cu_true___: true,
    ___cu_false___: false,
    ___cu_null___: null, // eslint-disable-line no-null/no-null
  };

  /**
   * will convert result to desired format: camelCase or snake_case, based on what was supplied in expectedKeys
   * todo - the camelCase or snake_case functionality can now be removed
   */
  public static parse = (expectedKeys: string[], parseThisUrl?: string) => {
    const url = parseThisUrl || window.location.search.replace('?', '');

    const valuePairs = url.split('?').pop()?.split('&') ?? []; // str.split('?') string[].length will always be >= 1
    const rawParams = new Map<string, string>();
    const rawParamNameDict = new Map<string, string>();
    for (const valuePair of valuePairs) {
      const pair = valuePair.split('=');
      rawParams.set(pair[0], pair[1]);
      Url.fillPossibleUrlParamNameVariations(pair[0], rawParamNameDict);
    }
    const processedParams: UrlParams = {};
    for (const expectedKey of expectedKeys) {
      processedParams[expectedKey] = Url.findAndProcessUrlParam(expectedKey, rawParamNameDict, rawParams);
    }
    return processedParams;
  };

  public static create = (link: string, params: UrlParams, transform = true) => {
    for (const key of Object.keys(params)) {
      const value = params[key];
      if (typeof value !== 'undefined') {
        const transformed = transform ? Value.obj.keyByValue(Url.URL_PARAM_DICT, value) : undefined;
        link +=
          (link.includes('?') ? '&' : '?') +
          encodeURIComponent(key) +
          '=' +
          encodeURIComponent(String(typeof transformed !== 'undefined' ? transformed : value));
      }
    }
    return link;
  };

  public static removeParamsFromUrl = (url: string, paramsToDelete: string[]) => {
    const urlParts = url.split('?');
    if (!urlParts[1]) {
      // Nothing to remove
      return url;
    }
    let queryParams = urlParts[1];
    queryParams = queryParams.endsWith('#') ? queryParams.slice(0, -1) : queryParams;
    const params = new URLSearchParams(queryParams);
    for (const p of paramsToDelete) {
      params.delete(p);
    }
    return `${urlParts[0]}?${params.toString()}`;
  };

  public static removeTrailingSlash = (url: string) => {
    return url.replace(/\/$/, '');
  };

  public static replaceUrlParam = (url: string, key: string, value: string) => {
    const regex = new RegExp(`([?|&]${key}=).*?(&|$)`, 'i');
    return url.replace(regex, '$1' + value + '$2');
  };

  private static snakeCaseToCamelCase = (s: string) => {
    return s.replace(/_[a-z]/g, boundary => boundary[1].toUpperCase());
  };

  private static camelCaseToSnakeCase = (s: string) => {
    return s.replace(/[a-z][A-Z]/g, boundary => `${boundary[0]}_${boundary[1].toLowerCase()}`);
  };

  private static findAndProcessUrlParam = (expectedParamName: string, rawParamNameDict: Map<string, string>, rawParams: Map<string, string>): UrlParam => {
    const paramName = rawParamNameDict.get(expectedParamName);
    if (typeof paramName === 'undefined') {
      return undefined; // param name not found in param name dict
    }
    const rawValue = rawParams.get(paramName);
    if (typeof rawValue === 'undefined') {
      return undefined; // original param name not found in raw params
    }
    if (typeof Url.URL_PARAM_DICT[rawValue] !== 'undefined') {
      return Url.URL_PARAM_DICT[rawValue]; // raw value was converted using a value dict to get proper: true, false, undefined, null
    }
    return decodeURIComponent(rawValue);
  };

  private static fillPossibleUrlParamNameVariations = (urlParamName: string, rawParamNameDict: Map<string, string>) => {
    rawParamNameDict.set(urlParamName, urlParamName);
    rawParamNameDict.set(Url.snakeCaseToCamelCase(urlParamName), urlParamName);
    rawParamNameDict.set(Url.camelCaseToSnakeCase(urlParamName), urlParamName);
    const shortened = urlParamName.replace('account', 'acct').replace('message', 'msg');
    rawParamNameDict.set(Url.snakeCaseToCamelCase(shortened), urlParamName);
    rawParamNameDict.set(Url.camelCaseToSnakeCase(shortened), urlParamName);
  };
}

export const emailKeyIndex = (scope: string, key: string): string => {
  return `${scope.replace(/[^A-Za-z0-9]+/g, '').toLowerCase()}_${key}`;
};

export const asyncSome = async <T>(arr: T[], predicate: (e: T) => Promise<boolean>) => {
  for (const e of arr) {
    if (await predicate(e)) return true;
  }
  return false;
};

export const asyncFilter = async <T>(arr: T[], predicate: (e: T) => Promise<boolean>) => {
  return (
    await Promise.all(
      arr.map(async e => {
        return { e, flag: await predicate(e) };
      })
    )
  )
    .filter(o => o.flag)
    .map(o => o.e);
};

export const stringTuple = <T extends string[]>(...data: T): T => {
  return data;
};

export const checkValidURL = (url: string): boolean => {
  const pattern = /(http|https):\/\/([a-z0-9-]+((\.[a-z0-9-]+)+)?)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@\-\/]))?/;
  return pattern.test(url);
};

/**
 * Executes multiple promises concurrently with a limit to the number of promises running simultaneously.
 * Resolves when all promises are resolved or rejects when any promise is rejected.
 *
 * @param concurrency - The maximum number of promises to run at the same time.
 * @param tasks - An array of functions that return promises.
 * @returns A Promise that resolves to an array of the resolved values of the input promises.
 */
export const promiseAllWithLimit = async <V>(concurrency: number, tasks: (() => Promise<V>)[]): Promise<V[]> => {
  let results: V[] = [];
  while (tasks.length) {
    const currentTasks = tasks.splice(0, concurrency).map(task => task());
    results = results.concat(await Promise.all(currentTasks));
  }
  return results;
};
