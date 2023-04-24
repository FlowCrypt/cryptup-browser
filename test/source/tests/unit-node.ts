/* ©️ 2016 - present FlowCrypt a.s. Limitations apply. Contact human@flowcrypt.com */

import test from 'ava';

import { MsgBlock } from '../core/msg-block';
import { MsgBlockParser } from '../core/msg-block-parser';
import { Config, TestVariant, Util } from '../util';
import { use, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised';
import { KeyUtil, KeyInfoWithIdentityAndOptionalPp, Key } from '../core/crypto/key';
import { UnreportableError } from '../platform/catch.js';
import { Buf } from '../core/buf';
import { OpenPGPKey } from '../core/crypto/pgp/openpgp-key';
import { DecryptError, DecryptSuccess, MsgUtil } from '../core/crypto/pgp/msg-util';
import { opgp } from '../core/crypto/pgp/openpgpjs-custom';
import { Attachment } from '../core/attachment.js';
import { GoogleData, GmailMsg } from '../mock/google/google-data';
import { testConstants } from './tooling/consts';
import { PgpArmor } from '../core/crypto/pgp/pgp-armor';
import { ExpirationCache } from '../core/expiration-cache';
import { readFileSync } from 'fs';
import * as forge from 'node-forge';
import { ENVELOPED_DATA_OID, SmimeKey } from '../core/crypto/smime/smime-key';
import { Str } from '../core/common';
import { PgpPwd } from '../core/crypto/pgp/pgp-password';

use(chaiAsPromised);

export const equals = (a: string | Uint8Array, b: string | Uint8Array) => {
  expect(typeof a).to.equal(typeof b, `types dont match`);
  if (typeof a === 'string' && typeof b === 'string') {
    expect(a).to.equal(b, 'string result mismatch');
    return;
  }
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    expect(Array.from(a).join('|')).to.equal(Array.from(b).join('|'), 'buffers dont match');
    return;
  }
  throw new Error(`unknown test state [${typeof a},${typeof b}] [${a instanceof Uint8Array},${b instanceof Uint8Array}]`);
};

export const defineUnitNodeTests = (testVariant: TestVariant) => {
  if (testVariant !== 'CONSUMER-LIVE-GMAIL') {
    test(`[unit][KeyUtil.parse] throw if parse methods expecting exactly one key find more than one`, async t => {
      const unarmoredKeys = Buffer.from([
        ...(await PgpArmor.dearmor(testConstants.flowcryptcompatibilityPublicKey7FDE685548AEA788)).data,
        ...(await PgpArmor.dearmor(testConstants.pubkey2864E326A5BE488A)).data,
      ]);
      const armoredKeys = PgpArmor.armor(opgp.enums.armor.publicKey, unarmoredKeys);
      expect((await KeyUtil.parseMany(armoredKeys)).length).to.equal(2);
      await t.throwsAsync(() => OpenPGPKey.parse(armoredKeys), {
        instanceOf: Error,
        message: 'Found 2 OpenPGP keys, expected one',
      });
      await t.throwsAsync(() => KeyUtil.parse(armoredKeys), {
        instanceOf: Error,
        message: 'Found 2 keys, expected one',
      });
      t.pass();
    });
    test(`[unit][OpenPGPKey.parseMany] throws on invalid input`, async t => {
      await t.throwsAsync(
        () =>
          OpenPGPKey.parseMany(`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: FlowCrypt Email Encryption
Comment: Seamlessly send and receive encrypted email

Something wrong with this key`),
        {
          instanceOf: Error,
          message: 'Misformed armored text',
        }
      );
    });
    test(`[unit][KeyUtil.parseMany] throws on invalid input`, async t => {
      await t.throwsAsync(
        () =>
          KeyUtil.parseMany(`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: FlowCrypt Email Encryption
Comment: Seamlessly send and receive encrypted email

Something wrong with this key`),
        {
          instanceOf: Error,
          message: 'Misformed armored text',
        }
      );
    });
    test(`[unit][OpenPGPKey.parse] throws on invalid input`, async t => {
      await t.throwsAsync(
        () =>
          OpenPGPKey.parse(`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: FlowCrypt Email Encryption
Comment: Seamlessly send and receive encrypted email

Something wrong with this key`),
        {
          instanceOf: Error,
          message: 'Misformed armored text',
        }
      );
    });
    test(`[unit][KeyUtil.parse] throws on invalid input`, async t => {
      await t.throwsAsync(
        () =>
          KeyUtil.parse(`-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: FlowCrypt Email Encryption
Comment: Seamlessly send and receive encrypted email

Something wrong with this key`),
        {
          instanceOf: Error,
          message: 'Misformed armored text',
        }
      );
    });
    test(`[unit][OpenPGPKey.getOrCreateRevocationCertificate] operations`, async t => {
      const stringData = 'hello';
      const data = Buf.fromUtfStr(stringData);
      const originalPrv = await OpenPGPKey.parse(testConstants.existingPrv);
      const revocationCertificate = await OpenPGPKey.getOrCreateRevocationCertificate(originalPrv);
      expect(revocationCertificate).to.be.not.empty;
      if (!revocationCertificate) {
        throw Error;
      }
      expect(revocationCertificate.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')).to.be.true;
      expect(revocationCertificate).to.include('Version: FlowCrypt Email Encryption');
      expect(revocationCertificate).to.include('Comment: Seamlessly send and receive encrypted email');
      expect(revocationCertificate).to.include('Comment: This is a revocation certificate');
      const expectNotRevoked = async (key: Key) => {
        expect(key.revoked).to.be.false;
        if (key.isPrivate) {
          await MsgUtil.sign(originalPrv, stringData);
        } else {
          await MsgUtil.encryptMessage({ pubkeys: [pubkey], data, armor: true });
        }
      };
      const expectRevoked = async (key: Key) => {
        expect(key.revoked).to.be.true;
        if (key.isPrivate) {
          await t.throwsAsync(() => MsgUtil.sign(revokedPrv, stringData), {
            instanceOf: Error,
            message: 'Error signing message: Primary key is revoked',
          });
        } else {
          await t.throwsAsync(() => MsgUtil.encryptMessage({ pubkeys: [revokedPub], data, armor: true }), {
            instanceOf: Error,
            message: 'Error encrypting message: Primary key is revoked',
          });
        }
      };
      const testKey = async (key: Key, func: (key: Key) => Promise<void>) => {
        await func(key);
        const armored = KeyUtil.armor(key);
        const unarmored = await OpenPGPKey.parse(armored);
        await func(unarmored);
        KeyUtil.pack(key);
        await func(key);
      };
      await testKey(originalPrv, expectNotRevoked); // the original key remains valid
      const pubkey = await KeyUtil.asPublicKey(originalPrv);
      await testKey(pubkey, expectNotRevoked); // the pub key remains valid
      await t.throwsAsync(() => OpenPGPKey.getOrCreateRevocationCertificate(pubkey), {
        instanceOf: Error,
        message: 'Key FAFB7D675AC74E87F84D169F00B0115807969D75 is not a private key',
      });
      // apply revocation certificate
      const revokedPrv = await OpenPGPKey.applyRevocationCertificate(originalPrv, revocationCertificate);
      await testKey(originalPrv, expectNotRevoked); // the original key remains valid
      await testKey(revokedPrv, expectRevoked);
      const revokedPub = await OpenPGPKey.applyRevocationCertificate(pubkey, revocationCertificate);
      await testKey(pubkey, expectNotRevoked); // the original key remains valid
      await testKey(revokedPub, expectRevoked);
      // extract the same revocation certificate from the revoked keys
      expect(await KeyUtil.getOrCreateRevocationCertificate(revokedPub)).to.equal(revocationCertificate);
      expect(await KeyUtil.getOrCreateRevocationCertificate(revokedPrv)).to.equal(revocationCertificate);
    });
    test(`[unit][MsgBlockParser.detectBlocks] does not get tripped on blocks with unknown headers`, async t => {
      expect(
        MsgBlockParser.detectBlocks("This text breaks email and Gmail web app.\n\n-----BEGIN FOO-----\n\nEven though it's not a vaild PGP m\n\nMuhahah")
      ).to.deep.equal({
        blocks: [
          MsgBlock.fromContent(
            'plainText',
            "This text breaks email and Gmail web app.\n\n-----BEGIN FOO-----\n\nEven though it's not a vaild PGP m\n\nMuhahah"
          ),
        ],
        normalized: "This text breaks email and Gmail web app.\n\n-----BEGIN FOO-----\n\nEven though it's not a vaild PGP m\n\nMuhahah",
      });
      t.pass();
    });

    test(`[unit][MsgBlockParser.detectBlocks] ignores false-positive blocks`, async t => {
      const input = `Hello, sending you the promised json:
      {
        "entries" : [ {
          "id" : "1,email-key-manager,evaluation.org,pgp-key-private,106988520142055188323",
          "content" : "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: FlowCrypt 7.6.9 Gmail Encryption\r\nComment: Seamlessly send and receive encrypted email\r\n\r\n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\r\n+P9DgunMb5OtkDwm6WWxpzV150LJcA==\r\n=FAco\r\n-----END PGP PRIVATE KEY BLOCK-----\r\n"
        }, {
          "id" : "1,email-key-manager,evaluation.org,pgp-key-public,ekm%40ekm-client-configuration-test.flowcrypt.test",
          "content" : "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: FlowCrypt 7.6.9 Gmail Encryption\r\nComment: Seamlessly send and receive encrypted email\r\n\r\nxsBNBF5mRKEBCADX62s0p6mI6yrxB/ui/LqxfG4RcQzZJf8ah52Ynu1n8V7Y\r\n7143LmT3MfCDw1bfHu2k1OK7hT+BOi6sXas1D/fVtjz5WwuoBvwf1DBZ7eq8\r\ntMQbLqQ7m/A8uwrVFOhWfuxulM7RuzIPIgv4HqtKKEugprUd80bPus45+f80\r\nH6ZSgEpmZD6t9JShY6f8pU1OHcnPqFsFF0sLyOk7WcCG5Li3WjkwU/lIu18q\r\nR26oLb5UM8z6vv6JD29GmqCj+OLYaPk8b00kdpGEvTjw3VzGM+tXOgUf2y1T\r\nK9UfhMNkyswxUZw543CMTdw9V0+AzM0q70T/p0fP9nlJCv6M3bQm6D/vABEB\r\nAAHNL0VrbSBVc2VyIDxla21AZWttLW9yZy1ydWxlcy10ZXN0LmZsb3djcnlw\r\ndC5jb20+wsB1BBABCAAfBQJeZkShBgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIe\r\nAQAKCRDESadeBea4P0KvCACD5uOgGxwGEmUWfH8EXPK7npDKulmoZnSWYrfC\r\nX3ctUKXjwPBWRXYid7LChnQAR6SRcyxyD1Eoel5ZVrJyKHqRkxcanFHeqRU1\r\nOyOgtsQyPIGtLipmOgc6i5JYhqbQ4mNu10CGS6ZKhjf6rFIqLl/8f4lnBc28\r\nUqVuP20Ru6KJZTVVQRF28FweMByR/3LyAWfObMwXJ0+uFEV941VEDv5MGdId\r\nfePTP2cHRSJxPqVhpPWtfzYLStUzLFvtLfE45hympok4lZeKfLVtZVVQEgT+\r\nojEImdiZQJ0dT+jeJhmuTjzURQcLapXv2GLBUZaY2zfoAXR31QNYjADOxlrO\r\nutSUzsBNBF5mRKEBCACVNQTzI2Cf1+G3q38OtXO89tuBI/a5TjcHh/sFIJB6\r\nPPuEg/uW+EsjkgI3yk+UZZd6iYohO2mJcJ7MnaFHOu7tmOEaaHSiYsA0RTnV\r\nqUBlbHbsl2oSlQJ/mjJ4cWq5ateuLHhx2RV0t1bm2anHJnqKGkqYqXA72m5g\r\nrLzRSJ9M43wQRheGWGNoNdg4kPxU+PjYwfk2ARX5SCUKoG0qp0RhRMplX74u\r\nYi+Ek/9qSyZevmhK55sXIUNwLsuEhejlr0iucOt2vcIybQ9EbMXz62yYMRjY\r\ngy4SxW5aQJxXFeWkSo6wzMqQ1ZiSArRCezBk+mftxNrmwmtCcJajQt2uAQQV\r\nABEBAAHCwF8EGAEIAAkFAl5mRKECGwwACgkQxEmnXgXmuD/7VAf+IMJMoADc\r\ndWNhn45AvkwbzSmYt4i2aRGe+qojswwYzvFBFZtyZ/FKV2+LHfKUBI18FRmH\r\nmKEba1UUetflytxiAwZxSJSf7Yz/NDiWaVn0eOLopmFMiPb02a5i3CjbLsDe\r\nex2y/69R0+fQc+rE3HZ04C8H/YAqFV0VOv3L+2EztOGK7KOZOx4toR05oDqb\r\nZbiDzwhsa2MugHLPLZuGl3eGk+n/EcINhopHg+HU8MHQE6rADvrok6QiYVhp\r\nGqi8ksD3kBAk43hGRSD2m/WDPWa/h2sh5rVswTKUDtv1fd1H6Ff5FnK21LHj\r\nEk0f+P9DgunMb5OtkDwm6WWxpzV150LJcA==\r\n=Hcoc\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n"
        }, {
          "id" : "1,email-key-manager,evaluation.org,pgp-key-fingerprint,C05803F40E0B9FE4FE9B4822C449A75E05E6B83F",
          "content" : "1,email-key-manager,evaluation.org,pgp-key-private,106988520142055188323\n1,email-key-manager,evaluation.org,pgp-key-public,ekm%40ekm-client-configuration-test.flowcrypt.test"
        } ]
      }`;
      const { blocks, normalized } = MsgBlockParser.detectBlocks(input);
      expect(normalized).to.equal(input);
      expect(blocks).to.have.property('length').that.equals(1);
      expect(blocks[0]).to.deep.equal(MsgBlock.fromContent('plainText', input));
      t.pass();
    });

    test(`[unit][MsgBlockParser.detectBlocks] replaces intended blocks`, async t => {
      const prv = `-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: FlowCrypt 7.6.9 Gmail Encryption\r\nComment: Seamlessly send and receive encrypted email\r\n\r\nxcLYBF5mRKEBCADX62s0p6mI6yrxB/ui/LqxfG4RcQzZJf8ah52Ynu1n8V7Y\r\n7143LmT3MfCDw1bfHu2k1OK7hT+BOi6sXas1D/fVtjz5WwuoBvwf1DBZ7eq8\r\ntMQbLqQ7m/A8uwrVFOhWfuxulM7RuzIPIgv4HqtKKEugprUd80bPus45+f80\r\nH6ZSgEpmZD6t9JShY6f8pU1OHcnPqFsFF0sLyOk7WcCG5Li3WjkwU/lIu18q\r\nR26oLb5UM8z6vv6JD29GmqCj+OLYaPk8b00kdpGEvTjw3VzGM+tXOgUf2y1T\r\nK9UfhMNkyswxUZw543CMTdw9V0+AzM0q70T/p0fP9nlJCv6M3bQm6D/vABEB\r\nAAEAB/sG3UWhvWjO4QcS9ZmC43z98oI/TLRHXQVgrwoMFZVflhVZWTbKE1AD\r\nadOHJNkoq7+LW3c/1esgbRyZvzqXq8PJyArlNIdI1rwCOQk2erFZQXfwk0mG\r\nWZ1IGPwtrQX75foXQ+TVVxmu0HrH7xWr/F73IwWkB51rMjmnLzL1UcJEYh/I\r\nVS5a4+KhCHf4k7GNewLdTd74ERNfL/BPRS2vye4oxJCr9Qx2nwB9a8WMk7X4\r\nIYIH0zpo5/Eu5nXUZyZ2D/72UlOmsox376J8B4lkoRMQPmIvfLBqyX4w7EG6\r\ngwBF+gib/hyHm8aAgkwPs931CDDJNf0wq17dqbDN0Uk8q1SRBADtHbjT2Utl\r\ns6R0g8BRakCh4FT1t/fvlFXO14T0O28vfGroWtbd0q/2XJF1WcRU9NXdo2DG\r\n3z5dQJzKz/nb8G9/LDpWcuBfYWXT3YZVOSiIUSp9SwYGTHIXCxqYev+ALc1b\r\nO3PYpbYgadnPeu/7qRTIzN9Wrnplp5PO7RcBGGWY/wQA6R2L8IEz1wZuiUqd\r\nFsb7Rzpe2bp4sQNsCdaX69Ci0fHsIOltku52K4A1hEqCaPZBGh7gnYGYSx2w\r\nF3UklJxaaxh3EjaxJT0R6+fHpkdhjnsKIgyhjwnuZSHQYINah00jupIZRjn7\r\n67XnOKKnWajodAojfgsdZqAbZ/WHSq8X6RED/i5Q4xaoa72VT3hMTYRkR6R9\r\nhBVjmR6NsUq9cIZoV6txFbpijj79qzrlY7yAl1NA7bkuHxvE+uHVBqFtBo2I\r\n3f9cINbCWWdgsAvNtYEwUnpgzDoL5UF0TCZvtmF2r0R7zVniuDTeKyEoUZYF\r\nJA1o6k3hnwCQDFLfWchcVPIra2pVPZrNL0VrbSBVc2VyIDxla21AZWttLW9y\r\nZy1ydWxlcy10ZXN0LmZsb3djcnlwdC5jb20+wsB1BBABCAAfBQJeZkShBgsJ\r\nBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAKCRDESadeBea4P0KvCACD5uOgGxwG\r\nEmUWfH8EXPK7npDKulmoZnSWYrfCX3ctUKXjwPBWRXYid7LChnQAR6SRcyxy\r\nD1Eoel5ZVrJyKHqRkxcanFHeqRU1OyOgtsQyPIGtLipmOgc6i5JYhqbQ4mNu\r\n10CGS6ZKhjf6rFIqLl/8f4lnBc28UqVuP20Ru6KJZTVVQRF28FweMByR/3Ly\r\nAWfObMwXJ0+uFEV941VEDv5MGdIdfePTP2cHRSJxPqVhpPWtfzYLStUzLFvt\r\nLfE45hympok4lZeKfLVtZVVQEgT+ojEImdiZQJ0dT+jeJhmuTjzURQcLapXv\r\n2GLBUZaY2zfoAXR31QNYjADOxlrOutSUx8LYBF5mRKEBCACVNQTzI2Cf1+G3\r\nq38OtXO89tuBI/a5TjcHh/sFIJB6PPuEg/uW+EsjkgI3yk+UZZd6iYohO2mJ\r\ncJ7MnaFHOu7tmOEaaHSiYsA0RTnVqUBlbHbsl2oSlQJ/mjJ4cWq5ateuLHhx\r\n2RV0t1bm2anHJnqKGkqYqXA72m5grLzRSJ9M43wQRheGWGNoNdg4kPxU+PjY\r\nwfk2ARX5SCUKoG0qp0RhRMplX74uYi+Ek/9qSyZevmhK55sXIUNwLsuEhejl\r\nr0iucOt2vcIybQ9EbMXz62yYMRjYgy4SxW5aQJxXFeWkSo6wzMqQ1ZiSArRC\r\nezBk+mftxNrmwmtCcJajQt2uAQQVABEBAAEAB/sFz/fuZM1pzKYdWo/ricQF\r\nc3RfloAQ/ewE3hY4P+mA6Yk+w0l0ux1qOFDfzYDGHiMFggAghUj6Mqns/KMA\r\nvFn8ZX03YyRQAxrLrnqvSRWaHdyQIOHf8XAUenRG3twydugJ/+99N+CvGElJ\r\nWudTO7uAT7/iLI+TtVGhcHk2ieayvwaleWfQd9eVw37xi58hMWV/NSBOIZhW\r\n2Lv/aldPr8ld8vlWYN4xbTCLF45FoetBrGjDkXb3BCELHSj/ot7I+wZ1uGIF\r\n33wh8Q0EWFgqQtMBnyL6m/XO0U1sOrJADVGQsOQ1/5+3AnpUJOHnP9rnhy8A\r\n2glYg3+2sRRupRG4n/6NBADJKA4RsHwvOeRx1pnuOD8B2fP0r5qJ4gi+tsRq\r\nIXOY1dpPbhzo4AAn+RVwo6JC3aUWtt2yUsJ9eTyWG432LkM9eUwL4Z//ymXf\r\nVFIfl4ySyEvbSujNfreEYM7FUr7kxpBfGE1c86J+AX6MZpfw9hIGs+8IHr/j\r\ngoZe8+CD+1xBuwQAveMZgrB+CoGjQMaVa6/GoWagV20KjHKXDhI/Aogjnu/B\r\nlwHemh1pJucI5kvnq+SaupFO8dgDt+bhwJxsH6d/Wj/J80+TR7pvYFSkk3LV\r\nP3IGRUy7U11LKEqno5n9/4/EuXvV/lixalIGNOGgpnoHgwPIkT9AYGxOlF21\r\n8T4nTG8D/R/URs9vxc9nmTDm9ykw0cHDMmSqLl1a5Dzl2VpQitFBgmaCEo5L\r\ne+QN/nX0KWMFttKXo++N/sU988sOhxQyEzeTq6B+9YJVnaaxAZByDRzrMgG+\r\nq/5XGxzbwsCta5NxE3iY9CWDrPm20KUkBF3ZKoDrlV0Uck6wX+XLipoDc4AX\r\nRfHCwF8EGAEIAAkFAl5mRKECGwwACgkQxEmnXgXmuD/7VAf+IMJMoADcdWNh\r\nn45AvkwbzSmYt4i2aRGe+qojswwYzvFBFZtyZ/FKV2+LHfKUBI18FRmHmKEb\r\na1UUetflytxiAwZxSJSf7Yz/NDiWaVn0eOLopmFMiPb02a5i3CjbLsDeex2y\r\n/69R0+fQc+rE3HZ04C8H/YAqFV0VOv3L+2EztOGK7KOZOx4toR05oDqbZbiD\r\nzwhsa2MugHLPLZuGl3eGk+n/EcINhopHg+HU8MHQE6rADvrok6QiYVhpGqi8\r\nksD3kBAk43hGRSD2m/WDPWa/h2sh5rVswTKUDtv1fd1H6Ff5FnK21LHjEk0f\r\n+P9DgunMb5OtkDwm6WWxpzV150LJcA==\r\n=FAco\r\n-----END PGP PRIVATE KEY BLOCK-----`;
      const pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: FlowCrypt 7.6.9 Gmail Encryption\r\nComment: Seamlessly send and receive encrypted email\r\n\r\nxsBNBF5mRKEBCADX62s0p6mI6yrxB/ui/LqxfG4RcQzZJf8ah52Ynu1n8V7Y\r\n7143LmT3MfCDw1bfHu2k1OK7hT+BOi6sXas1D/fVtjz5WwuoBvwf1DBZ7eq8\r\ntMQbLqQ7m/A8uwrVFOhWfuxulM7RuzIPIgv4HqtKKEugprUd80bPus45+f80\r\nH6ZSgEpmZD6t9JShY6f8pU1OHcnPqFsFF0sLyOk7WcCG5Li3WjkwU/lIu18q\r\nR26oLb5UM8z6vv6JD29GmqCj+OLYaPk8b00kdpGEvTjw3VzGM+tXOgUf2y1T\r\nK9UfhMNkyswxUZw543CMTdw9V0+AzM0q70T/p0fP9nlJCv6M3bQm6D/vABEB\r\nAAHNL0VrbSBVc2VyIDxla21AZWttLW9yZy1ydWxlcy10ZXN0LmZsb3djcnlw\r\ndC5jb20+wsB1BBABCAAfBQJeZkShBgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIe\r\nAQAKCRDESadeBea4P0KvCACD5uOgGxwGEmUWfH8EXPK7npDKulmoZnSWYrfC\r\nX3ctUKXjwPBWRXYid7LChnQAR6SRcyxyD1Eoel5ZVrJyKHqRkxcanFHeqRU1\r\nOyOgtsQyPIGtLipmOgc6i5JYhqbQ4mNu10CGS6ZKhjf6rFIqLl/8f4lnBc28\r\nUqVuP20Ru6KJZTVVQRF28FweMByR/3LyAWfObMwXJ0+uFEV941VEDv5MGdId\r\nfePTP2cHRSJxPqVhpPWtfzYLStUzLFvtLfE45hympok4lZeKfLVtZVVQEgT+\r\nojEImdiZQJ0dT+jeJhmuTjzURQcLapXv2GLBUZaY2zfoAXR31QNYjADOxlrO\r\nutSUzsBNBF5mRKEBCACVNQTzI2Cf1+G3q38OtXO89tuBI/a5TjcHh/sFIJB6\r\nPPuEg/uW+EsjkgI3yk+UZZd6iYohO2mJcJ7MnaFHOu7tmOEaaHSiYsA0RTnV\r\nqUBlbHbsl2oSlQJ/mjJ4cWq5ateuLHhx2RV0t1bm2anHJnqKGkqYqXA72m5g\r\nrLzRSJ9M43wQRheGWGNoNdg4kPxU+PjYwfk2ARX5SCUKoG0qp0RhRMplX74u\r\nYi+Ek/9qSyZevmhK55sXIUNwLsuEhejlr0iucOt2vcIybQ9EbMXz62yYMRjY\r\ngy4SxW5aQJxXFeWkSo6wzMqQ1ZiSArRCezBk+mftxNrmwmtCcJajQt2uAQQV\r\nABEBAAHCwF8EGAEIAAkFAl5mRKECGwwACgkQxEmnXgXmuD/7VAf+IMJMoADc\r\ndWNhn45AvkwbzSmYt4i2aRGe+qojswwYzvFBFZtyZ/FKV2+LHfKUBI18FRmH\r\nmKEba1UUetflytxiAwZxSJSf7Yz/NDiWaVn0eOLopmFMiPb02a5i3CjbLsDe\r\nex2y/69R0+fQc+rE3HZ04C8H/YAqFV0VOv3L+2EztOGK7KOZOx4toR05oDqb\r\nZbiDzwhsa2MugHLPLZuGl3eGk+n/EcINhopHg+HU8MHQE6rADvrok6QiYVhp\r\nGqi8ksD3kBAk43hGRSD2m/WDPWa/h2sh5rVswTKUDtv1fd1H6Ff5FnK21LHj\r\nEk0f+P9DgunMb5OtkDwm6WWxpzV150LJcA==\r\n=Hcoc\r\n-----END PGP PUBLIC KEY BLOCK-----`;
      const input = `Hello, these should get replaced:\n${prv}\n\nAnd this one too:\n\n${pub}`;
      const { blocks, normalized } = MsgBlockParser.detectBlocks(input);
      expect(normalized).to.equal(input);
      expect(blocks).to.have.property('length').that.equals(4);
      expect(blocks[0]).to.deep.equal(MsgBlock.fromContent('plainText', 'Hello, these should get replaced:'));
      expect(blocks[1]).to.deep.equal(MsgBlock.fromContent('privateKey', prv));
      expect(blocks[2]).to.deep.equal(MsgBlock.fromContent('plainText', 'And this one too:'));
      expect(blocks[3]).to.deep.equal(MsgBlock.fromContent('publicKey', pub));
      t.pass();
    });

    test(`[unit][PgpKey.usableForEncryptionButExpired] recognizes usable expired key`, async t => {
      const expiredKey = await KeyUtil.parse(testConstants.expiredPrv);
      expect(expiredKey.expiration).to.equal(1567605343000);
      expect(expiredKey.usableForEncryptionButExpired).to.equal(true);
      expect(expiredKey.missingPrivateKeyForDecryption).to.equal(false);
      expect(expiredKey.missingPrivateKeyForSigning).to.equal(false);
      t.pass();
    });

    test(`[unit][Key.usableForEncryptionButExpired] recognizes usable expired key when subkey is expired prior to expired primary key`, async t => {
      const expiredKey = await KeyUtil.parse(`-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEY7FFHhYJKwYBBAHaRw8BAQdAJMyoHhB6M1OIZo592p7H3U2dBphH5JpD
orInOSAmt+3NKjxmbG93Y3J5cHQubm90aWZ5LmV4cGlyaW5nLmtleXNAZ21h
aWwuY29tPsKSBBAWCgBEBQJjsUUeBQkAGl4ABAsJBwgJECM4WSPQXyFDAxUI
CgQWAAIBAhkBAhsDAh4BFiEECp1E5ycyjVgoiNqfIzhZI9BfIUMAAHfrAPwM
bYj191L3f7EbMguhCLLXeyzr2JPTgWtKwCQKjCRpYQEA3MuN0YB/sRwerKvP
CrTy8ZMHj2pc1ezRJJLD9nBqxQrOOARjsUUeEgorBgEEAZdVAQUBAQdArxUe
fRWzL8zjigAdkYHfEevatLcnvx9XOjrLBDwsezIDAQgHwn4EGBYIADAFAmOx
RR4FCQANLwAJECM4WSPQXyFDAhsMFiEECp1E5ycyjVgoiNqfIzhZI9BfIUMA
AAvIAP4+Xu5KG3XNg39ZiS0kJs53JZVY27VeeO1JC3Ns2wqmcAEAnpI4MIP3
QMlzT3kLMkM+vmxB9cgGp3m+CyBttV60vgw=
=RnaH
-----END PGP PUBLIC KEY BLOCK-----`);
      expect(expiredKey.usableForEncryptionButExpired).to.equal(true);
      expect(expiredKey.expiration).to.equal(1673425950000);
      t.pass();
    });

    test(`[unit][Key.expiration] gives correct expiration when earlier key expires later, in the past, primary key expires too`, async t => {
      const expiredKey = await KeyUtil.parse(`-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEY7P2PBYJKwYBBAHaRw8BAQdAKXZZoF11EaH4wUiCK8O259UZdAzyCJXq
aBWipx5BF3bNKjxmbG93Y3J5cHQubm90aWZ5LmV4cGlyaW5nLmtleXNAZ21h
aWwuY29tPsKSBBAWCgBEBQJjs/Y8BQkAGl4ABAsJBwgJEJtkS3XZon29AxUI
CgQWAAIBAhkBAhsDAh4BFiEESY3/9QK9ExLp4cC6m2RLddmifb0AAIqOAQDl
1D0cOiJwq5SGSKvBSlaWjnZ/jQWLLimQl8y+Z5/jmgEAz1Ma/A14hqNF5RIU
QnIgec4kaPWy2SWQyr84+GbFFAjOOARjs/Y8EgorBgEEAZdVAQUBAQdA1b9l
NzfymR2zXedT6A7SdDGqhdwI66oeDHrZrAo0kTcDAQgHwn4EGBYIADAFAmOz
9jwFCQANLwAJEJtkS3XZon29AhsMFiEESY3/9QK9ExLp4cC6m2RLddmifb0A
AP1OAQCarm1IbTdsVAEOYWT5wTW3TViSatrsNH6bM2BfW4ehnwEAt8cE2rpA
JZjJMVf3WPULEjdBktqxLYCnWX+l76sB7wLOOARjtpk8EgorBgEEAZdVAQUB
AQdAbZeKralww1T0SHDYhJs+Jz13UyqpR8pMSOsGPL3ZKEIDAQgHwn4EGBYI
ADAFAmO2mTwFCQAGl4AJEJtkS3XZon29AhsMFiEESY3/9QK9ExLp4cC6m2RL
ddmifb0AAPebAQDtM5w7GW/lwY6hWVt2KUTn0V5J/67PmpYapK/EkHENDgD/
fXoskfWDbX6oo8PPW+T5OGYJm2Tk7ozgcg2ezmUgEg8=
=JqXW
-----END PGP PUBLIC KEY BLOCK-----`);
      expect(expiredKey.usableForEncryptionButExpired).to.equal(true);
      expect(expiredKey.expiration).to.equal(1673602364000);
      t.pass();
    });

    test(`[unit][Key.expiration] gives correct expiration when earlier key expires later, in the past, non-expiring primary key`, async t => {
      const expiredKey = await KeyUtil.parse(`-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEY7QObRYJKwYBBAHaRw8BAQdAczbosTYkDbJ6Xd0/kAdMRGzDnpRbF5Th
zhRHEs5+uR7NKjxmbG93Y3J5cHQubm90aWZ5LmV4cGlyaW5nLmtleXNAZ21h
aWwuY29tPsKMBBAWCgA+BQJjtA5tBAsJBwgJEF1Ram9HtamJAxUICgQWAAIB
AhkBAhsDAh4BFiEE2eoEaD/F9813lUXtXVFqb0e1qYkAALurAQDrk80QfXEY
LwXJJrL9bHJIP0kya9cMSvEb8JKzXIzpIAEA3KM2EfDoi/1YS/JTFrEOn1i1
i/7lai45fVRmRB27Fw7OOARjtA5tEgorBgEEAZdVAQUBAQdAVRKAk9ImOIOx
HjE1NjoSm8J4+nxRCgJJwAc1ha4MTTIDAQgHwn4EGBYIADAFAmO0Dm0FCQAN
LwAJEF1Ram9HtamJAhsMFiEE2eoEaD/F9813lUXtXVFqb0e1qYkAABATAP4r
UImxLz0ms9p0uUEemR4MkeJ2Iui7nUO599X4cQCugQEA2KAxUuf4IC7oY5YJ
SuLyf8KT9m8kkXjHrA9PAIhEowHOOARjtrFtEgorBgEEAZdVAQUBAQdAFJ/Q
ZKQpr6ei1cBefr+z8hCEwFyMEzIxVfJY8QUsMH4DAQgHwn4EGBYIADAFAmO2
sW0FCQAGl4AJEF1Ram9HtamJAhsMFiEE2eoEaD/F9813lUXtXVFqb0e1qYkA
AHdQAQDhNHD2qXs3FsbPCGYuqBpI5mFet64slrmgF/qw082jJAD+IV0r8J7s
3iJakM0iGN7IBWTT03Rr4wV/RfVbSzpsrQ8=
=uMzH
-----END PGP PUBLIC KEY BLOCK-----`);
      expect(expiredKey.usableForEncryptionButExpired).to.equal(true);
      expect(expiredKey.expiration).to.equal(1673608557000);
      t.pass();
    });

    test(`[unit][Key.expiration] gives correct expiration when earlier key expires later, in the future, non-expiring primary key`, async t => {
      const expiringKey = await KeyUtil.parse(`-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEY7QXVRYJKwYBBAHaRw8BAQdAjAQdAmp9L2Xyc/oxarZmXFvKiNBAQb+K
a8tnPI4LXRHNKjxmbG93Y3J5cHQubm90aWZ5LmV4cGlyaW5nLmtleXNAZ21h
aWwuY29tPsKMBBAWCgA+BQJjtBdVBAsJBwgJEM5qLrmJzYEeAxUICgQWAAIB
AhkBAhsDAh4BFiEEHkmnB9FtCPOyqjRbzmouuYnNgR4AAB3+AQCmMhnTFAu+
HZ53xI5VNfcEDH8eJUzVws9Ua1Ob02+mbQD9FbrzBpChCw/r3xxEAfTvEfIa
m7p0GlQeUwcJwC/FCgbOOARjtBdVEgorBgEEAZdVAQUBAQdAjl5oDyPuDsyf
CytKq7Rk7v619xg0MJH4x1yy8OhjDhYDAQgHwn4EGBYIADAFAmO0F1UFCSWl
NQAJEM5qLrmJzYEeAhsMFiEEHkmnB9FtCPOyqjRbzmouuYnNgR4AAEd1AP42
HH8Xfpy66FxdNtgDMHVS23rKdlD+T+OCiO+UixsRAAEAuIcTCfi5ZRnjrH2/
Rk0gHr57uH2Du1DlC2Be6cT7kAfOOARjtrpVEgorBgEEAZdVAQUBAQdAdAZf
8udXJ69BsjaIY8Zh9QH1SKT8z85AdlzvkMA1ImYDAQgHwn4EGBYIADAFAmO2
ulUFCSWenYAJEM5qLrmJzYEeAhsMFiEEHkmnB9FtCPOyqjRbzmouuYnNgR4A
ACu7AP904FUsOvvYhiJJ2GIWwxqnWuhqtz0rKY1Xoxk0vhBmzQD+NqVK9O1/
qC2PFoU1J4aEVe5Jz2yovJnzkx/aa0Hs4g0=
=ZB8L
-----END PGP PUBLIC KEY BLOCK-----`);
      expect(expiringKey.usableForSigning).to.equal(true);
      expect(expiringKey.usableForEncryption).to.equal(true);
      expect(expiringKey.expiration).to.equal(2304330837000);
      t.pass();
    });

    test('[unit][PgpPwd.random] produces string of correct pattern', async t => {
      const generatedString = PgpPwd.random();
      // eg TDW6-DU5M-TANI-LJXY
      expect(/^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/.test(generatedString)).to.equal(true);
      t.pass();
    });

    test('[unit][Str.is7bit] correctly detects presence of non-7bit characters', async t => {
      const UNICODE = `abcგ`;
      const UNICODE_AS_BYTES = Buf.fromUtfStr(UNICODE);
      const ASCII = 'Simple ASCII text\r\nwith line breaks';
      const ASCII_AS_BYTES = Buf.fromUtfStr(ASCII);
      expect(Str.is7bit(UNICODE)).to.be.false;
      expect(Str.is7bit(UNICODE_AS_BYTES)).to.be.false;
      expect(Str.is7bit(ASCII)).to.be.true;
      expect(Str.is7bit(ASCII_AS_BYTES)).to.be.true;
      t.pass();
    });

    test('[unit][KeyUtil.parse] S/MIME key parsing works', async t => {
      /*
      // generate a key pair
      const keys = forge.pki.rsa.generateKeyPair(2048);
      // create a certification request (CSR)
      const csr = forge.pki.createCertificationRequest();
      csr.publicKey = keys.publicKey;
      csr.setSubject([{
        name: 'commonName',
        value: 'smime@recipient.com'
      }]);
      csr.sign(keys.privateKey);
      // issue a certificate based on the csr
      const cert = forge.pki.createCertificate();
      cert.serialNumber = '20211103'; // todo: set something unique here
      cert.validity.notBefore = new Date();
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 100);
      cert.setSubject(csr.subject.attributes);
      const caCertPem = readFileSync("./ca.crt", 'utf8');
      const caKeyPem = readFileSync("./ca.key", 'utf8');
      const caCert = forge.pki.certificateFromPem(caCertPem);
      const caKey = forge.pki.decryptRsaPrivateKey(caKeyPem, '1234');
      cert.setIssuer(caCert.subject.attributes);
      cert.setExtensions([{
        name: 'basicConstraints',
        cA: true
      }, {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
      }, {
        name: 'extKeyUsage',
        emailProtection: true
      }
      ]);
      cert.publicKey = csr.publicKey;
      cert.sign(caKey);
      const pem = forge.pki.certificateToPem(cert);
      console.log(pem);
      const p12asn1 = forge.pkcs12.toPkcs12Asn1(keys.privateKey, cert, 'try_me');
      const rawString = forge.asn1.toDer(p12asn1).getBytes();
      let buf = Buf.fromRawBytesStr(pem);
      writeFileSync("./smime.crt", buf);
      buf = Buf.fromRawBytesStr(rawString);
      writeFileSync("./test.p12", buf); */
      const key = await KeyUtil.parse(testConstants.smimeCert);
      expect(key.id).to.equal('1D695D97A7C8A473E36C6E1D8C150831E4061A74');
      expect(key.family).to.equal('x509');
      expect(key.usableForEncryption).to.equal(true);
      expect(key.usableForSigning).to.equal(true);
      expect(key.usableForEncryptionButExpired).to.equal(false);
      expect(key.usableForSigningButExpired).to.equal(false);
      expect(key.emails.length).to.equal(1);
      expect(key.emails[0]).to.equal('smime@recipient.com');
      expect(key.identities.length).to.equal(1);
      expect(key.identities[0]).to.equal('smime@recipient.com');
      expect(key.isPublic).to.equal(true);
      expect(key.isPrivate).to.equal(false);
      expect(key.expiration).to.not.equal(undefined);
      t.pass();
    });

    const httpsCert = `-----BEGIN CERTIFICATE-----
MIIGqzCCBZOgAwIBAgIQB0/pAsa31hmIThyhhU2ReDANBgkqhkiG9w0BAQsFADBN
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMScwJQYDVQQDEx5E
aWdpQ2VydCBTSEEyIFNlY3VyZSBTZXJ2ZXIgQ0EwHhcNMTkwNzA4MDAwMDAwWhcN
MjEwOTEwMTIwMDAwWjB2MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEbMBkGA1UEChMSWSBDb21iaW5hdG9y
LCBJbmMuMR0wGwYDVQQDExRuZXdzLnljb21iaW5hdG9yLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMsNA6BafLAJyN3SjorK4fq6P8oArZLHCHwB
uf4NQ0Oo/CdMgrV28/PM4yh2U0++zL9ZuS3foqMOSwy6DZbZIfBa/WBjhJKd4/gy
2yJwOGwSsIyVMpQ/HsBrZRruN2oEiu4inE4hPyYC03Z7zRlTDOuxDDBOJjuKMYRr
aMlzOqj7ZZDLAOYgRDoGHTGF1AnqT+ZsV98rXCijgFGvHTaXqJxcz+edKfHTzy+n
jsgbbbBJ9jGATX8qXqdqjCHm6D5G6hJ2MfcQt4Ohd5sm8BKvZAEMCcsLww2ijwx9
j7ZadN7n7dOp5sY32BEhe7l0ki22TDS+pcaySoP8E5axqrnAMkUCAwEAAaOCA1ww
ggNYMB8GA1UdIwQYMBaAFA+AYRyCMWHVLyjnjUY4tCzhxtniMB0GA1UdDgQWBBQO
JfQVakUgYp9x0ncgzQTXXFjfOjAfBgNVHREEGDAWghRuZXdzLnljb21iaW5hdG9y
LmNvbTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMGsGA1UdHwRkMGIwL6AtoCuGKWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9z
c2NhLXNoYTItZzYuY3JsMC+gLaArhilodHRwOi8vY3JsNC5kaWdpY2VydC5jb20v
c3NjYS1zaGEyLWc2LmNybDBMBgNVHSAERTBDMDcGCWCGSAGG/WwBATAqMCgGCCsG
AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAgGBmeBDAECAjB8
BggrBgEFBQcBAQRwMG4wJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
LmNvbTBGBggrBgEFBQcwAoY6aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
Z2lDZXJ0U0hBMlNlY3VyZVNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAAMIIBfQYK
KwYBBAHWeQIEAgSCAW0EggFpAWcAdgDuS723dc5guuFCaR+r4Z5mow9+X7By2IMA
xHuJeqj9ywAAAWvSsgGGAAAEAwBHMEUCIQDuwilh2VuUnkTH0tmDUbAdKWDxFukD
m/4EktTbiwgFNAIgZltmbZUzknxDpGUXkVLpFmWTogu4wAGxh72hbbFp804AdgCH
db/nWXz4jEOZX73zbv9WjUdWNv9KtWDBtOr/XqCDDwAAAWvSsgIeAAAEAwBHMEUC
IQDzAY1oWZD1mhX+nCKORP4DxtO3AnhLSUMOyvv3OBbICQIgWWzTJP2gsPM6vHux
kb6fQtPekabXk0nhrOScMHr/cvAAdQBElGUusO7Or8RAB9io/ijA2uaCvtjLMbU/
0zOWtbaBqAAAAWvSsgEiAAAEAwBGMEQCIFqbAfpfnJFvd4miwlb3ZMCy/tph+qn6
0gFBIGhOFVlQAiBqo/dlgJEfPJU2pjPlR22kl7wTbnFnbVabTAy8eKx+DjANBgkq
hkiG9w0BAQsFAAOCAQEARcovgnGiFSc6ve8yTxFOho47wBKXwYAUfoGiiRFybcX6
43JcEMyH6KYU8qnfhKzp9juYBXTuc+4BqLP8fGdrP6I7xfYux6PWdhZ9ReVxZhrn
+7neAPnr4IcDyUMGB3bqn4wslL8Go1+dHKfM+Ix8k/+ytaXWYZQgiWNwmuR3Piay
vo5ioURVp9Hm28b1A5o828aXph6nbPhyaLD5gUdQTuprQGpJMo2tL9AmZhtw3iPH
Nu6RzBFp27492OM1t0vvbEsNkMgD3/wSCMev5rleor1bvTT+GkSEArEdpHRydtcN
WeNYP84Yjw6OFSHdi2W0VojRGhxm7PZCMqswN/XaBg==
-----END CERTIFICATE-----`;

    test('[unit][KeyUtil.parse] S/MIME key parsing of HTTPS cert', async t => {
      // parsing throws because the domain name doesn't look like an e-mail
      // address
      await t.throwsAsync(() => KeyUtil.parse(httpsCert), {
        instanceOf: UnreportableError,
        message: 'This S/MIME x.509 certificate has an invalid recipient email: news.ycombinator.com',
      });
    });

    test('[unit][KeyUtil.parse] Unknown key family parsing fails', async t => {
      await t.throwsAsync(() => KeyUtil.parse('dummy string for unknown key'), {
        instanceOf: Error,
        message: 'Key type is unknown, expecting OpenPGP or x509 S/MIME',
      });
    });

    const expiredPgp = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=wYbc
-----END PGP PRIVATE KEY BLOCK-----`;

    test('[unit][KeyUtil.parse] OpenPGP parsing of expired key', async t => {
      const key = await KeyUtil.parse(expiredPgp);
      expect(key.id).to.equal('3449178FCAAF758E24CB68BE62CB4E6F9ECA6FA1');
      expect(key.allIds.length).to.equal(2);
      expect(key.allIds[0]).to.equal('3449178FCAAF758E24CB68BE62CB4E6F9ECA6FA1');
      expect(key.allIds[1]).to.equal('2D3391762FAC9394F7D5E9EDB30FE36B3AEC2F8F');
      expect(key.family).to.equal('openpgp');
      expect(key.usableForEncryption).equal(false);
      expect(key.usableForSigning).equal(false);
      expect(key.usableForEncryptionButExpired).equal(true);
      expect(key.missingPrivateKeyForDecryption).to.equal(false);
      expect(key.missingPrivateKeyForSigning).to.equal(false);
      expect(key.emails.length).to.equal(1);
      expect(key.emails[0]).to.equal('flowcrypt@metacode.biz');
      expect(key.identities.length).to.equal(1);
      expect(key.identities[0]).to.equal('Testing <flowcrypt@metacode.biz>');
      expect(key.isPublic).equal(false);
      expect(key.isPrivate).equal(true);
      expect(key.expiration).to.equal(63074017000);
      t.pass();
    });

    const notExpiredPgp = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
cmKFmmDYm+rrWuAv6Q==
=oWPu
-----END PGP PRIVATE KEY BLOCK-----`;

    test('[unit][KeyUtil.parse] OpenPGP parsing of not-expired key', async t => {
      const key = await KeyUtil.parse(notExpiredPgp);
      expect(key.id).to.equal('7C3B38BB2C8A7E693C29DF455C08033166AF91E3');
      expect(key.allIds.length).to.equal(2);
      expect(key.allIds[0]).to.equal('7C3B38BB2C8A7E693C29DF455C08033166AF91E3');
      expect(key.allIds[1]).to.equal('28A4CCBFA1AF056C3B73EA4DECF8F9D42D8DFED8');
      expect(key.family).to.equal('openpgp');
      expect(key.usableForEncryption).equal(true);
      expect(key.usableForSigning).equal(true);
      expect(key.usableForEncryptionButExpired).equal(false);
      expect(key.usableForSigningButExpired).equal(false);
      expect(key.missingPrivateKeyForDecryption).to.equal(false);
      expect(key.missingPrivateKeyForSigning).to.equal(false);
      expect(key.emails.length).to.equal(1);
      expect(key.emails[0]).to.equal('expiration_100years@test.com');
      expect(key.identities.length).to.equal(1);
      expect(key.identities[0]).to.equal('Testing <expiration_100years@test.com>');
      expect(key.isPublic).equal(false);
      expect(key.isPrivate).equal(true);
      expect(key.expiration).to.equal(4773398996000);
      t.pass();
    });

    const nonExpiringKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEXylIoBYJKwYBBAHaRw8BAQdAMgtGtZnSa/oq2FHZ7Ow7rnCpRDJ5+WlojNXt
6r74RdW0DE5vdCBFeHBpcmluZ4iQBBMWCAA4FiEEjdc3wIbaszE+t21fSpIVLfL9
bb0FAl8pSKACGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQSpIVLfL9bb1J
/QD8CDQrGNP3ZvSQUoA7kTQURLO9qkctY6Yn1+GsJR6M3zQA/ievQawWchCZVzgT
SBC9rHNi6GbYSn3Tm+PnsUOe9g8NuDgEXylIoBIKKwYBBAGXVQEFAQEHQLU+tO+s
CpD7n1C0Mg9Yzghr9pMps9UaexwMuxxVeWZcAwEIB4h4BBgWCAAgFiEEjdc3wIba
szE+t21fSpIVLfL9bb0FAl8pSKACGwwACgkQSpIVLfL9bb39XgD6A91LwqK+CEzl
McqZHXuttXHc2wZ2nvjjtbzWSEzxvpAA/jdWwCNBg65Wh93Df5/6Ec05W8AgFwJH
/NBHfzBA90AM
=E46c
-----END PGP PUBLIC KEY BLOCK-----`;

    test('[unit][KeyUtil.parse] OpenPGP parsing of never expiring key', async t => {
      const key = await KeyUtil.parse(nonExpiringKey);
      expect(key.id).to.equal('8DD737C086DAB3313EB76D5F4A92152DF2FD6DBD');
      expect(key.expiration).to.equal(undefined);
      t.pass();
    });

    const pgpArmoredTwoKeys = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
zZFGf6poIjKUC8V2Zww6
=Hjpw
-----END PGP PUBLIC KEY BLOCK-----`;

    test('[unit][KeyUtil.readMany] Parsing two OpenPGP armored together keys', async t => {
      const { keys, errs } = await KeyUtil.readMany(Buf.fromUtfStr(pgpArmoredTwoKeys));
      expect(keys.length).to.equal(2);
      expect(errs.length).to.equal(0);
      expect(keys.some(key => key.id === '5A5F75AEA28751C3EE8CFFC3AC5F0CE1BB2B99DD')).to.equal(true);
      expect(keys.some(key => key.id === 'BBC75684E46EF0948D31359992C4E7841B3AFF74')).to.equal(true);
      expect(keys.every(key => key.family === 'openpgp')).to.equal(true);
      t.pass();
    });

    const pgpArmoredSeparate = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFzYItQBCAD1FmP71FRRC3nkaIltLH2oZklMY+SAbnses8o5e3wj3DKQk3P4
ZTxALAl9g5GtYqYE5vA2SOSRiuiVD+ibYDOAAEjBBKYlfaFy1UCFAK5gibhP1o04
eEuRuAJt9JJO0aFTj+cwWx/wII+ledavdiWHg1T80JEoHV+EMlvNB51ydZGnSjPs
ntQTO4tQzp1knA9hS20O6g6gLakaNlEc1m3G445d8tWj7V3plLR+FegYWoCJkQ4F
3W6jLSM4ErfLQpj6Ew6bk65wRC8XSNFJAImfVGd40tAtYcHFf/HE3D3NLH3OhFc3
EUnaQtCEqrWqBD/HFdGvqmbVYL3KWusJCXafABEBAAG0IFRlc3QgV0tEIDx0ZXN0
LXdrZEBtZXRhY29kZS5iaXo+iQFUBBMBCAA+FiEEWl91rqKHUcPujP/DrF8M4bsr
md0FAlzYItQCGwMFCQPCZwAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQrF8M
4bsrmd3Ftwf+OhNoF3bq1o7QFJVt6bfIEN1Uqf2+h11pO60ZGJNjLm45rdy2Jt4r
Q86h/XUONGDfV28Pj/Gwz7/ruB4YcFL83HwuGHHh/QZsbHvmopycSS7DQp6yiiSk
M0sLBfbG5jxQpgahrsVqPDhWhvuNCGrWFqEPAmLWyz7CyvtVbglL4cB9V7W9eHFz
FsLSITLR9LJybqqIIRXerpc/cj4ZI0ll/nZbMuFsY/CWbfdxk6CsFTAQ7gegXs/c
QaKQuQJFtl46CFCjUMJJN3SSsaihOu5V3zVWJdW1GJXQWpe2Rir2MqzhSuW0Uw8g
/nd2sNwmriQRfQd7d46YOLcBqVksGiWCb7kBDQRc2CLUAQgA10E6Da2YSXL/6VKJ
YaFNgBi9p7pko6KzrSD8AGxjpDo7BV11jBNImZxP3WrmjPfFYuIET+Lt05St/fdn
tkiHkkPimKNSmH46E0lRnULO3Tmo7Eiu/CMPI5Oj9KZr8fQBvFOh2qFr+dgflIHr
WGO94tIeRq2jdZblGEtOY8kfqf7/WbzaVhIJM/zaYyeQFLv+CNkc2AMIDpsBmKPL
7wrQzGi1JK4Xn7JdRgMoEVFJJFsDkByvp6mvwjRgXkG/UKnDf75vOJzCP1i/6ESb
fu0+pz/gsiwPIcEnS+1F2LWmV2EQTf4FPz75J31bGixP2qIa+Macr+AepreugpFq
gdUQjwARAQABiQE8BBgBCAAmFiEEWl91rqKHUcPujP/DrF8M4bsrmd0FAlzYItQC
GwwFCQPCZwAACgkQrF8M4bsrmd3GZQf+OLkOd0ddebGvLgcQrUANuKASTbke+PUD
laTTpdJlhufLqXHAL3ydZjnmFXEOYQPzWr1DgaUEiEtiw4MO3lWKXj3+J200jPpg
+XEFNXneXrZEJoG/q4h2hB0icP/1k1q+FsSgc3I6kVsGBmnMasJ+j9FhUJ/JECJS
gQwP7QeE0O0oa8zQU+INc6viBkV1F3FP5PvIfVjfmw8yqlhZgeCSSavo/kEgyTlg
cItxVc8FURPk2BkmWYjZ+N0uNOYrI7FGOHdoW4j9rmuOhtYHGLRC0mAcADIRcv7p
ZlBF2eTk0HMhizTvGmOWcv5htkCqxpCSNnjHLsM6YCl+CcW6a8U7/g==
=46pe
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF4pefQBCADjcgq0Wi7ZCDiTCnMnG5PTnTU5nWW7eg9ofEjV9SbDDiHV2SkJ
ZBynFzGgAaWs/x3FINwNffnE/Yc4iokd1wk3tlhcfvzLUMZW9ZrTPAGOioSKa621
nQjTKkln2kuU60oeG5CJocIiLroLHay9N9kVvlidH4dVbC9+jyvdcjieq3RUnXVC
zpF3vZN/aTgbjecyfQY4oeiMglpBImTdPw/7k3Xz6L7D2o8wIuVyS7KxTrIsmR1F
uTkfAWzfhI4rZHxyzWmCWZnC+N+rLVdLOo4V7op6SZE1x3Hhy2BXChBzjIZbJ1/J
eIQLMk8WaszkGc0uXFXsF/fB+g9woa7cRjT5ABEBAAG0FXRlc3Qtd2tkQG1ldGFj
b2RlLmJpeokBVAQTAQgAPhYhBLvHVoTkbvCUjTE1mZLE54QbOv90BQJeKXn0AhsD
BQkDwmcABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEJLE54QbOv908+YH+gM4
kpkNL7IWUjRJqmuSybWT23BKtFq4/P1HhGyUKmIq/ZqjBIzR+rgmfM5qw/HYWO+l
FGPoCeusooMauWWHZ5rbNrP05cwRlRvCg+0GXJ3Yw2tzOayXq5SL3QLa//P2z4yt
Wa9pl5EXIzAWNKlGiuTmZ19tDIrNg3tJQKhdd9MNRite4ZyMvkMB9l/d8PSIIa9J
bbOaQZa0WH6lg417DHAhWIzcI8PLW9hXoeGkOy5z7ah9H7+rZJAcz/Z2Qfo0zu4+
vQnzefA9vzd+d9CRr3ExZMNxpSykH4l4PbYjMpKfLRpdsLvvLnV2H06KZEcxBsn0
czaln5Xm/0wga57IgFW5AQ0EXil59AEIAMW00JciIzastXINdy0Lx15ikpkwQe/o
BO0zxifSRwsvpgh3KdvKV2DfrEagvVXpjv3GV0li5bvdn9mKwDkpVttHddV4u4Sy
ATEN733x9EjhcZf8CQRbqDnJKjpDLI2xpUf9R5coI1je9agNeyOsppXnVs371O4L
aVYzdXLUtZ6LqMN/F0xVbDEEZsFzBI+0Z0f1b0tHuExF3xvBg6bodS7Tnel3LP0x
ZGb1EiwNMo+9GbLkpr64YkUrXvY/L7jm0eQSYmxUTD5o+EDKhizxDCD7adqCzhhK
XtpDsXH1M1N15SzJlchzbXBVY+cNC+6OCmsKFjbhGtFaEFSE/kdBMZMAEQEAAYkB
NgQYAQgAIBYhBLvHVoTkbvCUjTE1mZLE54QbOv90BQJeKXn0AhsMAAoJEJLE54Qb
Ov900VcH/RGkjO1VfyKPgm17PttvC6PtvSAERvEhSRTy3i2ds4s3DXtG3Y1N6NU/
YqolPFrY6PtFX0tTSeN4Zw1x9WckD0hI6qWsj0gcdwK05MmUn8TW0gKK2DwghLZt
3vtn25PuQtzIz/ahwMkOYM5vfJLH3ZoWt7yF/zrvuul9t4bM6ZaNA8uGJf+bYObx
CnSPBUoy8XAfrMg9YDF8djFjhGktbTMWY3feKbzPUHBfT6kii+D+Hmj/C2eb8gYx
XPk9f8zmQi8NqUMzsOQokj9iq+UB1cC3korAsuCVmC3El6cJbQvWEAMEVOFdY3pA
vpQiyk4ceuTNkUZ/qmgiMpQLxXZnDDo=
=lQQh
-----END PGP PUBLIC KEY BLOCK-----`;

    test('[unit][KeyUtil.readMany] Parsing two OpenPGP armored separate keys', async t => {
      const { keys, errs } = await KeyUtil.readMany(Buf.fromUtfStr(pgpArmoredSeparate));
      expect(keys.length).to.equal(2);
      expect(errs.length).to.equal(0);
      expect(keys.some(key => key.id === '5A5F75AEA28751C3EE8CFFC3AC5F0CE1BB2B99DD')).to.equal(true);
      expect(keys.some(key => key.id === 'BBC75684E46EF0948D31359992C4E7841B3AFF74')).to.equal(true);
      expect(keys.every(key => key.family === 'openpgp')).to.equal(true);
      t.pass();
    });

    test('[unit][KeyUtil.readMany] Parsing one S/MIME key', async t => {
      const { keys, errs } = await KeyUtil.readMany(Buf.fromUtfStr(testConstants.smimeCert));
      expect(keys.length).to.equal(1);
      expect(errs.length).to.equal(0);
      expect(keys[0].id).to.equal('1D695D97A7C8A473E36C6E1D8C150831E4061A74');
      expect(keys[0].family).to.equal('x509');
      t.pass();
    });

    test('[unit][KeyUtil.parse] S/MIME key parsing of unprotected PKCS#8 private key and mismatching certificate', async t => {
      await t.throwsAsync(
        () =>
          KeyUtil.parse(`${testConstants.smimeUnencryptedKey}
${testConstants.smimeCert}`),
        { instanceOf: UnreportableError, message: `Certificate doesn't match the private key` }
      );
      t.pass();
    });

    test('[unit][KeyUtil.decrypt] S/MIME key decryption of mismatching private key', async t => {
      const encryptedKey = await KeyUtil.parse(`${testConstants.smimeEncryptedKey}
${testConstants.smimeCert}`);
      await t.throwsAsync(() => KeyUtil.decrypt(encryptedKey, 'AHbxhwquX5pc'), {
        instanceOf: UnreportableError,
        message: `Certificate doesn't match the private key`,
      });
      t.pass();
    });

    test(`[unit][KeyUtil.decrypt] throws on incorrect PKCS#8 encrypted private key`, async t => {
      const encryptedKey = await KeyUtil.parse(`-----BEGIN ENCRYPTED PRIVATE KEY-----

AAAAAAAAAAAAAAAAzzzzzzzzzzzzzzzzzzzzzzzzzzzz.....
-----END ENCRYPTED PRIVATE KEY-----
${testConstants.smimeCert}`);
      await t.throwsAsync(() => KeyUtil.decrypt(encryptedKey, '123'), {
        instanceOf: Error,
        message: `Invalid PEM formatted message.`,
      });
      t.pass();
    });

    test(`[unit][KeyUtil.parse] throws on incorrect PKCS#8 private key`, async t => {
      await t.throwsAsync(
        () =>
          KeyUtil.parse(`-----BEGIN PRIVATE KEY-----

AAAAAAAAAAAAAAAAzzzzzzzzzzzzzzzzzzzzzzzzzzzz.....
-----END PRIVATE KEY-----
${testConstants.smimeCert}`),
        { instanceOf: Error, message: `Invalid PEM formatted message.` }
      );
      t.pass();
    });

    test(`[unit][KeyUtil.parse] throws on incorrect RSA PKCS#8 private key`, async t => {
      await t.throwsAsync(
        () =>
          KeyUtil.parse(`-----BEGIN RSA PRIVATE KEY-----

AAAAAAAAAAAAAAAAzzzzzzzzzzzzzzzzzzzzzzzzzzzz.....
-----END RSA PRIVATE KEY-----
${testConstants.smimeCert}`),
        { instanceOf: Error, message: `Invalid PEM formatted message.` }
      );
      t.pass();
    });

    test('[unit][KeyUtil.armor] S/MIME key from PKCS#12 is armored to PKCS#8', async t => {
      const p12 = readFileSync('test/samples/smime/human-pwd-original-PKCS12.pfx', 'binary');
      const key = SmimeKey.parseDecryptBinary(Buf.fromRawBytesStr(p12), 'AHbxhwquX5pc');
      expect(key.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(key.fullyDecrypted).to.equal(true);
      const armoredDecrypted = KeyUtil.armor(key);
      expect(armoredDecrypted).to.not.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(armoredDecrypted).to.include('-----END RSA PRIVATE KEY-----\r\n-----BEGIN CERTIFICATE-----');
      await KeyUtil.encrypt(key, 're-encrypt');
      expect(key.fullyDecrypted).to.equal(false);
      const armoredEncrypted = KeyUtil.armor(key);
      expect(armoredEncrypted).to.not.include('-----BEGIN RSA PRIVATE KEY-----');
      expect(armoredEncrypted).to.include('-----END ENCRYPTED PRIVATE KEY-----\r\n-----BEGIN CERTIFICATE-----');
      const parsedDecrypted = await KeyUtil.parse(armoredDecrypted);
      expect(parsedDecrypted.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsedDecrypted.fullyDecrypted).to.equal(true);
      const parsedEncrypted = await KeyUtil.parse(armoredEncrypted);
      expect(parsedEncrypted.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsedEncrypted.fullyDecrypted).to.equal(false);
      await KeyUtil.decrypt(parsedEncrypted, 're-encrypt');
      expect(parsedEncrypted.fullyDecrypted).to.equal(true);
      t.pass();
    });

    test('[unit][KeyUtil.readMany] Parsing unarmored S/MIME certificate', async t => {
      const pem = forge.pem.decode(testConstants.smimeCert)[0];
      const { keys, errs } = await KeyUtil.readMany(Buf.fromRawBytesStr(pem.body));
      expect(keys.length).to.equal(1);
      expect(errs.length).to.equal(0);
      expect(keys[0].id).to.equal('1D695D97A7C8A473E36C6E1D8C150831E4061A74');
      expect(keys[0].family).to.equal('x509');
      t.pass();
    });

    test('[unit][KeyUtil.parse] issuerAndSerialNumber of S/MIME certificate is constructed according to PKCS#7', async t => {
      const key = await KeyUtil.parse(testConstants.smimeCert);
      const buf = Buf.with((await MsgUtil.encryptMessage({ pubkeys: [key], data: Buf.fromUtfStr('anything'), armor: false })).data);
      const raw = buf.toRawBytesStr();
      expect(raw).to.include(key.issuerAndSerialNumber);
      t.pass();
    });

    test('[unit][MsgUtil.encryptMessage] duplicate S/MIME recipients are collapsed into one', async t => {
      const key = await KeyUtil.parse(testConstants.smimeCert);
      const buf = Buf.with((await MsgUtil.encryptMessage({ pubkeys: [key, key, key], data: Buf.fromUtfStr('anything'), armor: false })).data);
      const msg = buf.toRawBytesStr();
      const p7 = forge.pkcs7.messageFromAsn1(forge.asn1.fromDer(msg));
      expect(p7.type).to.equal(ENVELOPED_DATA_OID);
      if (p7.type === ENVELOPED_DATA_OID) {
        expect(p7.recipients.length).to.equal(1);
      }
      t.pass();
    });

    test('[unit][KeyUtil.parse] Correctly extracting email from SubjectAltName of S/MIME certificate', async t => {
      /*
            // generate a key pair
            const keys = forge.pki.rsa.generateKeyPair(2048);
            // create a certification request (CSR)
            const csr = forge.pki.createCertificationRequest();
            csr.publicKey = keys.publicKey;
            csr.setSubject([{
              name: 'commonName',
              value: 'Jack Doe'
            }]);
            // set (optional) attributes
            const subjectAltName = {
              name: 'subjectAltName',
              altNames: [{
                // 1 is RFC822Name type
                type: 1,
                value: 'email@embedded.in.subj.alt.name'
              }]
            }
            const extensions = [subjectAltName];
            (csr as any).setAttributes([{
              name: 'extensionRequest',
              extensions
            }]);
            csr.sign(keys.privateKey);
            // issue a certificate based on the csr
            const cert = forge.pki.createCertificate();
            cert.serialNumber = '1';
            cert.validity.notBefore = new Date();
            cert.validity.notAfter = new Date();
            cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 30);
            cert.setSubject(csr.subject.attributes);
            const caCertPem = fs.readFileSync("./ca.crt", 'utf8');
            const caKeyPem = fs.readFileSync("./ca.key", 'utf8');
            const caCert = forge.pki.certificateFromPem(caCertPem);
            const caKey = forge.pki.decryptRsaPrivateKey(caKeyPem, '1234');
            cert.setIssuer(caCert.subject.attributes);
            cert.setExtensions([{
              name: 'basicConstraints',
              cA: true
            }, {
              name: 'keyUsage',
              keyCertSign: true,
              digitalSignature: true,
              nonRepudiation: true,
              keyEncipherment: true,
              dataEncipherment: true
            }, subjectAltName
            ]);
            cert.publicKey = csr.publicKey;
            cert.sign(caKey);
            const pem = forge.pki.certificateToPem(cert);
      */
      const pem = `-----BEGIN CERTIFICATE-----
MIIETTCCAjWgAwIBAgIBATANBgkqhkiG9w0BAQUFADB0MRMwEQYDVQQIDApTb21l
LVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFzAVBgNV
BAMMDlNvbWUgQXV0aG9yaXR5MSEwHwYJKoZIhvcNAQkBFhJhdXRob3JpdHlAdGVz
dC5jb20wIBcNMjEwNDE3MTIyMTMxWhgPMjA1MTA0MTcxMjIxMzFaMBMxETAPBgNV
BAMTCEphY2sgRG9lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyKOw
VX51bduPdwSLR4u1O4HuOrELZjlOx8SWlOdU2yDZmp9iTZ/jP318xUs7XL1gIMDF
mXuDZB+KU9rwvECOecazWp8vpfLV/Tn/lp5lDLz+QqwlSWruzz0Z49F6zCWfBMQQ
Y475a03pd0oo6Soxt89A5PXuQhIBgdniyxUeQe0Okd7MC5/w0R+95aqZB47ui7ur
R7HcyGzkvfADXvdeZQsKSjja0lVFUJAJ6Uj2o0R9Z1YHtZKH9/D75IiYY3gqYJtt
BZoZPOMpl7Jam5Hz7PVWV3aeeMsAAHALWK7qvfaNx3IOCVh5KYQZ544P7cGGgpuw
UamKkF+wR7H4d7OYPwIDAQABo0kwRzAMBgNVHRMEBTADAQH/MAsGA1UdDwQEAwIC
9DAqBgNVHREEIzAhgR9lbWFpbEBlbWJlZGRlZC5pbi5zdWJqLmFsdC5uYW1lMA0G
CSqGSIb3DQEBBQUAA4ICAQCeGSsJNYsyQXnRal3L0HDF8PTj5zBa2jCSVAuwMe9Z
LWSJEXetF6uwH3yJzCxe/ZGNheEUAMGnMC1lYwsZ8x/hO8WcnzGxC1kqS71jV0us
rYZGsSb6dOoSigUfrzEcImx33n5yKYS8cHN/tUMvPiULX9RlSWnKlAfQClQeIxEA
6Y1Jeu0AVP3ugMajxqHoA10JOOrqjKuvkkM3gha9iS+q0w0mqhJ8GzZfOTdFJj/G
/erHQ/HWL7mqJoGh+i6I9N5qBNmdNEZazXJ/ACfR46Zav7nOXBF9CZ4k4g3mr/Po
1L3FXotxDQaTITY4xrse/GNCd92Q2Pc3ASS1SWRozpefyY414qfDP4x7IYwFOnK/
swVjxFEyniiliYOiUV7tEm5FYRkAaQIAMiAXsZQB5LwatJN7WCQMh3xfPiuW91wL
Qmq47Rku8zPVsmQ5oBF9Ip4RraLOapoL09abmhyS9CFiT+bqZYSa9erT81eZnEfY
p07CH3yZBVSw7nRTIS8ScDHRvTt+FzrcchVcPfXMfYeydosmgQdDFFy/fm2alb8B
JKEHXc4KK04f6Fa90Uo+1hVInMziuLRWN6vubkHUDSXY4jhGm84OksTyW3AFKigC
jLwe8W9IMt765T5x5oux9MmPDXF05xHfm4qfH/BMO3a802x5u2gJjJjuknrFdgXY
9Q==
-----END CERTIFICATE-----`;
      const key = await KeyUtil.parse(pem);
      expect(key.emails.length).to.equal(1);
      expect(key.emails[0]).to.equal('email@embedded.in.subj.alt.name');
      t.pass();
    });

    const smimeAndPgp = testConstants.smimeCert + '\r\n' + expiredPgp;

    test('[unit][KeyUtil.readMany] Parsing one S/MIME and one OpenPGP armored keys', async t => {
      const { keys, errs } = await KeyUtil.readMany(Buf.fromUtfStr(smimeAndPgp));
      expect(keys.length).to.equal(2);
      expect(errs.length).to.equal(0);
      expect(keys.some(key => key.id === '1D695D97A7C8A473E36C6E1D8C150831E4061A74')).to.equal(true);
      expect(keys.some(key => key.id === '3449178FCAAF758E24CB68BE62CB4E6F9ECA6FA1')).to.equal(true);
      expect(keys.some(key => key.family === 'openpgp')).to.equal(true);
      expect(keys.some(key => key.family === 'x509')).to.equal(true);
      t.pass();
    });

    test('[unit][KeyUtil.parse] key was never usable', async t => {
      const expiredPubKey =
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: FlowCrypt Email Encryption 7.8.4\r\nComment: Seamlessly send and receive encrypted email\r\n\r\nxsBNBF8QF1cBCADFQRM0S6kJ1LxL+Y2hqz+w2PIbAKnNpV4gr1D0jEX9ygMY\r\nYxyjGP7QcK2umeBrioWBUET/5yu+KkSVFOxGwXw2m1MqJXZH6fPumgDBEAYg\r\n8afLXI/5Rh7Lp2Z3eBDog6W0I9EOHAB6iFHQgc5m+PUlehMZ23VUKxDpb4kW\r\nsIts1b8Zm0sSimUf15bz0nGxCf00bYf5lCuxBfgAQGK+FgpIAdc03a7VI4zJ\r\nc/A18PR4mlMeDfIj2yWKaL4ka8lr8d+qAP2Cu0I6GcNgBUl5yCWc/6S20J52\r\nKjoa48w1vdAYzK1hjTE7INLrB6WKOCPLoY0jRuqE+ksarw6JtNsAhNrFABEB\r\nAAHNKTxoYXMub2xkZXIua2V5Lm9uLmF0dGVzdGVyQHJlY2lwaWVudC5jb20+\r\nwsCTBBABCAAmBQJfEBpQBQkAAAACBgsJBwgDAgQVCAoCBBYCAQACGQECGwMC\r\nHgEAIQkQ0CoIfv1WLLMWIQQoKZEjISHFGWNfjmPQKgh+/VYss4EFB/9apXb/\r\nRYrf/FwK3NEeAuVAjq4sQFOC+e2sOO1Y1i74Hm5Q3YpL5FPWxg1zzQR3cKlw\r\ngwGiTBH9Re86KuB6XIIhropA94c0c5RGXf4Syb66hsp+xyb5laoazW274M26\r\nLhNou77CFgJ4UTOYPqNoDADcGPCoYzlU/tkp8q+vuIEBuizNkO+vOdFdrG9x\r\nON2n7aPVBWTHTy7PXVQr6wYfbj2c3cmH9ju5bZKoKoZ7niR3jQi+NUAHf09Z\r\nkwWGoYwD37iTtPWrn/nnMqp7nqJxpChsJvtfousgKHWUA1IsCXoSeExZuXYU\r\nVpJduSYQx5H6dy4QwmK8bzRfra/l5O6sRTbNzsBNBF8QF1cBCADL0rwgqVw3\r\nsQ6JD7j9eOkbcc0iNrxLqYWnBCu71opLWVQ0b8mw9DqT3WuXtvOVmEBkqDig\r\nq9Q78BbD2EfQhFNuvcE5GL38BvyUkpgZBC+vi9UrisQTStmLS5bSsT7aipwM\r\nGy3tXFIoHX8XQk8swbKa20fCYd5KKZr3wFBZ6mtXN3O1qgelZ4HEl/bCFz6c\r\nuvZUFLvLaMksXh7um2/bjnB6E9uktn/ts34rbYIuHxVTLs6bq4VbPiUilurz\r\n8uzAsU2HMw2QTQTaJzycJyYzdDxAIXrSmtFah2/wqSYC82r65sA17y3gtbHq\r\neP0pzbzbMQitPCV2poxIHJuiMYh4iWV9ABEBAAHCwHwEGAEIAA8FAl8QGlAF\r\nCQAAAAICGwwAIQkQ0CoIfv1WLLMWIQQoKZEjISHFGWNfjmPQKgh+/VYsswOo\r\nCAC2gkz5f7RLboxFxgbjleY/SWttf9j5pJGCfcaPzLGo8wCbnEUdhs+FqAml\r\nGDF1yZAexCQLBukVhil1yEnknaX1emeHB7d4g6cQFoKtSHeVZ0C9mmM+OJMn\r\nZoGVylTsOLMmVXM/CXyp9JUAlo/oZm1Zpb9RK5rvNJukH1f0DajQjWlC09Y9\r\nVLVDBxlJccsEdas1yojMDHMqNOMiNaAlA33mrY3ucAiKb4q3uP9IuDRuD83M\r\ncoDahY5p8xl6IbKQhnxoWtBgGJWrlwBZro83z9HzW4LmP99pPZqfLZQAevUL\r\n+oQiPqyh512p6O5usc1GkEoN9cn9b/qnvnRu5RMxC/vI\r\n=NveA\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n';
      const parsed = await KeyUtil.parse(expiredPubKey);
      expect(parsed?.usableForEncryption).to.equal(false);
      expect(parsed?.expiration).to.equal(1594890073000);
      expect(parsed?.usableForEncryptionButExpired).to.equal(false); // because last signature was created as already expired, no intersection
      t.pass();
    });
    test('[unit][MsgUtil.type] correctly detects message type', async t => {
      expect(MsgUtil.type({ data: Buf.with('-----BEGIN PGP MESSAGE-----\n\ndummy-----END PGP MESSAGE-----') })).to.eql({
        armored: true,
        type: 'encryptedMsg',
      });
      const binaryMessage = await PgpArmor.dearmor(decodeURIComponent(testConstants.encryptedMessageMissingMdcUriEncoded));
      expect(MsgUtil.type({ data: binaryMessage.data })).to.eql({
        armored: false,
        type: 'encryptedMsg',
      });
      t.pass();
    });
    test('[unit][MsgUtil.decryptMessage] mdc - missing - error', async t => {
      const encryptedData = decodeURIComponent(testConstants.encryptedMessageMissingMdcUriEncoded);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const compatibilityKey1 = Config.key('flowcrypt.compatibility.1pp1')!;
      const kisWithPp = [
        {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          ...(await KeyUtil.keyInfoObj(await KeyUtil.parse(compatibilityKey1.armored!))),
          passphrase: compatibilityKey1.passphrase,
        },
      ];
      const decrypted1 = await MsgUtil.decryptMessage({ kisWithPp, encryptedData, verificationPubs: [] });
      expect(decrypted1.success).to.equal(false);
      if (!decrypted1.success) {
        expect(decrypted1.error).to.eql({
          type: 'no_mdc',
          message:
            'Security threat!\n\nMessage is missing integrity checks (MDC).  The sender should update their outdated software.\n\nDisplay the message at your own risk.',
        });
      }
      t.pass();
    });

    test('[unit][MsgUtil.decryptMessage] decrypts a pubkey-encrypted OpenPGP message', async t => {
      const data = await GoogleData.withInitializedData('flowcrypt.compatibility@gmail.com');
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const msg: GmailMsg = data.getMessage('166147ea9bb6669d')!;
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const encryptedData = Buf.fromBase64Str(msg!.raw!)
        .toUtfStr()
        .match(/-----BEGIN PGP MESSAGE-----.*-----END PGP MESSAGE-----/s)![0];
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const compatibilityKey1 = Config.key('flowcrypt.compatibility.1pp1')!;
      const kisWithPp = [
        {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          ...(await KeyUtil.keyInfoObj(await KeyUtil.parse(compatibilityKey1.armored!))),
          passphrase: compatibilityKey1.passphrase,
        },
      ];
      const decrypted1 = await MsgUtil.decryptMessage({ kisWithPp, encryptedData, verificationPubs: [] });
      expect(decrypted1.success).to.equal(true);
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      const verifyRes1 = (decrypted1 as DecryptSuccess).signature!;
      expect(verifyRes1.match).to.be.null;
      t.pass();
    });

    test('[MsgUtil.decryptMessage] handles long message', async t => {
      const data = Buf.fromUtfStr('The test string concatenated many times to produce large output'.repeat(100000));
      const passphrase = 'pass phrase';
      const prv = await KeyUtil.parse(prvEncryptForSubkeyOnly);
      const encrypted = await MsgUtil.encryptMessage({
        pubkeys: [await KeyUtil.asPublicKey(prv)],
        data,
        armor: true,
      });
      const kisWithPp: KeyInfoWithIdentityAndOptionalPp[] = [{ ...(await KeyUtil.keyInfoObj(prv)), family: prv.family, passphrase }];
      const decrypted = await MsgUtil.decryptMessage({
        kisWithPp,
        encryptedData: encrypted.data,
        verificationPubs: [],
      });
      expect(decrypted.success).to.equal(true);
      expect((decrypted as DecryptSuccess).content.length).to.equal(data.length);
      t.pass();
    });

    /* eslint-disable @typescript-eslint/no-non-null-assertion */
    test('[unit][MsgUtil.decryptMessage] finds correct key to verify signature', async t => {
      const data = await GoogleData.withInitializedData('ci.tests.gmail@flowcrypt.test');
      const msg: GmailMsg = data.getMessage('1766644f13510f58')!;
      const encryptedData = Buf.fromBase64Str(msg!.raw!)
        .toUtfStr()
        .match(/\-\-\-\-\-BEGIN PGP SIGNED MESSAGE\-\-\-\-\-.*\-\-\-\-\-END PGP SIGNATURE\-\-\-\-\-/s)![0];
      // actual key the message was signed with
      const signerPubkey = testConstants.pubkey2864E326A5BE488A;
      // better key
      const wrongPubkey =
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: FlowCrypt Email Encryption [BUILD_REPLACEABLE_VERSION]\r\nComment: Seamlessly send and receive encrypted email\r\n\r\nxjMEYZeW2RYJKwYBBAHaRw8BAQdAT5QfLVP3y1yukk3MM/oiuXLNe1f9az5M\r\nBnOlKdF0nKnNJVNvbWVib2R5IDxTYW1zNTBzYW1zNTBzZXB0QEdtYWlsLkNv\r\nbT7CjwQQFgoAIAUCYZeW2QYLCQcIAwIEFQgKAgQWAgEAAhkBAhsDAh4BACEJ\r\nEMrSTYqLk6SUFiEEBP90ux3d6kDwDdzvytJNiouTpJS27QEA7pFlkLfD0KFQ\r\nsH/dwb/NPzn5zCi2L9gjPAC3d8gv1fwA/0FjAy/vKct4D7QH8KwtEGQns5+D\r\nP1WxDr4YI2hp5TkAzjgEYZeW2RIKKwYBBAGXVQEFAQEHQKNLY/bXrhJMWA2+\r\nWTjk3I7KhawyZfLomJ4hovqr7UtOAwEIB8J4BBgWCAAJBQJhl5bZAhsMACEJ\r\nEMrSTYqLk6SUFiEEBP90ux3d6kDwDdzvytJNiouTpJQnpgD/c1CzfS3YzJUx\r\nnFMrhjiE0WVgqOV/3CkfI4m4RA30QUIA/ju8r4AD2h6lu3Mx/6I6PzIRZQty\r\nLvTkcu4UKodZa4kK\r\n=7C4A\r\n-----END PGP PUBLIC KEY BLOCK-----\r\n';
      {
        const decrypted1 = await MsgUtil.decryptMessage({
          kisWithPp: [],
          encryptedData,
          verificationPubs: [signerPubkey, wrongPubkey],
        });
        expect(decrypted1.success).to.equal(true);
        const verifyRes1 = (decrypted1 as DecryptSuccess).signature!;
        expect(verifyRes1.match).to.be.true;
      }
      {
        const decrypted2 = await MsgUtil.decryptMessage({
          kisWithPp: [],
          encryptedData,
          verificationPubs: [wrongPubkey, signerPubkey],
        });
        expect(decrypted2.success).to.equal(true);
        const verifyRes2 = (decrypted2 as DecryptSuccess).signature!;
        expect(verifyRes2.match).to.be.true;
      }
      {
        const decrypted3 = await MsgUtil.decryptMessage({
          kisWithPp: [],
          encryptedData,
          verificationPubs: [signerPubkey],
        });
        expect(decrypted3.success).to.equal(true);
        const verifyRes3 = (decrypted3 as DecryptSuccess).signature!;
        expect(verifyRes3.match).to.be.true;
      }
      {
        const decrypted4 = await MsgUtil.decryptMessage({
          kisWithPp: [],
          encryptedData,
          verificationPubs: [wrongPubkey],
        });
        expect(decrypted4.success).to.equal(true);
        const verifyRes4 = (decrypted4 as DecryptSuccess).signature!;
        expect(verifyRes4.match).to.not.be.true;
      }
      t.pass();
    });

    test('[unit][MsgUtil.verifyDetached] verifies Thunderbird html signed message', async t => {
      const data = await GoogleData.withInitializedData('flowcrypt.compatibility@gmail.com');
      const msg: GmailMsg = data.getMessage('17daefa0eb077da6')!;
      const msgText = Buf.fromBase64Str(msg!.raw!).toUtfStr();
      const sigText = msgText
        .match(/\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-.*\-\-\-\-\-END PGP SIGNATURE\-\-\-\-\-/s)![0]
        .replace(/=\r\n/g, '')
        .replace(/=3D/g, '=');
      const plaintext = msgText
        .match(/Content\-Type: multipart\/mixed; boundary="------------0i0uwO075ZQ0NjkA1rJACksf".*--------------0i0uwO075ZQ0NjkA1rJACksf--\r?\n/s)![0]
        .replace(/\r?\n/g, '\r\n')!;
      const pubkey = plaintext
        .match(/\-\-\-\-\-BEGIN PGP PUBLIC KEY BLOCK\-\-\-\-\-.*\-\-\-\-\-END PGP PUBLIC KEY BLOCK\-\-\-\-\-/s)![0]
        .replace(/=\r\n/g, '')
        .replace(/=3D/g, '=');
      const result = await MsgUtil.verifyDetached({ plaintext, sigText, verificationPubs: [pubkey] });
      expect(result.match).to.be.true;
      t.pass();
    });

    test('[unit][MsgUtil.verifyDetached] verifies Thunderbird text signed message', async t => {
      const data = await GoogleData.withInitializedData('flowcrypt.compatibility@gmail.com');
      const msg: GmailMsg = data.getMessage('17dad75e63e47f97')!;
      const msgText = Buf.fromBase64Str(msg!.raw!).toUtfStr();
      const sigText = msgText
        .match(/\-\-\-\-\-BEGIN PGP SIGNATURE\-\-\-\-\-.*\-\-\-\-\-END PGP SIGNATURE\-\-\-\-\-/s)![0]
        .replace(/=\r\n/g, '')
        .replace(/=3D/g, '=');
      const plaintext = msgText
        .match(/Content\-Type: multipart\/mixed; boundary="------------FQ7CfxuiGriwTfTfyc4i1ppF".*-------------FQ7CfxuiGriwTfTfyc4i1ppF--\r?\n/s)![0]
        .replace(/\r?\n/g, '\r\n')!;
      const pubkey = plaintext
        .match(/\-\-\-\-\-BEGIN PGP PUBLIC KEY BLOCK\-\-\-\-\-.*\-\-\-\-\-END PGP PUBLIC KEY BLOCK\-\-\-\-\-/s)![0]
        .replace(/=\r\n/g, '')
        .replace(/=3D/g, '=');
      const result = await MsgUtil.verifyDetached({ plaintext, sigText, verificationPubs: [pubkey] });
      expect(result.match).to.be.true;
      t.pass();
    });

    test('[unit][MsgUtil.verifyDetached] verifies Firefox rich text signed message', async t => {
      const data = await GoogleData.withInitializedData('flowcrypt.compatibility@gmail.com');
      const msg: GmailMsg = data.getMessage('175ccd8755eab85f')!;
      const msgText = Buf.fromBase64Str(msg!.raw!).toUtfStr();
      const sigBase64 = msgText.match(/Content\-Type: application\/pgp\-signature;.*\r\n\r\n(.*)\r\n\-\-/s)![1];
      const sigText = Buf.fromBase64Str(sigBase64).toUtfStr();
      const plaintext = msgText
        .match(
          /Content\-Type: multipart\/mixed;\r?\n? boundary="\-\-\-\-sinikael\-\?=_2\-16054595384320\.6487848448108896".*\-\-\-\-\-\-sinikael\-\?=_2\-16054595384320\.6487848448108896\-\-\r?\n/s
        )![0]
        .replace(/\r?\n/g, '\r\n')!;
      const result = await MsgUtil.verifyDetached({ plaintext, sigText, verificationPubs: [testConstants.flowcryptcompatibilityPublicKey7FDE685548AEA788] });
      expect(result.match).to.be.true;
      t.pass();
    });

    test(`[unit][MsgUtil.verifyDetached] returns non-fatal error when signature doesn't match`, async t => {
      const sigText = `-----BEGIN PGP SIGNATURE-----

wsB5BAABCAAjFiEEK7IZd28jzkjruGCcID+ucHYAU4EFAmG1nzIFAwAAAAAACgkQID+ucHYAU4H1
9AgAmi5QUmrzlMa/V8SeEv7VydA3v7Hca/EM18o4ot/ygQgS1BoCm9tAajOGWgzo7eEJwDK8LRj2
c/XcKWExxcqkLjiem7CdePbi/xr5jMsPYzOlMtcFaD3zY9h8zabiiGM0kIpT8PVCofgFJMqQdByr
gF0NuioMzAiCY+W9aiaSzquH9FVVE+C4bwsU4leTkANDGi05XBUIYaocNilHnUghG6DyFWS6qYFW
cU4SvRcN5yDDUUjrtFJqp2a2Cs76KgbBr3KQcD42EypUL4/ZS+7/4MN4SA05R/mMtmfK4HwAKcC2
jSB6A93JmnQGIkAem/kzGkKclmfAdGfc4FS+3Cn+6Q==Xmrz
-----END PGP SIGNATURE-----`;
      const data = await GoogleData.withInitializedData('flowcrypt.compatibility@gmail.com');
      const msg = data.getMessage('17dad75e63e47f97')!;
      const msgText = Buf.fromBase64Str(msg!.raw!).toUtfStr();
      {
        const pubkey = msgText
          .match(/\-\-\-\-\-BEGIN PGP PUBLIC KEY BLOCK\-\-\-\-\-.*\-\-\-\-\-END PGP PUBLIC KEY BLOCK\-\-\-\-\-/s)![0]
          .replace(/=\r\n/g, '')
          .replace(/=3D/g, '=');
        const resultRightKey = await MsgUtil.verifyDetached({
          plaintext: 'some irrelevant text',
          sigText,
          verificationPubs: [pubkey],
        });
        expect(resultRightKey.match).to.be.false;
        expect(resultRightKey.error).to.not.be.undefined;
        expect(resultRightKey.isErrFatal).to.not.be.true;
      }
      {
        const resultWrongKey = await MsgUtil.verifyDetached({
          plaintext: 'some irrelevant text',
          sigText,
          verificationPubs: [testConstants.flowcryptcompatibilityPublicKey7FDE685548AEA788],
        });
        expect(resultWrongKey.match).to.be.null;
        expect(resultWrongKey.error).to.be.undefined;
      }
      t.pass();
    });
    /* eslint-enable @typescript-eslint/no-non-null-assertion */

    test('[unit][MsgUtil.getSortedKeys,matchingKeyids] must be able to find matching keys', async t => {
      const passphrase = 'some pass for testing';
      const key1 = await OpenPGPKey.create([{ name: 'Key1', email: 'key1@test.com' }], 'curve25519', passphrase, 0);
      const key2 = await OpenPGPKey.create([{ name: 'Key2', email: 'key2@test.com' }], 'curve25519', passphrase, 0);
      const pub1 = await KeyUtil.parse(key1.public);
      const pub2 = await KeyUtil.parse(key2.public);
      // only encrypt with pub1
      const { data } = await MsgUtil.encryptMessage({
        pubkeys: [pub1],
        data: Buf.fromUtfStr('anything'),
        armor: true,
      });
      const m = await opgp.readMessage({ armoredMessage: Buf.fromUint8(data).toUtfStr() });
      const parsed1 = await KeyUtil.parse(key1.private);
      const parsed2 = await KeyUtil.parse(key2.private);
      const kisWithPp: KeyInfoWithIdentityAndOptionalPp[] = [
        // supply both key1 and key2 for decrypt
        { ...(await KeyUtil.keyInfoObj(parsed1)), passphrase },
        { ...(await KeyUtil.keyInfoObj(parsed2)), passphrase },
      ];
      // we are testing a private method here because the outcome of this method is not directly testable from the
      //   public method that uses it. It only makes the public method faster, which is hard to test.
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore - accessing private method
      const sortedKeys = await MsgUtil.getSortedKeys(kisWithPp, m);
      // point is that only one of the private keys should be used for decrypting, not two
      expect(sortedKeys.prvMatching.length).to.equal(1);
      expect(sortedKeys.signedBy.length).to.equal(0);
      expect(sortedKeys.encryptedFor.length).to.equal(1);
      expect(sortedKeys.prvForDecrypt.length).to.equal(1);
      expect(sortedKeys.prvForDecryptDecrypted.length).to.equal(1);
      // specifically the pub1
      expect(sortedKeys.prvForDecryptDecrypted[0].ki.longid).to.equal(OpenPGPKey.fingerprintToLongid(pub1.id));
      // also test MsgUtil.matchingKeyids
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const matching1 = MsgUtil.matchingKeyids(KeyUtil.getPubkeyLongids(pub1), m.getEncryptionKeyIDs());
      expect(matching1.length).to.equal(1);
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      const matching2 = MsgUtil.matchingKeyids(KeyUtil.getPubkeyLongids(pub2), m.getEncryptionKeyIDs());
      expect(matching2.length).to.equal(0);
      t.pass();
    });

    test('[unit][OpenPGPKey.create] multiple uids', async t => {
      const passphrase = 'some pass for testing';
      const key = await OpenPGPKey.create(
        [
          { name: 'Key1', email: 'key1@test.com' },
          { name: 'Key2', email: 'key2@test.com' },
        ],
        'curve25519',
        passphrase,
        0
      );
      const pub = await KeyUtil.parse(key.public);
      expect(pub.emails[0]).to.equal('key1@test.com');
      expect(pub.identities[0]).to.equal('Key1 <key1@test.com>');
      expect(pub.emails[1]).to.equal('key2@test.com');
      expect(pub.identities[1]).to.equal('Key2 <key2@test.com>');
      t.pass();
    });

    test('[OpenPGPKey.fingerprintToLongid] only works for pgp', async t => {
      // shorten pgp fingerprint to become longid
      expect(OpenPGPKey.fingerprintToLongid('3449178FCAAF758E24CB68BE62CB4E6F9ECA6FA1')).to.equal('62CB4E6F9ECA6FA1');
      // throw on s/mime id
      expect(() => OpenPGPKey.fingerprintToLongid('63F7025E700F3945301FB2FBA5674F84')).to.throw(
        'Unexpected fingerprint format (len: 32): "63F7025E700F3945301FB2FBA5674F84"'
      );
      // throw on broken format
      expect(() => OpenPGPKey.fingerprintToLongid('aaxx')).to.throw('Unexpected fingerprint format (len: 4): "aaxx"');
      t.pass();
    });

    test('[Attachment.sanitizeName] for special and unicode characters', async t => {
      // slash
      expect(Attachment.sanitizeName('abc/def')).to.equal('abc_def');
      // backslash
      expect(Attachment.sanitizeName('abc\\def')).to.equal('abc_def');
      // combinations of slashes and backslashes
      expect(Attachment.sanitizeName('abc\\/def')).to.equal('abc_def');
      expect(Attachment.sanitizeName('abc/\\def')).to.equal('abc_def');
      // trimming
      expect(Attachment.sanitizeName('  1  ')).to.equal('1');
      expect(Attachment.sanitizeName('    ')).to.equal('_');
      // empty
      expect(Attachment.sanitizeName('')).to.equal('_');
      // cyrillic
      const cyrillicName = '\u0410\u0411\u0412';
      expect(Attachment.sanitizeName(cyrillicName)).to.equal(cyrillicName);
      t.pass();
    });

    // public key that allows to encrypt for primary key - to simulate a bug in other implementation that wrongly encrypts for primary when it shouldn't
    // sec  rsa2048/F90C76AE611AFDEE
    //      created: 2020-10-15  expires: never       usage: SCE
    //      trust: ultimate      validity: ultimate
    // ssb  rsa2048/4BA880ECE71397FC
    //      created: 2020-10-15  expires: never       usage: E
    const pubEncryptForPrimaryIsFine = `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQENBF+IL20BCACTJLnno0xB29YeNP9xV4bdkEE0zSo/UoFzRKpUupG+0El17oDw\nQDUeW2YjZwLxMJVlRyo+eongpFYFbC+d5cwiHE/YP6uQPmniiEpa3ICZw87Jk/R2\n5dTAVk9QuAlvkI1lWA0+1SDTFxuWD1LTEjcSS6so8pr2VOF6xFu5QKCkbX0/aQe5\npoHryZ/RkUW4d+B3aTC56RnXSAfeegwn1VDF+J+t0jZ0rMzKs2IaDgqX5HzBqOOI\nlIrr43ROHmceuTMZp19aoLYhFNn1lseyug/YQm4b6Hf6VVypNNUFdgbK8xrxowOq\nb2cgSajgcZVMkTF5IQuyS/IIlobJGZeqZ33nABEBAAG0aVRlc3QgS2V5IFdoZW4g\nTWVzc2FnZSBXcm9uZ2x5IGVuY3J5cHRlZCBmb3IgUHJpbWFyeSBLZXkgPHRlc3Qu\nZmlsZS5lbmNyeXB0ZWQuZm9yLnByaW1hcnkua2V5QGV4YW1wbGUuY29tPokBTgQT\nAQoAOAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgBYhBL+zmJKJcURh2km3GfkMdq5h\nGv3uBQJfjVbfAhsPAAoJEPkMdq5hGv3uqCEH/3gbq7JwKQf0NV0muZysc0aNt000\nG3NtZkuYi83l8JMwlDq50lOMgL7gCngTB9ed822d27ClMsj8eP9XuKtw6e7gpvMc\njMF2rACiQKYuZ0iVUK23Zi0fb17zN0BJ0gJ9BpEv5MjaYJ1G4QZDOKG23a/hVUUv\nfRmwbBynSFMgVWQJHGQ9KcY2Jt8M3sLcxpuPO3QLWGivitbZDB2QrL/fALRQpc1Y\nnNkgdUxpZE5dkos01IR5GjZeSmrYpP7UaHa/O3lCdLiskjtCNwWcTr1yJZdzmbZ4\npw6Hu+kEIiYgmwPNodJpRYxZ8rR6ChJ4q1SE6J3iJ4SlGVdU0TM4L5nuJxy5AQ0E\nX4gvbQEIANUO63F2tdT4zOt8gP2XBZwo8fbI59AEEgBaq7o3sluujAak3mK71LyT\n4S4gvJLyGlAU9TV4JQxRuky6oCcyA1D6PNCYGiR6OJbmmzosrh34bYkfz3xjDu/d\nNAKPDCJz2arcVuVbE5onjQd9afjaZh+4pVKs3lKn1UdBXIrei2LC98CemRWxUwfH\nG0LswvnIg24ByvFBvOzBiB7m9340ComMnKGRpeze8uEubYNNQDexL2zCo2itUFKB\nuPkQbCN7jXg/vnNLk2GXFlUYt20puEH4iyaJ/QFIZzzeqFRQWvI63JJ7zQZIGeok\nS/0MLq1udNYxUqk014TEso0jvC1evX0AEQEAAYkBNgQYAQoAIBYhBL+zmJKJcURh\n2km3GfkMdq5hGv3uBQJfiC9tAhsMAAoJEPkMdq5hGv3usZ4H/1N12NiLOVwQ3Zeq\nVxUocwC/UjZX6JlAPg0h1Spx0RGdNuu4WMLnlF/1yzK+LE84WFYkvXXIzNi1LIyX\nPh3YCPGFEec82MkLQFkLm7sjE4Xc3APYZJK2s5LSjyloZkprb7sbVjdWoBwAPClv\nQsgAlHBeCrlWcLo7fzZdxmpvmJFHd/J7ajKsMCn5f9DXFCoCNdrv+s5Qf4jo6KaE\nhZrQ75+T52Iq9R5Z2gS5G4jY3eW+iK2/xW5Q0x0UeoJG7u8WR56LSl0jS9lufuOS\nyFkO3XIWLzDfz51EVy7ApK33D3GQTfOQ8tJEqW2p17rQTcXuhmg4Dgcf1b0dyVac\n7jV1Tgs=\n=4gfr\n-----END PGP PUBLIC KEY BLOCK-----\n`;
    // a normal keypair
    // sec  rsa2048/F90C76AE611AFDEE
    //      created: 2020-10-15  expires: never       usage: SC
    //      trust: ultimate      validity: ultimate
    // ssb  rsa2048/4BA880ECE71397FC
    //      created: 2020-10-15  expires: never       usage: E
    const prvEncryptForSubkeyOnly = `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n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\n1b0dyVac7jV1Tgs=\n=4Jfy\n-----END PGP PRIVATE KEY BLOCK-----\n`;

    test('[MsgUtil.encryptMessage] do not decrypt message when encrypted for key not meant for encryption', async t => {
      const data = Buf.fromUtfStr('hello');
      const passphrase = 'pass phrase';
      const tmpPrv = await KeyUtil.parse(prvEncryptForSubkeyOnly);
      await KeyUtil.encrypt(tmpPrv, passphrase);
      expect(tmpPrv.fullyEncrypted).to.equal(true);
      const prvEncryptForSubkeyOnlyProtected = KeyUtil.armor(tmpPrv);
      const tmpPub = await opgp.readKey({ armoredKey: pubEncryptForPrimaryIsFine });
      tmpPub.subkeys = [];
      // removed subkey from the pubkey, which makes the structure into this - forcing opgp to encrypt for the primary
      // sec  rsa2048/F90C76AE611AFDEE
      //      created: 2020-10-15  expires: never       usage: SCE
      //      trust: ultimate      validity: ultimate
      const justPrimaryPub = tmpPub.armor();
      const pubkeys = [await KeyUtil.parse(justPrimaryPub)];
      const encrypted = await MsgUtil.encryptMessage({
        pubkeys,
        data,
        armor: true,
      });
      const parsed = await KeyUtil.parse(prvEncryptForSubkeyOnlyProtected);
      const kisWithPp: KeyInfoWithIdentityAndOptionalPp[] = [{ ...(await KeyUtil.keyInfoObj(parsed)), family: parsed.family, passphrase }];
      const decrypted = await MsgUtil.decryptMessage({
        kisWithPp,
        encryptedData: encrypted.data,
        verificationPubs: [],
      });
      // todo - later we'll have an org rule for ignoring this, and then it will be expected to pass as follows:
      // expect(decrypted.success).to.equal(true);
      // expect(decrypted.content!.toUtfStr()).to.equal(data.toUtfStr());
      expect(decrypted.success).to.equal(false);
      expect((decrypted as DecryptError).error.type).to.equal('key_mismatch');
      t.pass();
    });

    test('[KeyUtil.diagnose] correctly displays revoked userid', async t => {
      const key = await KeyUtil.parse(`-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: FlowCrypt Testing Only unspecified

lFgEX6UIExYJKwYBBAHaRw8BAQdAMfHf64wPQ2LC9In5AKYU/KT1qWvI7e7aXr+L
WeQGUKIAAQCcB3zZlHfepQT26LIwbTDn4lvQ9LuD1fk2hK6i9FXFxxO7tBI8dXNl
ckBleGFtcGxlLmNvbT6IjwQQFgoAIAUCX6UIEwYLCQcIAwIEFQgKAgQWAgEAAhkB
AhsDAh4BACEJEEoCtcZ3snFuFiEENY1GQZqrKQqgUAXASgK1xneycW6P6AEA5iXF
K+fWpj0vn3xpKEuFRqvytPKFzhwd4wEvL+IGSPEBALE/pZdMzsDoKPENiLFpboDV
NVJScwFXIleKmtNaRycFiIwEExYIAD4FAmLqt7IJEEoCtcZ3snFuFiEENY1GQZqr
KQqgUAXASgK1xneycW4CngECmwMEFgIBAAYLCQcIAwIEFQgKAgAA7VwA/3x+J0i5
DPaKtiosXHEV3LnOjaDGJgQlj7bR1BD4P62RAP0To1EcOvYk3qdgwda00oDkvYon
aAtVAK9dqadkbOI4D4h7BDAWCAAtBQJi6reyCRBKArXGd7JxbhYhBDWNRkGaqykK
oFAFwEoCtcZ3snFuAocAAh0gAABfXQEAvxCRqQz9r7iyrPyo4R/xF1BajPxoHd0Q
y4GYx/aIq5UA/19k0C/X7tH+fPJEd3Z2QjlrvyTbymUa+z4YGK1rh/YHtA9maXJz
dEBtb2NrLnRlc3SIjwQTFggAQQUCYuq3sgkQSgK1xneycW4WIQQ1jUZBmqspCqBQ
BcBKArXGd7JxbgKeAQKbAwQWAgEABgsJBwgDAgQVCAoCApkBAACNnQEA8tTL+tGS
wC9u4ECmo2Y8AUa0nvvv9+JmiMQphqldxD0A/jkDmtuj+KX8zxArkwC4IKCAFd2G
cdgj1z2/dAKVWmICnF0EX6UIExIKKwYBBAGXVQEFAQEHQBDdeawWVNqYkP8c/ihL
EUlVpn8cQw7rmRc/sIhdAXhfAwEIBwAA/0Jy7IelcHDjxE3OzagEzSxNrCVw8uPH
NRl8s6iP+CQYEfGIeAQYFggACQUCX6UIEwIbDAAhCRBKArXGd7JxbhYhBDWNRkGa
qykKoFAFwEoCtcZ3snFuWp8BAIzRBYJSfZzlvlyyPhrbXJoYSICGNy/5x7noXjp/
ByeOAQDnTbQi4XwXJrU4A8Nl9eyz16ZWUzEPwfWgahIG1eQDDA==
=eyAR
-----END PGP PRIVATE KEY BLOCK-----`);
      expect(key.identities).to.have.length(1);
      expect(key.identities).to.eql(['first@mock.test']);
      expect(key.emails).to.have.length(1);
      expect(key.emails).to.eql(['first@mock.test']);
      const result = await KeyUtil.diagnose(key, '');
      expect(result.get('Primary User')).to.equal('first@mock.test');
      expect(result.get('User id 0')).to.equal('* REVOKED, INVALID OR MISSING SIGNATURE * <user@example.com>');
      expect(result.get('User id 1')).to.equal('first@mock.test');
      t.pass();
    });

    test('[KeyUtil.diagnose] displays PK and SK usage', async t => {
      const usageRegex = /\[\-\] \[(.*)\]/;
      /* eslint-disable @typescript-eslint/no-non-null-assertion */
      const result1 = await KeyUtil.diagnose(await KeyUtil.parse(pubEncryptForPrimaryIsFine), '');
      {
        const pk0UsageStr = result1.get('Usage flags')!;
        const sk0UsageStr = result1.get('SK 0 > Usage flags')!;
        const pk0Usage = pk0UsageStr.match(usageRegex)![1].split(', ');
        expect(pk0Usage).to.include('certify_keys');
        expect(pk0Usage).to.include('sign_data');
        expect(pk0Usage).to.include('encrypt_storage');
        expect(pk0Usage).to.include('encrypt_communication');
        const sk0Usage = sk0UsageStr.match(usageRegex)![1].split(', ');
        expect(sk0Usage).to.not.include('certify_keys');
        expect(sk0Usage).to.not.include('sign_data');
        expect(sk0Usage).to.include('encrypt_storage');
        expect(sk0Usage).to.include('encrypt_communication');
      }
      const result2 = await KeyUtil.diagnose(await KeyUtil.parse(prvEncryptForSubkeyOnly), '');
      {
        const pk0UsageStr = result2.get('Usage flags')!;
        const sk0UsageStr = result2.get('SK 0 > Usage flags')!;
        const pk0Usage = pk0UsageStr.match(usageRegex)![1].split(', ');
        expect(pk0Usage).to.include('certify_keys');
        expect(pk0Usage).to.include('sign_data');
        expect(pk0Usage).to.not.include('encrypt_storage');
        expect(pk0Usage).to.not.include('encrypt_communication');
        const sk0Usage = sk0UsageStr.match(usageRegex)![1].split(', ');
        expect(sk0Usage).to.not.include('certify_keys');
        expect(sk0Usage).to.not.include('sign_data');
        expect(sk0Usage).to.include('encrypt_storage');
        expect(sk0Usage).to.include('encrypt_communication');
      }
      /* eslint-enable @typescript-eslint/no-non-null-assertion */
      t.pass();
    });

    const dsaPrimaryKeyAndSubkeyBothHavePrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
JW/1mKoBRBfyKzP8ibuUyur7X6rryVL/dctxoA==
=Pmsz
-----END PGP PRIVATE KEY BLOCK-----`;

    const rsaPrimaryKeyAndSubkeyBothHavePrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQWFBF+7wagBDADHQ/DNEc16xAUAu6mYzMiNCG5IyzheXtEP2QUtPxEDrxNlOhv3
YyqyJadp5+ycIctVquwmzGRNolfFKDdVR1f7KAr0wpU5gRfH8OyneaHeGFopUpbI
Mk0zjlw9jNtxL6UwXhx6Z50A1mBTdB55ttaLSG+A2FTlCOTN0RV+vX79EFRHNFku
m5xhDQWRH3DVvso20eR7vcHwXSwdNALxPWtzQhmTdri+ThgCZ+uWvn++e98xw/k0
X/uvMoz4ccIqZo5PJgBfSpC8vt8ufCIAtrmb5JXghnxx/dlvL+Z6ebp9vwA7OFML
EV1VBRx5H343TMtQ0rC8U5qW6DMyZ+iSeb2toFYraw2zlTr3XaK5tfHCstsU8EFn
OopISKe32OVKgsEwZdUqdGTERMW6eYf97wRpE3X4Q8kFp5KkAmeDaDL7wPio/F1R
LmbAhr9ZNpFqaIGxJsqy0rzvPrTINOjtuThanmbXDVdj90o9VyyrRABqWM/UB6y7
rhCnVtJ8uTWpImkAEQEAAf4HAwJbB9fwdhhbOe4gLCfaF0wWxuSQieivh1bZy8dx
th77aYxl/xLdY/JQUbAVQPQCTReRs7vTSMbbTHN8aeyi+pCCHx6hT1wHi/pXzJFR
p/Jz/TXUma+prysBIYX4KQsEsehzfIxf7Zg1Y6wEriiwNaWqyM7Zj+VOwd9w2Agu
Q5NF9S+H60IH71+0fWkVV95oGt1LY5uHVaRmu65lGXtpS6qFX/8GrHPk+r204DTY
R2qnzkbfsl4uwmkbNsBxjJAuIsWIBDQx7PVJzf9jZJ/M45lEvvAyueZw6skoc4lY
Q7qzX2UvZY4q+rx00C7Wk5wrjdbruaJZqM4B78VEups00FRnUJazaqJAhX/QiUvh
XgFtGDSPM2lesTehH/JMXMkmPv/ptclCVx7J0jzm+ZWxVNtD1O6ar98mK8O9kdAB
+MwkmC0gOaKvR0sSOi7LKQZAL7QpOV+CWI7oCJfjwX8qRCocVfxoZOCQ9IbO1RqD
7zBr4LoxOJihbqusmfljoKv0Qxq5tNhlsVrPRfAXwzomDBM4lDX22+bpIAAFNRhW
30p6MlhyqdlWI2joOtzu8KgtAZ8kIFJlF6DdtQG8VYA1KB7tOQo8IugZXJnVbnry
2zauq69cL3bILrZmbEc+PpxZmXJZk7+9fei3mk+iWgiXVd2QNlQTDqDRhyQg5OX6
UsOflHkG7ViBn94jO82IDhLYI09MORYVo/IkJMYmpzzL+VY299X2zX5iJU3LNA39
/Q1KuzEsWmbIlR7b8NwSgy8ID3E7mnzNepb1QS8tYfeXCCb2s+kC4SRKHt2D17+C
3xVWqMT5l57eOuGvKXJeDArCAesEBUiS3M9xNTsO+4YBsuNOI6IL6TIF9OExgBxp
UUAOcwWpBu3D13OGxWd3UWuENK/aPT65rnBaarXsvZ2ohJo5pSvVVHO9il+c51O4
C+UoA7sVLXIuyy7dAVdpEFzIFPmOdTqmxrFkjOfyVUrOtDdwdHavs1KYDRgwrR4j
rYbSKpWCc7InChSidvnH6pYwZoUYECYdaLkEm1nmwyLJfzR0J1PNTAmPMJ3gJkgh
CGJKOOFEgThv0JLuF55kS31/KsIJi5PdqZeYJktlavMrxUMAyfomnMX8mg2W0X8J
tSFNb25kHlbXHPLNpHetQJRhucMCRnBGU45r3NLAffSElAeaYUgz32OWc+0gvrm5
tKBmSdIUdw9ZtL5bdYi6wod9ZPsuwQFYZt+A1yj4DNPTBn3pERK0zKwZ+X3P55J8
h0BSAUIEvTaeK6S0KmJ5NkRzvZc+vzGC3bHc5hs2BYD+W8t2owbQAys5yq9AhNxm
Q8rSnC6vXbOCWyfWk5Cq190LzJ24Y47CtDNUZXN0MSAocnNhKSA8Zmxvd2NyeXB0
LnRlc3Qua2V5LmltcG9ydGVkQGdtYWlsLmNvbT6JAc4EEwEIADgWIQRmKF+EuYVx
vQHAGO6LO7nPxHbuFgUCX7vBqAIbAwULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAK
CRCLO7nPxHbuFtwsC/0RtBl6z9QZupZ4jozZ4EuGQRs9dDVkgHmYF9H9Oy1bZRQf
Di72uRzukAaSvfTgiTYC9toa1jwAdDU2CgEzrMp3F+u2IckUd7yof1TtiBE/SVJx
Vd9zeRn6Oo5sQ8fvwMGvGPZ8TDfsXnwvDJyw16ILVUF/fX44kx51HrQNUaKnen96
dawrpzGw5O7Uu+/Jeiup2Fj8KHZ4V0BlWa3HaGLWpL1gxElLvBVrX5BxNXo0C/WI
LLg1cp731CROQSRI4LSSnzhNCMPLdMgNgIDWAJKAK/Fm9717ar30hqPJ/pg5T2G9
ttm2JKQB1wYTgQ7j0l7jrnJ2OY6UjXZn0M592fKj0Le4R/6cjmVAez9Hkc92oKIF
7TLPVGQkNEzt/LKCMx9xTLQw8oRo+tvcbW+ZX8yTgZXDrpqsDKhiQrpa7AiCbUvt
DgXULFAYnjD8dI/44lcyVel4m5nrwfGjEcGTwwqtPHirXgk7Er/0FVST/BbIFu0T
MYCInvRy8I56WcyhFj2dBYYEX7vBqAEMANYJv49i4OvEr1IWvQqijKcwfGcnZf/y
6lTdSwzQYhW9IspC4PSpkoZayj1ei0CZnZti/nFR/uTWYtnDx0DEveY7yBmyNMLX
5g++GLjBXBAGO061uaO9SA1lbo1eUOoV6pRzrtxBH7ZVFf9Gup8+NvGUEUOU3D8j
VKinb+Chjao1vmANufDwqUdKi8c39GRedjgt2GzJcT+uh2AQqn1AZAJaRDfZGtol
kujgq1oD6zQtUPaf//mc7kiy53cZ79/zMzC2U1asMc0QEZd7pEeJY2kHVqiNL4Yb
Hv1xpeBJr+JeIwZu0JHwIWfRbroiVc068y9C8cHe7Ar45WVGtZD8zEYPK+1fN0Vr
BCstpT03hIuJA2tWAjKrfkxG5wer+RIgWWAATGXnBRbq2GSTop09ESI7xVqMYCaP
YpyFGgeMxR/KiX5pGBD4pz5oviMXp9KxjLpoC+hc3QYGHHDvRrvcal0wOVfssTrC
uZDJ5yBGvGLuRGFpSipGxtJ6HIb1G8HXMwARAQAB/gcDAicwXmen244W7sWY9C5F
YYz0M+jzPGUd0U7RGbTIJ1CaMSifCWObWPg3+SgVmM6wg62VUu5034S7glV6DuDD
xEPvIR5dlD2dU1iUx8BEVoeEW/Wxn8Unxwtc1y2VavpVqJvTCwGFzYqxkGt6nteg
m1CbohjPX1YHxtmxsPnXGJpokSQEWN6t1zwrN/iWkVLCUdLXGrLnRMsE8NFrX3d4
oiIUyUB8MnWaDhTkAPjYrlibSgS6q1uUWqlnijF9MrcP4B+2BLedAb0xE2e40GNA
WTb1Uw1BksDUI00V+hfgGOuXaP4hvyGnOEM4tgMOFFkzXGcqI2hKb+0UgDyyldZZ
o6wxchXRM0nrPzkZSOS+r/IVwLi02HoOo05G1IvCZ2HvL+YyqpHV6Jg6swMnwTYN
8aENtC4GGxhtrK1pH3q73+Lo9asTxVYxrqJkjJ6DueUDd/bSv35l36wUwRdi4bhJ
Bke7maU6Muz++oTpWFLVjpS/utF0SI4Hnu70H/ZRzgwW4X22b1Qgb3iZHKKgOclV
+f8q01EXOo+XE2PrmzLjMMOC9YfWhJvboj48PJfFHHJFRrLSvuV6skHlLpmzSB+W
i1Gh26sjRvQBwShBWfBwZ11pnScbik1jTunNIxAQETZDD1YKOJDWDz05UNbyBSe+
WEJSAsiDDtvU9D6mFBm+4BRidnxEmmkYiHHGuKm2dYIX8ecTrCoS9wihQBarth/r
6eF+xG/60wMl/QHAuoKhetFo8arKuWD6t4oHKpgLtUnEllElatlPjdoo4VRQzhRV
NXt9sqEVdhmzL17tqxKl67yYJDtbNsx60qevIeh1ALVRtp5tTLsDXSZyNdjIeggc
GPz6xe2e8ejwBUeyIWtnyXLJJLA6ozmd9Z9fFTVJsfb82McWJpaw/zXfE30YpB4v
xs1GYuUyhAMIh8fYWeUYWZcqkcfzSxz4sxRUz7jVg0W30dR3hx8GlSWOhgBp7U1R
+WNzVd0vtbSCPKxIW7iEghsTigFAfPfIk546PNwCPaeIkCMNs/EE8BguttCa8x7s
4Fcz7WWq03/wm5+yhsSxCpt6pgWxvRgoReCwNPFtcVavsO9K+h7E0HI/1ttK1JsR
shS71RL4FF1Ufr/NW+IUIQxT/0H2hftzKqG14yOrWA7AoC1f5onYAAreFqLyjOBl
ER60nAE03IHVUpWh6+VAJ8/+R05Fic0HYy+zrYGWJWQAlqzqCJL4MNNzAzJRFeBv
BD/jxb3KWLcUKqPT7jD1huWM3YW6I8yqqAkg5zVd8x89R/nibTLdZWWqLf1x/k3Z
0fRgLnDM2iAHywI2ePSaI3u6iMHSmWYB0jAQag2+uMa+dMPbI/+ciQG2BBgBCAAg
FiEEZihfhLmFcb0BwBjuizu5z8R27hYFAl+7wagCGwwACgkQizu5z8R27hbgjwv+
IV4aA+UyMgrENYbOV57TJde65wH8PRLptSX2FUudhYDemt5ePiKH0A65uWTsNKlo
xOcHioS6E5Q0i5ShD1PXHekAtPwc3BVBWOLi/f4KmPwhGt91NdHMQHSCYPOT3EBH
RNjzlQevW0WoSzsakBiKCo6AA/E5GloKORXMsGIOEkTIHMi+08yRS1cZkmalYlRZ
GriWiq1nFAfDBYhOrzBoRA2D+M2AXENgV8yeAp4VRwhdkcWyjxx4aM3rpUoEEWRP
Exgw6RqT8St8oQl0NZVORgyf8hWI1+4SGMbK9CmRyXDgua5gzUyf00NsLRheRQHm
ZAvn6PBX7vsaReOVa2zsnuY5g70xCxvzHIwR94POu5cENwRtCkrppFnISALpQ1kA
648mPMRkXUOCAfqKrQb6ANWnMHOdtvAo/GCil97MprUTiJpwKYuhKcanVMTXewzZ
3YPiV3VO3n30KQDDVSc5BUdGuphu48qQh/5BQoKOiVVL2451m7VJTMREmB/YRmSg
=/3Ew
-----END PGP PRIVATE KEY BLOCK-----`;

    test('[KeyUtil.diagnose] handles incorrect passphrase', async t => {
      const result = await KeyUtil.diagnose(await KeyUtil.parse(rsaPrimaryKeyAndSubkeyBothHavePrivateKey), '4321');
      expect(result.get('Is Private?')).to.equal('[-] true');
      expect(result.get('User id 0')).to.equal('Test1 (rsa) <flowcrypt.test.key.imported@gmail.com>');
      expect(result.get('Primary User')).to.equal('Test1 (rsa) <flowcrypt.test.key.imported@gmail.com>');
      expect(result.get('Fingerprint')).to.equal('6628 5F84 B985 71BD 01C0 18EE 8B3B B9CF C476 EE16');
      expect(result.get('Subkeys')).to.equal('[-] 1');
      expect(result.get('Primary key algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('key decrypt')).to.equal('[-] INCORRECT PASSPHRASE');
      expect(result.get('isFullyDecrypted')).to.equal('[-] false');
      expect(result.get('isFullyEncrypted')).to.equal('[-] true');
      expect(result.get('Primary key verify')).to.equal('[-] valid');
      expect(result.get('Primary key creation?')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('Primary key expiration?')).to.equal('[-] -');
      expect(result.has('Encrypt/Decrypt test: Encryption with key was successful')).to.be.true;
      expect(result.has('Encrypt/Decrypt test: Skipping decryption because isPrivate:true isFullyDecrypted:false')).to.be.true;
      expect(result.get('Sign/Verify test')).to.equal('[-] skipped, not fully decrypted');
      expect(result.get('SK 0 > LongId')).to.equal('[-] 0485D618EAA64B05');
      expect(result.get('SK 0 > Created')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('SK 0 > Algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('SK 0 > Verify')).to.equal('[-] OK');
      expect(result.get('SK 0 > Subkey object type')).to.equal('[-] SecretSubkeyPacket');
      expect(result.get('SK 0 > Subkey getBitSize')).to.equal('[-] 3072');
      expect(result.get('SK 0 > Subkey decrypted')).to.equal('[-] false');
      expect(result.get('SK 0 > Binding signature length')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Key flags')).to.equal('[-] 12');
      expect(result.get('SK 0 > SIG 0 > Version')).to.equal('[-] 4');
      expect(result.get('SK 0 > SIG 0 > Public key algorithm')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Sig creation time')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('SK 0 > SIG 0 > Sig expiration time')).to.equal('[-] -');
      expect(result.get('SK 0 > SIG 0 > Verify')).to.equal('[-] valid');
      expect(result.get('expiration')).to.equal('[-] undefined');
      expect(result.get('internal dateBeforeExpiration')).to.equal('[-] undefined');
      expect(result.get('internal usableForEncryptionButExpired')).to.equal('[-] false');
      expect(result.get('internal usableForSigningButExpired')).to.equal('[-] false');
      t.pass();
    });

    test('[KeyUtil.diagnose] decrypts and successfully tests PK sign and SK encrypt', async t => {
      const result = await KeyUtil.diagnose(await KeyUtil.parse(rsaPrimaryKeyAndSubkeyBothHavePrivateKey), '1234');
      expect(result.get('Is Private?')).to.equal('[-] true');
      expect(result.get('User id 0')).to.equal('Test1 (rsa) <flowcrypt.test.key.imported@gmail.com>');
      expect(result.get('Primary User')).to.equal('Test1 (rsa) <flowcrypt.test.key.imported@gmail.com>');
      expect(result.get('Fingerprint')).to.equal('6628 5F84 B985 71BD 01C0 18EE 8B3B B9CF C476 EE16');
      expect(result.get('Subkeys')).to.equal('[-] 1');
      expect(result.get('Primary key algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('key decrypt')).to.equal('[-] success');
      expect(result.get('isFullyDecrypted')).to.equal('[-] true');
      expect(result.get('isFullyEncrypted')).to.equal('[-] false');
      expect(result.get('Primary key verify')).to.equal('[-] valid');
      expect(result.get('Primary key creation?')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('Primary key expiration?')).to.equal('[-] -');
      expect(result.has('Encrypt/Decrypt test: Encryption with key was successful')).to.be.true;
      expect(result.has('Encrypt/Decrypt test: Decryption with key succeeded')).to.be.true;
      expect(result.get('Sign/Verify test')).to.equal('[-] sign msg ok|verify ok');
      expect(result.get('SK 0 > LongId')).to.equal('[-] 0485D618EAA64B05');
      expect(result.get('SK 0 > Created')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('SK 0 > Algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('SK 0 > Verify')).to.equal('[-] OK');
      expect(result.get('SK 0 > Subkey object type')).to.equal('[-] SecretSubkeyPacket');
      expect(result.get('SK 0 > Subkey getBitSize')).to.equal('[-] 3072');
      expect(result.get('SK 0 > Subkey decrypted')).to.equal('[-] true');
      expect(result.get('SK 0 > Binding signature length')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Key flags')).to.equal('[-] 12');
      expect(result.get('SK 0 > SIG 0 > Version')).to.equal('[-] 4');
      expect(result.get('SK 0 > SIG 0 > Public key algorithm')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Sig creation time')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('SK 0 > SIG 0 > Sig expiration time')).to.equal('[-] -');
      expect(result.get('SK 0 > SIG 0 > Verify')).to.equal('[-] valid');
      expect(result.get('expiration')).to.equal('[-] undefined');
      expect(result.get('internal dateBeforeExpiration')).to.equal('[-] undefined');
      expect(result.get('internal usableForEncryptionButExpired')).to.equal('[-] false');
      expect(result.get('internal usableForSigningButExpired')).to.equal('[-] false');
      t.pass();
    });

    const dsaPrimaryKeyIsMissingPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
oA==
=e6+m
-----END PGP PRIVATE KEY BLOCK-----`;

    const rsaPrimaryKeyIsMissingPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=OeNi
-----END PGP PRIVATE KEY BLOCK-----`;

    const dsaExpiredPubkeysOnly = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQMuBF+32zERCACS4joBHUWYAKIMZ39mK6NXc7wgaRP4fz2cm8YL6NHgWAwKTjcp
Ik+VBOAQWGdDq9/iuQwDQNzX2jXAj+i+Ycsx8Ro59DlUexN1kmGyUoE4EVFU6tm4
IwpPiye9b+xboCUYcdTug/KXTgk1znzcmxy31h9sZvkjOin0IHUQTkNYbYJV1GzL
ZeUaF5axdjXmdz7aBH+/Z+FL4KA6ec6/0Thb4o3ls9eYz1lq8axhp7ZLww0fwO5F
gXKwEQC3xjeco4V2YfDFXWbjPqYEw/OujvuBm3Sk+ezbztcFeqU9DiaDRWA8CzUC
ZzUku0+0yaWSEhw/MXZ1/ggcngfdDoOHD3RvAQC0d5heEQOXI/LrBrMLwhGTRMQ5
WuzadW6qmSzZl7PaKwf+KT87eUkHQLfVHxKzN2OHkfnZaXkg9uKSPXtbTzKpiWBO
pRBb42iRZsoyRz4j177SKHA9354J7uOuxaB9Tpj8a4tYbirnMkD3vdW3bxyFfytR
cPPk69gVzRBE/LvgUXmzn8F1E92FyeomNQriPgbwaxcIxZhh7zf64tDzXeqyjavt
qeCIEz1pUzTkHpBAGPqxxPfiilKj675r4+2C4ELM7hroAw8SGWhEY52cdQ/h7+sD
GFdxiwo4NXrGnnj8YUtnL4XytEsDTaa8x2jyB+4wL3y90G+89onj2jiQJmFy7VMz
Oql9qfNLH9WU95UaPnETnM6Qdopb2xhr54FLxwJHJQf+ICuftpIaTZrlrSQ3QwAr
BtPRNDAouCsF9yOV1IVg0M6oH1IO149WlSJ+DSj6mdVW+3mh9MR+LEqsLBsc+kpu
VMvBkYnkxQLeKMnn5OAYdy2/w4+wLGHW6Zk0g1+41uNiX/TD40Rbals4AOwS/Cfv
hMyYlEFFHWzc3Gd3oFWAnH4HlBkex+Vj9Z+mnugr5evNzJUjp/zysgyCQLpO5qR1
X9n7+ccxShpQVkeoj34PCT2YAgxoozdEICL6fyPHLmAAU4s2JJpcFj9Hpr05eBN3
f1K5wCzIgBu7Y0QXPubPp+MeVhQCvYczHr9sMh8EuU7LeuadS97p6ao/DHr9DRl+
YbQ4RFNBIGV4cGlyZWQgVGVzdCA8Zmxvd2NyeXB0LnRlc3Qua2V5LmltcG9ydGVk
QGdtYWlsLmNvbT6IlgQTEQgAPhYhBNKQyfMICB8GxBIEtv59tSXBN1FbBQJft9sx
AhsDBQkAAVGABQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEP59tSXBN1FbBqUA
/jcJMWGvBv9SaMBW1zhzwGpJm5jEpt3oPGNMTccCX+7nAQCWTdmehp4yYZnGkGRc
Y75OpvAHHJ6VouBO76vFiRDx9LkCDQRft9sxEAgAm6CMWettPQ2elDOaGSAxsf+x
aCuOZk5w6wgDOIc5YilYlZ+rZ68Aj3mPk9ZGyLhxP4FPZ9GExw/CbbqJ3r3n4ODD
yz9tCsnkzdgOIIEiihB4GGz3NetE94RQBS/bW2MQC5G74uBhKDU00kzVSdlk1KW4
9gkYmIF22AGf+kr2/H6idijSc13M1jzm6kyzkOdVEnLiDXEZH7Qr9Kr3gqA7UqY6
wl1zoJj4SJdUetj9uemK2gSaoh3BIlW7vRVoa8khhWNF/WJdwNV5UcBX1HyoIzxt
353JQSplv4MJKl8HusO7HpF7oxiRyTgG5vJUnHH8tIONFiY8XENlsMbE7EKaTwAD
BQgAlT6U5z95raOQe4uQEymCpcER1kaZjRKvu85FqKMX41+gdEGQZKCB31FDVg7a
/xplZBPYsA6ihCbExPkP7pyusOhQIShh77QXlIWUli5DWSTJH8SbvzOP1Hg+GHlI
ysBmhdbaB2h42Rsrro9VLLqq+m8X8sSiUnBh4BUjRS5fLkdZ9E9AjDeff0jW0HUK
9vLAtkvRy7UtGabMfCHBokEHQSvN2NfSPJbhoFcgZXI7lqt9z+CYUT0H5jHJb45k
1QjLdGfZiP2WwUfS5mP4cmuIUXZ9UYQatUlReRmM0fXmsGZQDFUSqc7YEFaaPJSP
VrYJTH3cgSYPB+zPHA3CeWrQa4h+BBgRCAAmFiEE0pDJ8wgIHwbEEgS2/n21JcE3
UVsFAl+32zECGwwFCQABUYAACgkQ/n21JcE3UVtmdAD/cwfwJUquz6WQtolRb1RI
kSoBm4IgVS+PkLG2wt1GHVMA/1nhkJ6Veumyy4ldoSRdomImB9gjwHoCqWT+qXqe
h4nt
=lETP
-----END PGP PUBLIC KEY BLOCK-----`;

    const rsaExpiredPubkeysOnly = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF+323wBCADulm2pzzTL0gY/fMbYNHgq72j6XvNic4WncU8WDxytfnPNKqFI
fJcWXPq8QBQIK8pwBRm4vHu5q7fDpId+c8pdZ3kVG2JQvWEFO83q4YJGEWPnLYYY
6le9vSXTWQ7la24aTAEHfH17BdMIGET/so+owRzkBpUl72JuSuarQJJl3ePmu2Iv
KaD2xSc0G2wm++ywZa255PHC4VmZ0lQ2xlZdGZPEWfSDVTchpHvPLQe0vSI/Eg4Q
tRQYlYfLCQuOmkrCV+jqAsbDMHTNF2yE//CnlPA8unjLNdmw6DVhO85F3TIWR5NI
1LOvxEc9MDsWqMuMizzHnnSAnPdLo/sm/fHtABEBAAG0OFJTQSBleHBpcmVkIFRl
c3QgPGZsb3djcnlwdC50ZXN0LmtleS5pbXBvcnRlZEBnbWFpbC5jb20+iQFUBBMB
CAA+FiEEQUF/y80YjGYEme19zhZF0KSimP0FAl+323wCGwMFCQABUYAFCwkIBwIG
FQoJCAsCBBYCAwECHgECF4AACgkQzhZF0KSimP1rGAgAw/GI6PbRstEBiZs9udv0
GttgIU4KnZh9jkr77JWRIH/MGrg2mTXazNt6LdlzOYPUdqB9bYo6tZnLox4x6tQK
8y9TOOXgGcqdiridnEmb2W4eDGN9bfbbDf2c702u+EpITEiSwOi/ResDSsnqFpHJ
sPf4wRrcPpwuecruDaEzPMAyziamWboCgpOzczjod935rhGXsCTcR6BausslmkOW
pUGWtpHw0QZWaHCxt3uUL9gMNNpn5Xmb2Qas2sJQPpSm441fgY7UUig7IoEp5tsp
QZYG85PeUSV8387h3HUjwRsePxcyAZlkAlexC6Hj9w8LrTLMEQsyoFY2D/dSRSCx
e7kBDQRft9t8AQgAwZUUmA8/e18vMWWiaNDhDro7g5XaETe/bCJfxBwmOtig8oin
ghJuDxejzK4B63VoQ3c4VDdl0rQb3utjS1bBZz0piJadtDAefbGIJL5yp6QT2bq7
DCDWuNssrmbBe3SksgqGSehY5SPQD6juKtbPdeD17QsfuBolsh1yQgqW0S5tbB5i
YUCrIJupbdKITR6dtgSOcDntIrktPk26iAq/9PdVQ218dM79SPgxzUugEsyTlUJe
7CFrkNLrIVuHRAycHGZniIAnw0MWZBtTPY3XYkVyt2TXrE97A854HLP1lvhL0/py
q/bfBXvrFONdlep03ZKNraY6BdrCnaSxHPI53QARAQABiQE8BBgBCAAmFiEEQUF/
y80YjGYEme19zhZF0KSimP0FAl+323wCGwwFCQABUYAACgkQzhZF0KSimP0btQgA
qH4mtWTOtanrs3zS+ORrZzlZacydNfX7BFqbrWBNx3Qn4ZUMYzroyXXrBKU2a0Ek
Wtn6JZO+3KF7NLjDKbPTP9oKA0RnBCxcEqd+Zt28+3g413RVOg/3GZ6cwctpmZId
PzBbLiMWVh9yhWNXKhwCNcjRNRiEp5eMsMo7xrvIMwT1dZWo3B1SU8ojcadRAQpB
jzIGNwXIlC7ENE5V8LyvJmFlI3Y54EiylEkXbycrAtaCtcOc8VI97dcej0A5vx+B
sGZik43btY7ooSmvfw154LBqk6j9bps8KS++T3ng2m62kWFelbR8ybjJmFkeDIdM
31rxxiAYCGthro8UvpKojA==
=AZcU
-----END PGP PUBLIC KEY BLOCK-----`;

    const dsaExpiredPrimaryKeyIsMissingPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
qWT+qXqeh4nt
=/Vbx
-----END PGP PRIVATE KEY BLOCK-----`;

    const rsaExpiredPrimaryKeyIsMissingPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
jA==
=lAqt
-----END PGP PRIVATE KEY BLOCK-----`;

    test('[KeyUtil.diagnose] decrypts and tests PK missing private key and SK with private key', async t => {
      const result = await KeyUtil.diagnose(await KeyUtil.parse(rsaPrimaryKeyIsMissingPrivateKey), '1234');
      expect(result.get('Is Private?')).to.equal('[-] true');
      expect(result.get('User id 0')).to.equal('Test1 (rsa) <flowcrypt.test.key.imported@gmail.com>');
      expect(result.get('Primary User')).to.equal('Test1 (rsa) <flowcrypt.test.key.imported@gmail.com>');
      expect(result.get('Fingerprint')).to.equal('6628 5F84 B985 71BD 01C0 18EE 8B3B B9CF C476 EE16');
      expect(result.get('Subkeys')).to.equal('[-] 1');
      expect(result.get('Primary key algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('key decrypt')).to.equal('[-] success');
      expect(result.get('isFullyDecrypted')).to.equal('[-] true');
      expect(result.get('isFullyEncrypted')).to.equal('[-] false');
      expect(result.get('Primary key verify')).to.equal('[-] valid');
      expect(result.get('Primary key creation?')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('Primary key expiration?')).to.equal('[-] -');
      expect(result.has('Encrypt/Decrypt test: Encryption with key was successful')).to.be.true;
      expect(result.has('Encrypt/Decrypt test: Decryption with key succeeded')).to.be.true;
      expect(result.get('Sign/Verify test')).to.equal('[-] Exception: Error: Cannot sign with a gnu-dummy key.');
      expect(result.get('SK 0 > LongId')).to.equal('[-] 0485D618EAA64B05');
      expect(result.get('SK 0 > Created')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('SK 0 > Algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('SK 0 > Verify')).to.equal('[-] OK');
      expect(result.get('SK 0 > Subkey object type')).to.equal('[-] SecretSubkeyPacket');
      expect(result.get('SK 0 > Subkey getBitSize')).to.equal('[-] 3072');
      expect(result.get('SK 0 > Subkey decrypted')).to.equal('[-] true');
      expect(result.get('SK 0 > Binding signature length')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Key flags')).to.equal('[-] 12');
      expect(result.get('SK 0 > SIG 0 > Version')).to.equal('[-] 4');
      expect(result.get('SK 0 > SIG 0 > Public key algorithm')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Sig creation time')).to.equal('[-] 1606140328 or 2020-11-23T14:05:28.000Z');
      expect(result.get('SK 0 > SIG 0 > Sig expiration time')).to.equal('[-] -');
      expect(result.get('SK 0 > SIG 0 > Verify')).to.equal('[-] valid');
      expect(result.get('expiration')).to.equal('[-] undefined');
      expect(result.get('internal dateBeforeExpiration')).to.equal('[-] undefined');
      expect(result.get('internal usableForEncryptionButExpired')).to.equal('[-] false');
      expect(result.get('internal usableForSigningButExpired')).to.equal('[-] false');
      t.pass();
    });
    test('[KeyUtil.diagnose] decrypts and tests RSA1024 PK and RSA1024 SK', async t => {
      const result = await KeyUtil.diagnose(await KeyUtil.parse(testConstants.rsa1024secret), '');
      expect(result.get('Is Private?')).to.equal('[-] true');
      expect(result.get('User id 0')).to.equal('rsa1024@test');
      expect(result.get('Primary User')).to.equal('rsa1024@test');
      expect(result.get('Fingerprint')).to.equal('E9A0 AD72 11FE 7E37 2DCE 62AC 672C 24E1 38A0 37F4');
      expect(result.get('Subkeys')).to.equal('[-] 1');
      expect(result.get('Primary key algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('Primary key verify')).to.equal('[-] valid');
      expect(result.get('Primary key creation?')).to.equal('[-] 1611140945 or 2021-01-20T11:09:05.000Z');
      expect(result.get('Primary key expiration?')).to.equal('[-] -');
      expect(
        result.has(
          'Encrypt/Decrypt test: Got error performing encryption/decryption test: Error: Error encrypting message: Could not find valid encryption key packet in key 672c24e138a037f4: RSA keys shorter than 2047 bits are considered too weak.'
        )
      ).to.be.true;
      expect(result.get('Sign/Verify test')).to.equal(
        '[-] Exception: Error: Could not find valid signing key packet in key 672c24e138a037f4: RSA keys shorter than 2047 bits are considered too weak.'
      );
      expect(result.get('SK 0 > LongId')).to.equal('[-] 2C322F7709C13B10');
      expect(result.get('SK 0 > Created')).to.equal('[-] 1611140946 or 2021-01-20T11:09:06.000Z');
      expect(result.get('SK 0 > Algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('SK 0 > Verify')).to.equal('[-] OK');
      expect(result.get('SK 0 > Subkey object type')).to.equal('[-] SecretSubkeyPacket');
      expect(result.get('SK 0 > Subkey getBitSize')).to.equal('[-] 1024');
      expect(result.get('SK 0 > Subkey decrypted')).to.equal('[-] true');
      expect(result.get('SK 0 > Binding signature length')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Key flags')).to.equal('[-] 12');
      expect(result.get('SK 0 > SIG 0 > Version')).to.equal('[-] 4');
      expect(result.get('SK 0 > SIG 0 > Public key algorithm')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Sig creation time')).to.equal('[-] 1611140947 or 2021-01-20T11:09:07.000Z');
      expect(result.get('SK 0 > SIG 0 > Sig expiration time')).to.equal('[-] -');
      expect(result.get('SK 0 > SIG 0 > Verify')).to.equal('[-] valid');
      expect(result.get('expiration')).to.equal('[-] undefined');
      expect(result.get('internal dateBeforeExpiration')).to.equal('[-] undefined');
      expect(result.get('internal usableForEncryptionButExpired')).to.equal('[-] false');
      expect(result.get('internal usableForSigningButExpired')).to.equal('[-] false');
      t.pass();
    });
    test('[KeyUtil.diagnose] decrypts and tests secure PK and insecure SK', async t => {
      const result = await KeyUtil.diagnose(await KeyUtil.parse(testConstants.rsa1024subkeyOnly), '');
      expect(result.get('Is Private?')).to.equal('[-] true');
      expect(result.get('User id 0')).to.equal('rsa1024subkey@test');
      expect(result.get('Primary User')).to.equal('rsa1024subkey@test');
      expect(result.get('Fingerprint')).to.equal('B804 AF5A 259A 6673 F853 BEB2 B655 50F5 77CF 5CC5');
      expect(result.get('Subkeys')).to.equal('[-] 1');
      expect(result.get('Primary key algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('Primary key verify')).to.equal('[-] valid');
      expect(result.get('Primary key creation?')).to.equal('[-] 1611500681 or 2021-01-24T15:04:41.000Z');
      expect(result.get('Primary key expiration?')).to.equal('[-] -');
      expect(
        result.has(
          'Encrypt/Decrypt test: Got error performing encryption/decryption test: Error: Error encrypting message: Could not find valid encryption key packet in key b65550f577cf5cc5: RSA keys shorter than 2047 bits are considered too weak.'
        )
      ).to.be.true;
      expect(result.get('Sign/Verify test')).to.equal('[-] sign msg ok|verify ok');
      expect(result.get('SK 0 > LongId')).to.equal('[-] 1453C9506DBF5B6A');
      expect(result.get('SK 0 > Created')).to.equal('[-] 1611500698 or 2021-01-24T15:04:58.000Z');
      expect(result.get('SK 0 > Algo')).to.equal('[-] rsaEncryptSign');
      expect(result.get('SK 0 > Verify')).to.equal('[-] OK');
      expect(result.get('SK 0 > Subkey object type')).to.equal('[-] SecretSubkeyPacket');
      expect(result.get('SK 0 > Subkey getBitSize')).to.equal('[-] 1024');
      expect(result.get('SK 0 > Subkey decrypted')).to.equal('[-] true');
      expect(result.get('SK 0 > Binding signature length')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Key flags')).to.equal('[-] 12');
      expect(result.get('SK 0 > SIG 0 > Version')).to.equal('[-] 4');
      expect(result.get('SK 0 > SIG 0 > Public key algorithm')).to.equal('[-] 1');
      expect(result.get('SK 0 > SIG 0 > Sig creation time')).to.equal('[-] 1611500699 or 2021-01-24T15:04:59.000Z');
      expect(result.get('SK 0 > SIG 0 > Sig expiration time')).to.equal('[-] -');
      expect(result.get('SK 0 > SIG 0 > Verify')).to.equal('[-] valid');
      expect(result.get('expiration')).to.equal('[-] undefined');
      expect(result.get('internal dateBeforeExpiration')).to.equal('[-] undefined');
      expect(result.get('internal usableForEncryptionButExpired')).to.equal('[-] false');
      expect(result.get('internal usableForSigningButExpired')).to.equal('[-] false');
      t.pass();
    });

    test('[unit][KeyUtil.parse] correctly handles signing/encryption detection for PKSK with private keys', async t => {
      // testing encrypted key
      const encryptedKey = await KeyUtil.parse(rsaPrimaryKeyAndSubkeyBothHavePrivateKey);
      expect(encryptedKey.usableForSigning).to.be.true;
      expect(encryptedKey.missingPrivateKeyForSigning).to.be.false;
      expect(encryptedKey.usableForEncryption).to.be.true;
      expect(encryptedKey.missingPrivateKeyForDecryption).to.be.false;
      expect(await KeyUtil.decrypt(encryptedKey, '1234')).to.be.true;
      const armoredKey = KeyUtil.armor(encryptedKey);
      // testing decrypted key
      const key = await KeyUtil.parse(armoredKey);
      expect(key.usableForSigning).to.be.true;
      expect(key.missingPrivateKeyForSigning).to.be.false;
      expect(key.usableForEncryption).to.be.true;
      expect(key.missingPrivateKeyForDecryption).to.be.false;
      t.pass();
    });

    test('[unit][KeyUtil.decrypt] validates the private key', async t => {
      const corruptedRsaKey = await KeyUtil.parse(`-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Corrupted encrypted RSA private key
Comment: Passphrase is 123

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
=kFcl
-----END PGP PRIVATE KEY BLOCK-----`);
      await t.throwsAsync(() => KeyUtil.decrypt(corruptedRsaKey, '123'), {
        instanceOf: Error,
        message: 'Key is invalid',
      });
      t.pass();
    });

    const unencryptedCorruptedRsaKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: FlowCrypt Email Encryption [BUILD_REPLACEABLE_VERSION]
Comment: Seamlessly send and receive encrypted email

xcLYBGHcWwkBB/9lhOJ0DQdAaHcrKa50W92WvoH5jBZEKsPrNmefmSol74M1
MZ+afc9NvCZmFZZLrjcQ6lCFIFExWEmq5LNMKo7J7gR533MfqQMX1q0SP2z0
4NZqQoFn/SU3oQ9ZsmN/uqWXPZvN54DcMDGdUmJurRaGQB9PN4aJOljfy0bh
kolS62Nm2A3emsfoaCLxPYBx0R1Mb2mQKgBw40J9bY+5G8fob5G9y2RUrpBu
z/PZwPAaacSbBzs1LKIUsZ3iBaT2k3wzbORq8Ex2uJ1PYbky2q/v1aUJ2ctx
vFXGY3mSB1iUluMfL/xlJr1N+ooNEA0NOzUOgff8f+vRHLNzpZskGJ7DABEB
AAEAB/9OHQssMK6YBXPn1n3XD9gBwPLwFa7C+FmQ++yukuz00rQz5oddGr+H
hb8NIS6niDE0bw13QQ2QEOhyrfigJNUqkDZqgSz0CS0Shh1/DKxsDFpnNa6d
SCvyO9jDxohN37BQ3dTR+9rYUGqwRn681dhOdOHxPz5pX/QrW7OQwgPbCYnp
alz6apDw21iOyjdKubPDU19ANQFkvIvayIPuJ28BirO5VU9a3e7dQMuqvFbR
NKtY/VQmpPrdB2o99UsFWzEJVd+dKTl7ip26odsCx4K3PDOzw+GVN9BGfuCN
qoQ66u+1hSzRwf7x9YUPaBkqE8SlFW078Jy0lSizp8S4srNBBADGZch4/zc2
2+ZFej5jaBHxeB7Dq6aKKFbBSK9zYipre4xqFXgmuePEJHirdgO4sk0xAsCg
DbBgA8ByzTjqQhgXucFA1mLtOpi9GIRHZ0tN7XYfoPoAE1tsNR2AaLEFr2ea
6u83zqU2ErhpGI9supgRCyunfhMXxsoXki/qHNHS6wQA0zgB4eAClgoJ6nW8
K4yB1r3cfrGAedPEXP08Ckdds2ooTZXushgEEgcpOfhpQ7kcFl9LsqhKTTbA
Q4V9vXx3nCJ9LmFUNAvXX1Bno+0I/WFPERF0FrD37nCj10mINYjsSZGxr+p3
dalQRUtad/TeZlC/GDGgd5X+tZozfU1TFVED/jVmgROnkaMpHSDSqQm+NhKv
EXqQR0Oo3xHMzsgxKqwKBANVc66vD9uB5mgu+QrHzlRuEigjmTADsUicaGXW
dwDlogKBxEYdHh4ZJFNhTkbCN+uhGwbSwCvDm45JoiZUXnyO7mF93LOzm1A9
8/bE3DbqhsWkdpEooRhSWWinhb/OOCfNEUJvYiA8cnNhQGJvYi5jb20+wsCN
BBABCAAgBQJh3FsLBgsJBwgDAgQVCAoCBBYCAQACGQECGwMCHgEAIQkQprNm
Gnb2B9MWIQSC/Y9kL3SWdehfWSyms2YadvYH07hnB/9b31piilyTIdwRJAwA
eQVMQLBCyyZSPRLw+sUBoCfsfVs3k7J53OOelQzc5VCFSDbIG9TB1GvJ66Ai
EhsriMSAYPbqqGcgDDeH9cliiKO4Sq0LbIGyUdlhWtMuGJ3/qp3Sj4Q0VGOv
VCwmEUsR/GdsUlw3i8uaBdlad1ypUU0KrPYSSXxDJ17j7LB8DaXzuL/cJQeF
sUmzpkoaI292ARzn8kMH6vdnIaVAq6ArS5qOoNVPneFd+gH6NEOnev1eO1+3
lxRg/tMSs3ybW3eDWFtRlA9h5xSWDtJpBL5wODifNkhoL/eGiM5ZRxnbteLE
7ggNbfZk2Sn+USGU+KuaYlAVx8LYBGHcWwkBCACtf7FkxFcpE32qTYnMofxx
ztdAZvcx5LC5sTTLPv4tU+g2cvmvYfbS6GLgYdpT8zfH12xiThmRTGRJYPSS
LYA717dPEBBcRaTHgs7zLkuCthpMRPt0p0eI00n3h4wCvDrUkViyMbwob3X2
v6BiU8CWasVkyDdZNjMqox54OwGz8TCWFzBmuzVMXh23+zsQQevi1t6toFui
l6v6X0n/s491+X7JcwK91ovITMlOl/gZFR6nG56s4kB6XA7E3qDuBct9KIEo
CD5FIbFbTavxeFSGVxxn36VBQo6qadPIeWP0wilAZhw/nViEzWefzK16lYqq
o2xsk/HUJgwwH7RLRXNZABEBAAEAB/wOAEnHxLt27mJ8AZVe/OyDH6rJwPVu
YpLrbVRCGaOH82dAK5+gKmLxirzd+C+XCj/kYetWdJCGI/jM3iTmfgME8UfS
+swjMiCV1CXQxJnl4r21DXUQaSZx8YEc12SyXM/Pkyop+S8CwVnu73BpNvKK
APRMiYbD7YaMCI1fLP3acDiUUUmegkFyrnvU+ErcglgDw3pGX/2nUde5lBoq
mxMgJ+WouflvS/rJTTfY1FlOjAG0Ui2iUldgH3u7bziz+JikK2K+mtH8RVT6
DxFSKbmsw+/YneaW2meJvPhk/Nptpqtnfkw+oDk0gWmap9l8cnJhu9m404Zp
xw4yR6vOtZahBADRtNb8iVNQZqxFp8luUhFkSVCfJb/v3J2/B1fGVcukQlke
v0mnGHks6LBaICd1s+5PYYwJo1IDBESJfPSyAqa8RFoBuFU9m8VGXZrrPtYe
9jk5A+ZTK5Wu3F8n89c7Ygg3+GqTsbejO15r56G784UBUBTrKn/pqelnahQE
LqueKQQA08ymIjsyJJOaj4sTZdHw2iw9PXHEXn7VcD0Vr1zuTx8y2CyL7Rzq
jQBnrZvlp3EavqcvxHMffwPW7oEkdb2/YRXhokapO4qYuu/BbNZzaOiba5Yi
I9V3g24H23mShAiTJL1RVMoKpilSznUwqRNhejTZrfBrdpj8+xAWQpcFcbED
/02k8e28oPos/C4t55nkUbxaq9CTKFxQ0vNLL1bz5KgAgK8MntGHFs+ZvXXZ
9WdX48PeXRGqAc8G1cjE6ZoCLBYF5oDIx8G8ZuwFFISQeJHmgUi3leFYjK/l
sd+ZeEfPTWw4Xk0rQx3RRHKpqzE6HYXzceHRcjvVWtrmzEgiSgXMSVLCwHYE
GAEIAAkFAmHcWwsCGwwAIQkQprNmGnb2B9MWIQSC/Y9kL3SWdehfWSyms2Ya
dvYH05rAB/4mFtBaGmjuiTvpjOVht3Uo3hVBvwjN/fdvwaIINhAVkBSanvtl
n1/jbkGn3OCZQtoQZzDcwqlpky8O6qkltXya5GYlhd/btUOx7L7zt+WOpcFS
hXFZoWMB0ua9VcXjyQWefVrA0y9+AgL1phseJjelfM32rf0XegAedxKxNxOp
FraCqKUj088pjlLZsORJCsLOgugt7y4O9lf7fNiRo3I81LZsqegqdzcvCeK9
16th/tRiES/wUwhdVRvLACSGOVCGwsWs1KMJQeqqxxIxrxg0zv7yk17WIY/s
PBcqDCjq5jgMhU1oyVclRK7jJdmu0Azvwo2lleLAFLdCzHEXWXUz
=//ru
-----END PGP PRIVATE KEY BLOCK-----`;

    test('[unit][KeyUtil.parse] validates the private key if it is not encrypted', async t => {
      await t.throwsAsync(() => KeyUtil.parse(unencryptedCorruptedRsaKey), {
        instanceOf: Error,
        message: 'Key is invalid',
      });
      t.pass();
    });

    test('[unit][KeyUtil.readBinary] validates the private key if it is not encrypted', async t => {
      const binaryKey = (await PgpArmor.dearmor(unencryptedCorruptedRsaKey)).data;
      const { keys, err } = await KeyUtil.readBinary(binaryKey);
      expect(keys.length).to.equal(0);
      expect(err.length).to.equal(1);
      expect(err[0].message).to.equal('Key is invalid');
      t.pass();
    });

    test('[unit][KeyUtil.decrypt] correctly handles signing/encryption detection for PKSK with private keys', async t => {
      const dsakey = await KeyUtil.parse(dsaPrimaryKeyAndSubkeyBothHavePrivateKey);
      expect(await KeyUtil.decrypt(dsakey, '1234')).to.be.true;
      // DSA keys are no longer allowed
      expect(dsakey.usableForSigning).to.be.false;
      expect(dsakey.missingPrivateKeyForSigning).to.be.false;
      expect(dsakey.usableForEncryption).to.be.false;
      expect(dsakey.missingPrivateKeyForDecryption).to.be.false;
      const rsakey = await KeyUtil.parse(rsaPrimaryKeyAndSubkeyBothHavePrivateKey);
      expect(await KeyUtil.decrypt(rsakey, '1234')).to.be.true;
      expect(rsakey.usableForSigning).to.be.true;
      expect(rsakey.missingPrivateKeyForSigning).to.be.false;
      expect(rsakey.usableForEncryption).to.be.true;
      expect(rsakey.missingPrivateKeyForDecryption).to.be.false;
      t.pass();
    });

    test('[unit][KeyUtil.parse] determines PK missing private key for signing', async t => {
      // testing encrypted key
      const encryptedKey = await KeyUtil.parse(rsaPrimaryKeyIsMissingPrivateKey);
      expect(encryptedKey.usableForSigning).to.be.true;
      expect(encryptedKey.missingPrivateKeyForSigning).to.be.true;
      expect(encryptedKey.usableForEncryption).to.be.true;
      expect(encryptedKey.missingPrivateKeyForDecryption).to.be.false;
      expect(await KeyUtil.decrypt(encryptedKey, '1234')).to.be.true;
      const armoredKey = KeyUtil.armor(encryptedKey);
      // testing decrypted key
      const key = await KeyUtil.parse(armoredKey);
      expect(key.usableForSigning).to.be.true;
      expect(key.missingPrivateKeyForSigning).to.be.true;
      expect(key.usableForEncryption).to.be.true;
      expect(key.missingPrivateKeyForDecryption).to.be.false;
      t.pass();
    });

    test('[unit][KeyUtil.decrypt] determines PK missing private key for signing', async t => {
      const dsakey = await KeyUtil.parse(dsaPrimaryKeyIsMissingPrivateKey);
      expect(await KeyUtil.decrypt(dsakey, '1234')).to.be.true;
      // DSA keys are no longer allowed
      expect(dsakey.usableForSigning).to.be.false;
      expect(dsakey.missingPrivateKeyForSigning).to.be.false;
      expect(dsakey.usableForEncryption).to.be.false;
      expect(dsakey.missingPrivateKeyForDecryption).to.be.false;
      const rsakey = await KeyUtil.parse(rsaPrimaryKeyIsMissingPrivateKey);
      expect(await KeyUtil.decrypt(rsakey, '1234')).to.be.true;
      expect(rsakey.usableForSigning).to.be.true;
      expect(rsakey.missingPrivateKeyForSigning).to.be.true;
      expect(rsakey.usableForEncryption).to.be.true;
      expect(rsakey.missingPrivateKeyForDecryption).to.be.false;
      t.pass();
    });

    test('[unit][KeyUtil.parse] determines missing private key for encryption in expired key', async t => {
      const dsakey = await KeyUtil.parse(dsaExpiredPubkeysOnly);
      // DSA keys are no longer allowed
      expect(dsakey.usableForEncryptionButExpired).to.be.false;
      expect(dsakey.usableForSigningButExpired).to.be.false;
      expect(dsakey.usableForSigning).to.be.false;
      expect(dsakey.usableForEncryption).to.be.false;
      expect(dsakey.missingPrivateKeyForSigning).to.be.false;
      expect(dsakey.missingPrivateKeyForDecryption).to.be.false;
      const rsakey = await KeyUtil.parse(rsaExpiredPubkeysOnly);
      expect(rsakey.expiration).to.be.equal(1605971196000);
      expect(rsakey.usableForEncryptionButExpired).to.be.true;
      expect(rsakey.usableForSigningButExpired).to.be.true;
      expect(rsakey.usableForSigning).to.be.false;
      expect(rsakey.usableForEncryption).to.be.false;
      expect(rsakey.missingPrivateKeyForSigning).to.be.true;
      expect(rsakey.missingPrivateKeyForDecryption).to.be.true;
      t.pass();
    });

    test('[unit][KeyUtil.decrypt] handles PK missing private key for signing in expired key', async t => {
      const dsakey = await KeyUtil.parse(dsaExpiredPrimaryKeyIsMissingPrivateKey);
      expect(await KeyUtil.decrypt(dsakey, '1234')).to.be.true;
      // DSA keys are no longer allowed
      expect(dsakey.usableForEncryptionButExpired).to.be.false;
      expect(dsakey.usableForSigningButExpired).to.be.false;
      expect(dsakey.usableForSigning).to.be.false;
      expect(dsakey.usableForEncryption).to.be.false;
      expect(dsakey.missingPrivateKeyForSigning).to.be.false;
      expect(dsakey.missingPrivateKeyForDecryption).to.be.false;
      const rsakey = await KeyUtil.parse(rsaExpiredPrimaryKeyIsMissingPrivateKey);
      expect(await KeyUtil.decrypt(rsakey, '1234')).to.be.true;
      expect(rsakey.expiration).to.equal(1605971196000);
      expect(rsakey.usableForEncryptionButExpired).to.be.true;
      expect(rsakey.usableForSigningButExpired).to.be.true;
      expect(rsakey.usableForSigning).to.be.false;
      expect(rsakey.usableForEncryption).to.be.false;
      expect(rsakey.missingPrivateKeyForSigning).to.be.true;
      expect(rsakey.missingPrivateKeyForDecryption).to.be.false;
      t.pass();
    });

    test('[unit][KeyUtil.parseBinary] handles OpenPGP binary key', async t => {
      const key = Buffer.from(
        'mDMEX7JGnBYJKwYBBAHaRw8BAQdA8L8ZDEHJ3N8fojA1P0n9Tc2E0BTCl6AXq/b2ZoS5Evy0BlRl' +
          'c3QgMYiQBBMWCAA4FiEExOEH3ZJIrCG1lTnB5pbLkt3W1hMFAl+yRpwCGwMFCwkIBwIGFQoJCAsC' +
          'BBYCAwECHgECF4AACgkQ5pbLkt3W1hOHzAEAj3hiPLsaCeRGjLaYNvKNTetdfGLVSu2+cGMsHh8r' +
          '+pgBANNxQyqE5+3LjHhecVVNErbgr1n6vTurE5Jhc1Go3x8F',
        'base64'
      );
      const parsed = await KeyUtil.parseBinary(key, '');
      expect(parsed.length).to.be.equal(1);
      expect(parsed[0].id).to.be.equal('C4E107DD9248AC21B59539C1E696CB92DDD6D613');
      t.pass();
    });

    test('[unit][KeyUtil.parseBinary] handles PKCS#12 binary key', async t => {
      const key = Buffer.from(
        `MIIQqQIBAzCCEG8GCSqGSIb3DQEHAaCCEGAEghBcMIIQWDCCBo8GCSqGSIb3DQEHBqCCBoAwggZ8AgEAMIIGdQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIRH4NrqNQHA4CAggAgIIGSJW1vMxm5bcaOvPk7hoCKw3YTD+HBOI8LJ8YTYlFMHquJ9NvV0Ib/N0Y7NXP/KYERjaHwjy5cPvAtOWjyNRgVAe/r74TubRSVsizBWNbBKcpi8+Ani4jLCQ+zUeYKYqCYFfld/3NL/Ge0gB6K3TPacuWRdfGXk20htpyGbjZPuCXs1eYHQ6ekUvlpDaEA6n87Tkl4jF3xkz5nr8rfkvmZphvrLH/L6KiJX9wK6VqeTvowYukWQrdkklLVfxBWUdNHRxDqbUXZXkfCdixyKUlD4S9NbBqSbfgx9s951G23lUHnCBqdOzUqSFcLA7o0v0VrD5fYwuVk6tR8S63P3PJD5IrWgZV0hg4k8SVVZd++5khO61J6qBg8gGmYFclwc7itr8LxUCgSZUzJs0u+GGe9vM4IV2l3p/ywuimui21R9rWHExtvjJYkkpjkEcoqws40mQHQ6c8RLYmqGjC+WdqanJHBh8dFWQtZYISfLV2cFtg7ZOUot2LEIr9fZ1By+D+YudRUhzhk2/SPnQAay1zteXVPIzHqBjXIxR2LPd1YMadckEqTSlEz/9y0qukH2UE2RmW/GnjWVMSKZATfk7C1n4vSrw/7M+mVT0F7rjo3f1MObwzblkK9As96atdF/WWMyVZrN+xfltQscP+cCexpGSQi1I18lqTzcgIRye9dW1O3sCi7ygVQWfcweXq1f5CoknN76zxruiHFhOaqDKM1txcKdZJkQ6Lfmj1M6N+Hw3secHoOU/K21PNVLO+3/uRh04ebW9uweJA7aIHnypqzim47EBDCoquz0SMluYrEbSJKkNrjnAIadJ0s4UaYRV+dwh6ENY6lH8nWrYw54WMMxxIE80cpNoaf0lO6QDTdxY1mkFyNRQO5fbdsltMaemgyzct66UB38MkOawtRa0smd6MUuwaJlQ1tgBOpuuFX2ztojdeTmDQPgta3UPYv+rj3O1ePKBGBxsaq/aodIasLwYVCkpCtHJbzF+ILr3/a9h3QPbTrC5ysxfp8vteJFEBaU7UU2+LvY5tT+LI9YqBIxWOF4N+VnV+WFAv9WsrgfIE4VWYGxjDX6J8aw3Z/qGdqz7z7DcpcrDUKGo8/xQPogsA0x8QudWTEWdKhwdf+31UFoZiArrH5t4NPzsPikZzE+bCVZYwsKeE9nMfjNDxR+47G9lpOPfaX5fyryXWGofT19HMHbshBMtHoE80e7DSVrJr1odeN9iiOMC8EBr3l+HRaQ9JV90fylCvrempDGEWB/czljpWH+ud0pkHy5AT74zDp4OtwsisBsHI8x0kzA1pGnNhSGDOMdZ4cwC4N+GgfZ6/OIHpeDyiSvD5Xk2dT31U0CVrOK6KicaUwuLRkE+zSZNwnT/dNyawC61dhL1v2sAxGYti3pZ2sxHuEfdnassLQkkUEWXuS0WKgRc9q8oS296rsyD5wIrpU+jgUSNvrN1RLE879qT4MwKhOXI6StyVKtm9msVgrxe9bfOIeqHlK7emS/6dagR5kYoEECsOIDU7LfKnj+zXe6GzlxxIafN7h/g0HnPXfiGfM+z4spq95d7IBCMvI0of3+uFgACXN00l1iGm32NC0ZQ39+ZdQ//rSgxmZdSZhe6oKrgwJfxCjnaRPj7ky+T4Q2QQt4TLcDqrheEoc19rL8ueEo1rHMYbu9zwThPfswng7ZfWY5Fh1zxdhE2eUQA6pd2QRuzcW5o3cPS29dK9Yi4K3cwu/wUegkQJW2ON50K7bjMKt/3h0R0Zwi+lAx81NKvBNc2r7SI9dpGhpM2qkCQT0YMu+ZwlYXHfPjs2yCjL0vc3fWYSxRmmMEsLGIwSJHBbg6RCcJvlMxVOVK1v4GP70sga/gHRW8/+2HCwiVkmMkFqesNP/7GFYfbRvOzM8H6uooYicpFmeCSQxlK3beRHaO8EQo+iuwUDZQWz/4aQt4uOpUg6mt/cOD81BZ33TD9ttPynk5favdKMEzibL1QyIuZ54sGlBpTgGgHUHA9TmqdaNfVkGbAUXpoGRm7LjOZ3M+jNnHLG4TPOX7qyaYcHxoT+RSGEFvjXSvZXUsbbF0MGy3iAawAUHbqP6aiN1joeQ5duzqvlV5yswCStwCaXuuFkj1//BZn304aG5RUPw//5CAEIo7XQIvLoqjCCCcEGCSqGSIb3DQEHAaCCCbIEggmuMIIJqjCCCaYGCyqGSIb3DQEMCgECoIIJbjCCCWowHAYKKoZIhvcNAQwBAzAOBAgow96Pb9dRqgICCAAEgglIw41Sx1K7v1GHSdXd00xK6UlPnmO9fQcQACWq3Qp869er/ssLxXciqJ4Td4DUjh6utUF7Y9oh2gceUaYzmj4/6A1hV90ARBTlGnhw+xEBjKybti1pE7zdOG6TwOUDK02mLlwjaVLMLVx93P34etM0q7jroIWcmNrkwpGqjidc88CbV2N0dNhJxn6v0qgpZetMyjqNYfK/45nJxT4J1Xcldd2q7117eyYoLgc6Cu4py74S8ENtxjmT3zfreYanP35Ms6o/11i+cnvcNmIDqf9k1Qz3hlNd6bqTGghL11Mmc5CYjm7iCyY3lLlHixE4/QeKL6uZrqdK2uMYiRkbkLkGy85+AKrducNC09eXDAhyYRUZo5uSOnvLS/DcK/R27eXNZKnFHCiVmeZ4u5Z/vTmI3TcbmbZKFPvVJWcLYGeJXR67IiaEc9Up5YArr55fqHbMQWR4zBCWfuY/Xm26TKgI3yQiVIrXT4FnxMg29jQWt44y/BLsn1A/PrqtfkRci9Kn5MrAXfkN4/Dxkjw2Hyr9QUjJOxbPOFc3Er4/fzNImL4/3ESadRtQGqeZc6Ph/wXEC1wSU9IyP9MnWz9R8w/JaLbPIaviPnmT+TbZhO883a7EpugTReJRzFLwUKORTFBvB1qry8cH03ZouIUnjKjEKWTNaQSUuYiNCtR+tEAXWeBX/RwfIKpADeCJ1015bK2UXjV24FuShKZvyfGfMeWuTHOQ8a6Ugh5d8uhhYtDU081RS1dyaMRmRyLZz0f/Vzwbd6PfTRthd7v4WIueJKrqbgjMmf56s1nCiRqS614nHUXZ+U62qxn4DnIlYSpBBPpAfucUyZ4fxepb5qj3S3ZsmhF9CCK03RZtvY/s3w+aJXs4qq3d4h8oVozL1qeGszzu6OjpKAbGbaR8SsWb8GkRRfA4WEw6pWaxgSWNSro3YvwjljQ1Ab1oQTs/9F0VGWwDzA3k0meNfxtv4UfReWaUuMyqD2riRG9TW49tYNpRNDpsKXIEj+msZPvG5B9qvjj0Dg4OLVa5oI3oJkPC+X6jP+Ovm0m/N5KgDnPf3SCUrYwE8IJxIq3LiY4v4R0XJbLTGstfxrnKZ21wDzBZfrGTFWbRPoh/3SchmlC/v59/cLWY+VLzBT7vkQ+8PHnDj7tJZa47U/gibvDc4JgRbdkvlAJrA6Z8a1pEWcEJpxSLdQbuJ+ahA/sJvoPkGZ45jVhXAUn1HKeRsykwSNOZwkzhIKQ6deXOi12nTbY9EkPP2J3NMJkwoPlbVUEH+/IEJ/63qOQf+ihv0TwVBE48tl3WzuqlpDt23f/b617Lp7g6nUB9TGafBvUZCK08tJM4V9J8drtAN7hwMxSrr2Rpyy4na5ZweJv1j8XanSdP+X9qicBv1iNNj7wrr55MoGqCjse8WNqUZtdIRQ+k8cjlYPYs/ADCyXx0l2DEAczqSL15r/OnO5K3qYgfOE6o73cfZcWpJhyIDoshWV+EK9YWlxOmlYWUE+Zcx7+UsQs21xNqiVBzVJK+6Ax4GJmwDUYarMK1Cz02HgInIaGpP7DOtI//LcLh7sECP+moT/6KXIo60KNvMJEJlh3vrpl8AEK8nZ5xxPucyHX/XHo3o4PErfICHwaw7t5PQQ690PlAsa2bIrD4n5Aw6MKK23mx4KRYHBYWwRLXze6AmOHl6sHZ9sIO8w0IWGZtD3WU5wwAaXmgcjrIeUvaqpoLQZAiXIbgwfetPgjQI9NlLjaw6UK42NhYlg6e+Cr3HvcLRv/pJVS7HZZDPyBfJ0GYpkBzO0eze0OQR3+JvDKAxaQFVq/cb7Lf0aia0+a1bxnO+fh+cHHMnOVcUPlN7RPprF65vENjDzwPd4RRfT5ypQd0QqyMm2EzdXY9qzfcxmxh417vYEolXosmnyCY778dNSmJJIhXLfnqUNmyUBISjgidgH6Wl2L04HDCPjryybQz4JO6Dz8em80hG84spu2iSw56h7QaAesYj9tQhok4UX12MXsY1dl1bmTesukDXcfJjfv2BkDHVzlEncFffYoNKQaViABX+cgzJvAS6sGJPicUUl55et0AOsTDPZvvySbi3X5+Y+vvI1cwozEFbZkXdptWlmbIXRWuDtcDOsSTGMIhd2gJW4UyuJmc2UztuIa5x28YJGNPxYoG4TCcPd2V9gg1jL9tAUTwq9Jrel4Zp0Z8RY5uSRudso83Ap7a2WspvkDkHgIZ3p6DASkd+dzoVPObz5TLrNSioVU0p+bPPzI+Z0tavho9phqZq6g7HysETb5wVndoZOs78E9/kwHjyVibLI4ghB0EQSmkOxgT0RhQcNaMWCfbgTetZrtSEDFjTI3hmGRQ7T6ALicpiOE1T8m9IAwKkmC2n1vIZBfp/qSUa/B+SLZugoTKFcxbsXxqRvdgQJepF8F9qqNXXbtnXg7PX0TsEvRMjfOa7uPw+vlIc4g//svNU9XwYSC10J1KG3y1YUArbaJXXZGU+Mbliwe4n+kzQYbTpiUwX8WfSeZiFbCQgK0Qoqc1lMZ4tuJXfZyG2x+BtVsYIOLcnnxVIcM7FBdZ1fqRMuwxV2leiwqXFiCaAmh9dXZYz41FkD25UzAxwVlbvxskerehhDuEVlajY1py3f7dOKM3jwWF5Ftbvs50zlscyDNSjQtaDmBwx1TfR8kWwQjOI/zHu+gJOBxlm+SjxIEILOipaLEfq9/rV4AXIhyKq8fc2IkEYLKG89gPwAqi8dYDYpAWM/WjZjKwx3x31xwA7DLZycEzbl77favLfhDFOhsgZqFiG/4OhSk7/7en44Dyr/NXD/t4mRxAuhTajUt5V9SK6VuaquPNT7LJGQ8EnAYC74gE1IVIdR1KrDddNFocoq6GAlC7xoI62noYeEwcEfbzkTRKvu1b7+q+NS/0l/v8/iGmSPOPQ47BwbTGK/Tq2HnA8QYx4f2gi3X43ox7cy+GfGm7xOPmGbqJz1HDx3oCrDz0LiFXt0JKJ8XsfnbHHgD6P/TR19oQbVbhESt7OdftqwHTiBd7Cz+yg9nGp6znhGK/LOZlhFrb/E8dXPZOsj3s4/yf6ry8l/isKyfiBw5Y6i/aB9tSXrZ0sZ8NPSmyaSJbzolDfSV7MqSWZfwt7jv5P0RdOOy6G2knmXUcF3ys6uRKSNAlo3iC20kjRVbyPgZqBzi2MSUwIwYJKoZIhvcNAQkVMRYEFJ2NnbXtly3Wm4JXdJHjiCwHmr89MDEwITAJBgUrDgMCGgUABBSDibEh/MQX3YVQrTUgcjUCFtzaoQQIeNCS6r7MZ+wCAggA`,
        'base64'
      );
      const parsed = await KeyUtil.parseBinary(key, 'test');
      expect(parsed.length).to.be.equal(1);
      expect(parsed[0].id).to.be.equal('60EFFE4DF7B2114A77021459C273F0AA864AFF7F');
      expect(parsed[0].family).to.be.equal('x509');
      expect(parsed[0].emails.length).to.be.equal(1);
      expect(parsed[0].emails[0]).to.be.equal('test@example.com');
      expect(parsed[0].isPrivate).to.be.equal(true);
      expect(parsed[0].isPublic).to.be.equal(false);
      t.pass();
    });

    test('[unit][KeyUtil.parse] handles encrypted PKCS#8 key', async t => {
      const p8 = readFileSync('test/samples/smime/human-pwd-pem.txt', 'utf8');
      let parsed = await KeyUtil.parse(p8);
      expect(parsed.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsed.family).to.equal('x509');
      expect(parsed.emails.length).to.equal(1);
      expect(parsed.emails[0]).to.equal('human@flowcrypt.com');
      expect(parsed.isPrivate).to.equal(true);
      expect(parsed.isPublic).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(false);
      expect(KeyUtil.armor(parsed)).to.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(KeyUtil.armor(parsed)).to.not.include('-----BEGIN RSA PRIVATE KEY-----');
      expect(KeyUtil.armor(parsed)).to.not.include('-----BEGIN PRIVATE KEY-----');
      // incorrect passphrase will make the key remain encrypted
      expect(await KeyUtil.decrypt(parsed, 'incorrect')).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(false);
      expect(await KeyUtil.decrypt(parsed, 'AHbxhwquX5pc')).to.equal(true);
      expect(parsed.fullyDecrypted).to.equal(true);
      const armoredAfterDecryption = KeyUtil.armor(parsed);
      expect(armoredAfterDecryption).to.not.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(armoredAfterDecryption).to.include('-----BEGIN RSA PRIVATE KEY-----');
      parsed = await KeyUtil.parse(armoredAfterDecryption);
      expect(parsed.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsed.family).to.equal('x509');
      expect(parsed.emails.length).to.equal(1);
      expect(parsed.emails[0]).to.equal('human@flowcrypt.com');
      expect(parsed.isPrivate).to.equal(true);
      expect(parsed.isPublic).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(true);
      t.pass();
    });

    test('[unit][KeyUtil.parse] correctly handles shuffled certificates in PEM', async t => {
      const p8 = readFileSync('test/samples/smime/human-pwd-shuffled-pem.txt', 'utf8');
      let parsed = await KeyUtil.parse(p8);
      expect(parsed.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsed.family).to.equal('x509');
      expect(parsed.emails.length).to.equal(1);
      expect(parsed.emails[0]).to.equal('human@flowcrypt.com');
      expect(parsed.isPrivate).to.equal(true);
      expect(parsed.isPublic).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(false);
      expect(KeyUtil.armor(parsed)).to.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(KeyUtil.armor(parsed)).to.not.include('-----BEGIN RSA PRIVATE KEY-----');
      expect(KeyUtil.armor(parsed)).to.not.include('-----BEGIN PRIVATE KEY-----');
      // incorrect passphrase will make the key remain encrypted
      expect(await KeyUtil.decrypt(parsed, 'incorrect')).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(false);
      expect(await KeyUtil.decrypt(parsed, 'AHbxhwquX5pc')).to.equal(true);
      expect(parsed.fullyDecrypted).to.equal(true);
      const armoredAfterDecryption = KeyUtil.armor(parsed);
      expect(armoredAfterDecryption).to.not.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(armoredAfterDecryption).to.include('-----BEGIN RSA PRIVATE KEY-----');
      parsed = await KeyUtil.parse(armoredAfterDecryption);
      expect(parsed.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsed.family).to.equal('x509');
      expect(parsed.emails.length).to.equal(1);
      expect(parsed.emails[0]).to.equal('human@flowcrypt.com');
      expect(parsed.isPrivate).to.equal(true);
      expect(parsed.isPublic).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(true);
      t.pass();
    });

    test('[unit][KeyUtil.encrypt] encrypts S/MIME key', async t => {
      const p8 = readFileSync('test/samples/smime/human-unprotected-pem.txt', 'utf8');
      let parsed = await KeyUtil.parse(p8);
      expect(parsed.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsed.family).to.equal('x509');
      expect(parsed.emails.length).to.equal(1);
      expect(parsed.emails[0]).to.equal('human@flowcrypt.com');
      expect(parsed.isPrivate).to.equal(true);
      expect(parsed.isPublic).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(true);
      expect(KeyUtil.armor(parsed)).to.not.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(KeyUtil.armor(parsed)).to.include('-----BEGIN PRIVATE KEY-----');
      await KeyUtil.encrypt(parsed, 'new_passphrase');
      expect(parsed.fullyDecrypted).to.equal(false);
      const armoredAfterEncryption = KeyUtil.armor(parsed);
      expect(armoredAfterEncryption).to.include('-----BEGIN ENCRYPTED PRIVATE KEY-----');
      expect(armoredAfterEncryption).to.not.include('-----BEGIN RSA PRIVATE KEY-----');
      expect(armoredAfterEncryption).to.not.include('-----BEGIN PRIVATE KEY-----');
      parsed = await KeyUtil.parse(armoredAfterEncryption);
      expect(parsed.id).to.equal('9B5FCFF576A032495AFE77805354351B39AB3BC6');
      expect(parsed.family).to.equal('x509');
      expect(parsed.emails.length).to.equal(1);
      expect(parsed.emails[0]).to.equal('human@flowcrypt.com');
      expect(parsed.isPrivate).to.equal(true);
      expect(parsed.isPublic).to.equal(false);
      expect(parsed.fullyDecrypted).to.equal(false);
      t.pass();
    });

    test('[unit][SmimeKey.decryptMessage] decrypts an armored S/MIME PKCS#7 message', async t => {
      const p8 = readFileSync('test/samples/smime/human-unprotected-pem.txt', 'utf8');
      const privateSmimeKey = await KeyUtil.parse(p8);
      const publicSmimeKey = await KeyUtil.asPublicKey(privateSmimeKey);
      const text = 'this is a text to be encrypted';
      const buf = Buf.with((await MsgUtil.encryptMessage({ pubkeys: [publicSmimeKey], data: Buf.fromUtfStr(text), armor: true })).data);
      const encryptedMessage = buf.toRawBytesStr();
      expect(encryptedMessage).to.include(PgpArmor.headers('pkcs7').begin);
      const p7 = SmimeKey.readArmoredPkcs7Message(buf);
      expect(p7.type).to.equal(ENVELOPED_DATA_OID);
      const decrypted = SmimeKey.decryptMessage(p7 as forge.pkcs7.PkcsEnvelopedData, privateSmimeKey);
      const decryptedMessage = Buf.with(decrypted).toRawBytesStr();
      expect(decryptedMessage).to.equal(text);
      t.pass();
    });

    test(`[unit][KeyUtil.parse] orders primary uids first`, async t => {
      const armoredPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

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
3zbO9HlycA+1PReoJyHlCgPPtTbEDIEB
=6lFO
-----END PGP PRIVATE KEY BLOCK-----`;
      const armoredPublicKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=hLUh
-----END PGP PUBLIC KEY BLOCK-----`;
      const pubKey = await KeyUtil.parse(armoredPublicKey);
      expect(pubKey.identities.length).to.equal(2);
      expect(pubKey.identities[0]).to.equal('First <first@example.com>');
      expect(pubKey.identities[1]).to.equal('Second <second@example.com>');
      expect(pubKey.emails.length).to.equal(2);
      expect(pubKey.emails[0]).to.equal('first@example.com');
      expect(pubKey.emails[1]).to.equal('second@example.com');
      const prvKey = await KeyUtil.parse(armoredPrivateKey);
      expect(prvKey.identities.length).to.equal(2);
      expect(prvKey.identities[0]).to.equal('First <first@example.com>');
      expect(prvKey.identities[1]).to.equal('Second <second@example.com>');
      expect(prvKey.emails.length).to.equal(2);
      expect(prvKey.emails[0]).to.equal('first@example.com');
      expect(prvKey.emails[1]).to.equal('second@example.com');
      t.pass();
    });

    test(`[unit][OpenPGPKey.parse] sets usableForEncryption and usableForSigning to false for RSA key less than 2048`, async t => {
      const key1 = await KeyUtil.parse(testConstants.rsa1024secret);
      expect(key1.usableForEncryption).to.equal(false);
      expect(key1.usableForSigning).to.equal(false);
      expect(key1.usableForEncryptionButExpired).to.equal(false);
      expect(key1.usableForSigningButExpired).to.equal(false);
      expect(key1.missingPrivateKeyForDecryption).to.equal(false);
      expect(key1.missingPrivateKeyForSigning).to.equal(false);
      const key2 = await KeyUtil.parse(testConstants.rsa1024public);
      expect(key2.usableForEncryption).to.equal(false);
      expect(key2.usableForSigning).to.equal(false);
      expect(key2.usableForEncryptionButExpired).to.equal(false);
      expect(key2.usableForSigningButExpired).to.equal(false);
      expect(key2.missingPrivateKeyForDecryption).to.equal(false);
      expect(key2.missingPrivateKeyForSigning).to.equal(false);
      t.pass();
    });

    test(`[unit][OpenPGPKey.parse] sets usableForEncryption and usableForSigning to false for primary RSA1024 key and RSA4096 subkey`, async t => {
      const key1 = await KeyUtil.parse(testConstants.rsa1024primary4096subkeySecret);
      expect(key1.usableForEncryption).to.equal(false);
      expect(key1.usableForSigning).to.equal(false);
      expect(key1.usableForEncryptionButExpired).to.equal(false);
      expect(key1.usableForSigningButExpired).to.equal(false);
      expect(key1.missingPrivateKeyForDecryption).to.equal(false);
      expect(key1.missingPrivateKeyForSigning).to.equal(false);
      const key2 = await KeyUtil.parse(testConstants.rsa1024primary4096subkeyPublic);
      expect(key2.usableForEncryption).to.equal(false);
      expect(key2.usableForSigning).to.equal(false);
      expect(key2.usableForEncryptionButExpired).to.equal(false);
      expect(key2.usableForSigningButExpired).to.equal(false);
      expect(key2.missingPrivateKeyForDecryption).to.equal(false);
      expect(key2.missingPrivateKeyForSigning).to.equal(false);
      t.pass();
    });

    test(`[unit][OpenPGPKey.parse] sets usableForEncryption to false and usableForSigning to true for 2048/RSA PK and 1024/RSA SK`, async t => {
      const key = await KeyUtil.parse(testConstants.rsa1024subkeyOnly);
      expect(key.usableForEncryption).to.equal(false);
      expect(key.usableForSigning).to.equal(true);
      expect(key.usableForEncryptionButExpired).to.equal(false);
      expect(key.usableForSigningButExpired).to.equal(false);
      expect(key.missingPrivateKeyForDecryption).to.equal(false);
      expect(key.missingPrivateKeyForSigning).to.equal(false);
      t.pass();
    });

    test(`[unit][OpenPGPKey.decrypt] sets usableForEncryption to false and usableForSigning to true for 2048/RSA PK and 1024/RSA SK`, async t => {
      const key = await KeyUtil.parse(testConstants.rsa1024subkeyOnlyEncrypted);
      expect(key.usableForEncryption).to.equal(false);
      expect(key.usableForSigning).to.equal(true);
      expect(key.usableForEncryptionButExpired).to.equal(false);
      expect(key.usableForSigningButExpired).to.equal(false);
      expect(key.missingPrivateKeyForDecryption).to.equal(false);
      expect(key.missingPrivateKeyForSigning).to.equal(false);
      expect(await KeyUtil.decrypt(key, '1234')).to.be.true;
      expect(key.usableForEncryption).to.equal(false);
      expect(key.usableForSigning).to.equal(true);
      expect(key.usableForEncryptionButExpired).to.equal(false);
      expect(key.usableForSigningButExpired).to.equal(false);
      expect(key.missingPrivateKeyForDecryption).to.equal(false);
      expect(key.missingPrivateKeyForSigning).to.equal(false);
      t.pass();
    });

    test(`[unit][PgpArmor.dearmor] throws on incorrect sequence`, async t => {
      await expect(
        PgpArmor.dearmor(`-----BEGIN PGP MESSAGE-----

AAAAAAAAAAAAAAAAzzzzzzzzzzzzzzzzzzzzzzzzzzzz.....`)
      ).to.eventually.be.rejectedWith('Misformed armored text');
      t.pass();
    });

    test(`[unit][PgpArmor.dearmor] correctly handles long string`, async t => {
      const source = Buffer.from('The test string concatenated many times to produce large output'.repeat(100000));
      const type = 3;
      const armored = PgpArmor.armor(type, source);
      const dearmored = await PgpArmor.dearmor(armored);
      expect(dearmored.type).to.equal(type);
      equals(dearmored.data, source);
      t.pass();
    });

    test(`[unit][PgpArmor.clipIncomplete] correctly handles all the cases`, async t => {
      expect(PgpArmor.clipIncomplete('')).to.be.an.undefined;
      expect(PgpArmor.clipIncomplete('plain text')).to.be.an.undefined;
      expect(PgpArmor.clipIncomplete('prefix -----BEGIN PGP MESSAGE-----\n\nexample')).to.equal('-----BEGIN PGP MESSAGE-----\n\nexample');
      t.pass();
    });

    test(`[unit][ExpirationCache] entry expires after configured interval`, async t => {
      const cache = new ExpirationCache(2000); // 2 seconds
      cache.set('test-key', 'test-value');
      expect(cache.get('test-key')).to.equal('test-value');
      await Util.sleep(2);
      expect(cache.get('test-key')).to.be.an('undefined');
      t.pass();
    });

    test(`[unit][Str] splitAlphanumericExtended returns all parts extendec till the end of the original string`, async t => {
      expect(Str.splitAlphanumericExtended('part1.part2@part3.part4')).to.eql(['part1.part2@part3.part4', 'part2@part3.part4', 'part3.part4', 'part4']);
      t.pass();
    });

    test(`[unit][MsgUtil.verifyDetached] VerifyRes contains signer longids`, async t => {
      const prv = await KeyUtil.parse(rsaPrimaryKeyAndSubkeyBothHavePrivateKey);
      await KeyUtil.decrypt(prv, '1234');
      const plaintext = 'data to sign';
      const sigText = await MsgUtil.sign(prv, plaintext, true);
      const verifyRes = await MsgUtil.verifyDetached({ plaintext, sigText, verificationPubs: [] });
      expect(verifyRes.signerLongids.length).to.equal(1);
      expect(verifyRes.signerLongids[0]).to.equal(KeyUtil.getPrimaryLongid(prv));
      t.pass();
    });

    test(`[unit][MsgUtil.sign(detached=false)] creates a cleartext signed message`, async t => {
      const prv = await KeyUtil.parse(rsaPrimaryKeyAndSubkeyBothHavePrivateKey);
      await KeyUtil.decrypt(prv, '1234');
      const plaintext = 'data to sign';
      const signedData = await MsgUtil.sign(prv, plaintext, false);
      expect(signedData).to.not.include(PgpArmor.headers('encryptedMsg').begin);
      expect(signedData).to.include(PgpArmor.headers('signedMsg').begin);
      expect(signedData).to.include(plaintext);
      const decrypted = await MsgUtil.decryptMessage({
        kisWithPp: [],
        encryptedData: signedData,
        verificationPubs: [KeyUtil.armor(await KeyUtil.asPublicKey(prv))],
      });
      expect(decrypted.success).to.be.true;
      if (decrypted.success) {
        const verifyRes = decrypted.signature;
        expect(verifyRes?.match).to.be.true;
        expect(verifyRes?.signerLongids.length).to.equal(1);
        expect(verifyRes?.signerLongids[0]).to.equal(KeyUtil.getPrimaryLongid(prv));
      }
      t.pass();
    });
  }
};
