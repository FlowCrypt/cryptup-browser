# 🌐 FlowCrypt Browser Extension (Encrypt Gmail with PGP)

| 👋 Try our extension                                                                                                           |
|:-------------------------------------------------------------------------------------------------------------------------------|
| ⬇ Download the FlowCrypt Browser Extension on your device from the [FlowCrypt Downloads](https://flowcrypt.com/download) page. |

## 💻 Developers

![Mock tests](https://flowcrypt.semaphoreci.com/badges/flowcrypt-browser.svg?key=d575b4ff-e35d-4217-9152-27cea9e72c19)

We develop the project in TypeScript. However, since browsers only understand JavaScript, the project needs to be transpiled to it. You need to build the project the first time you download/clone it, and then build it again after each change you make to see the result in the browser. To get started, please follow the instructions below:

1. Navigate to the project folder and install the tooling by running the following commands:

```bash
# 1. Navigate to the appropriate folder
$ cd some/folder/flowcrypt-browser
# 2. Install the tooling
$ npm install
```

2. To build the project, run the following command:

```bash
$ npm run build
```

- For building project on Windows we recommend to use [Cygwin](https://www.cygwin.com/) with rsync package.

After executing the build command, you can find your built project in the `build/chrome-consumer` and `build/firefox-consumer` folders.

> ℹ️ Note: The `build` folder also contains other versions of the browser extension.

✔️ To load the extension in Google Chrome, please follow these steps:

1. Open your Chrome browser and navigate to `chrome://extensions/`.
2. If it isn't already enabled, toggle on the **Developer mode**. The switch button is located at the top-right corner.
3. Click on the **Load unpacked** button.
4. Browse to the `flowcrypt-browser/build` folder and select the appropriate project version, either `chrome-consumer` or `chrome-enterprise`.

✔️ To load the extension in Firefox, please follow these steps:

1. Open your Firefox browser and navigate to `about:debugging`.
2. Click on the **This Firefox** tab.
3. Click on the **Load Temporary Add-on** button located at the top-right corner.
4. Browse to the `flowcrypt-browser/build` folder, open the `firefox-consumer` project version folder, and select the `manifest.json` file.

If you wish, you can also use the `run_firefox` script (`npm run run_firefox`) included in the `package.json` file to run the Firefox extension in a separate instance without interfering with the production extension installed in your browser.

Printing debug data to test logs can be accomplished using a [special Debug class](https://github.com/FlowCrypt/flowcrypt-browser/tree/master/extension/js/common/platform/debug.ts#L7).

## 📚 Other guides

- [FlowCrypt Project Structure and Overview](https://github.com/FlowCrypt/flowcrypt-browser/wiki/FlowCrypt-Project-Structure-and-Overview)
- [FlowCrypt TypeScript Style Guide](https://github.com/FlowCrypt/flowcrypt-browser/wiki/FlowCrypt-TypeScript-Style-Guide)
- [Running tests locally](https://github.com/FlowCrypt/flowcrypt-browser/wiki/Running-tests-locally)
