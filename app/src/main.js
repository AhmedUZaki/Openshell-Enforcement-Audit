const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("node:path");
const {
  listSandboxes,
  runAttempt,
  listResults,
  createSandbox,
  getInstalledOpenShellVersion,
  listOpenShellVersions,
  createProtectedFolder,
  listDirectory,
  computeEffectivePermission,
  getActivePolicy,
  runNetworkTest,
  previewNetworkExpectation,
} = require("./runner");
const { commandEvents } = require("./wsl");

function createWindow() {
  const win = new BrowserWindow({
    width: 1100,
    height: 820,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, "..", "index.html"));

  // Every command this app runs is forwarded live to this window's
  // renderer for the "Command activity" log -- each command keeps its own
  // id from start to finish, so the log can match a reply to its command
  // even with several running at once.
  const onStart = (evt) => {
    if (!win.isDestroyed()) win.webContents.send("command:start", evt);
  };
  const onUpdate = (evt) => {
    if (!win.isDestroyed()) win.webContents.send("command:update", evt);
  };
  const onFinish = (evt) => {
    if (!win.isDestroyed()) win.webContents.send("command:finish", evt);
  };
  commandEvents.on("start", onStart);
  commandEvents.on("update", onUpdate);
  commandEvents.on("finish", onFinish);
  win.on("closed", () => {
    commandEvents.off("start", onStart);
    commandEvents.off("update", onUpdate);
    commandEvents.off("finish", onFinish);
  });
}

// One running copy only. The per-sandbox locks (a test and a delete-and-
// recreate of the same sandbox must never overlap) live inside this process,
// so a second copy would bypass them. A second launch just brings the first
// window to the front.
const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
} else {
  app.on("second-instance", () => {
    const [win] = BrowserWindow.getAllWindows();
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });
}

app.whenReady().then(() => {
  if (!gotSingleInstanceLock) return;
  ipcMain.handle("sandboxes:list", async () => listSandboxes());
  ipcMain.handle("attempt:run", async (_event, params) => runAttempt(params));
  ipcMain.handle("results:list", async () => listResults());
  ipcMain.handle("sandbox:create", async (_event, params) => createSandbox(params));
  ipcMain.handle("openshell:version", async () => getInstalledOpenShellVersion());
  ipcMain.handle("openshell:versions", async () => listOpenShellVersions());
  ipcMain.handle("folder:create", async (_event, params) => createProtectedFolder(params));
  ipcMain.handle("directory:list", async (_event, { sandboxName, dirPath }) => listDirectory(sandboxName, dirPath));
  ipcMain.handle("permission:compute", async (_event, { sandboxName, targetPath }) => computeEffectivePermission(sandboxName, targetPath));
  ipcMain.handle("policy:get", async (_event, { sandboxName }) => getActivePolicy(sandboxName));
  ipcMain.handle("network:run", async (_event, params) => runNetworkTest(params));
  ipcMain.handle("network:expect", async (_event, params) => previewNetworkExpectation(params));

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
