const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("audit", {
  listSandboxes: () => ipcRenderer.invoke("sandboxes:list"),
  runAttempt: (params) => ipcRenderer.invoke("attempt:run", params),
  listResults: () => ipcRenderer.invoke("results:list"),
  createSandbox: (params) => ipcRenderer.invoke("sandbox:create", params),
  getOpenShellVersion: () => ipcRenderer.invoke("openshell:version"),
  listOpenShellVersions: () => ipcRenderer.invoke("openshell:versions"),
  createProtectedFolder: (params) => ipcRenderer.invoke("folder:create", params),
  listDirectory: (sandboxName, dirPath) => ipcRenderer.invoke("directory:list", { sandboxName, dirPath }),
  computeEffectivePermission: (sandboxName, targetPath) => ipcRenderer.invoke("permission:compute", { sandboxName, targetPath }),
  getActivePolicy: (sandboxName) => ipcRenderer.invoke("policy:get", { sandboxName }),
  runNetworkTest: (params) => ipcRenderer.invoke("network:run", params),
  previewNetworkExpectation: (params) => ipcRenderer.invoke("network:expect", params),

  // Live command-activity feed: each callback fires once per event, with
  // the running count of listeners managed by the renderer.
  onCommandStart: (cb) => {
    const handler = (_event, evt) => cb(evt);
    ipcRenderer.on("command:start", handler);
    return () => ipcRenderer.removeListener("command:start", handler);
  },
  onCommandUpdate: (cb) => {
    const handler = (_event, evt) => cb(evt);
    ipcRenderer.on("command:update", handler);
    return () => ipcRenderer.removeListener("command:update", handler);
  },
  onCommandFinish: (cb) => {
    const handler = (_event, evt) => cb(evt);
    ipcRenderer.on("command:finish", handler);
    return () => ipcRenderer.removeListener("command:finish", handler);
  },
});
