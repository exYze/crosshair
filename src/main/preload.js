const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("aip", {
  loadSettings: () => ipcRenderer.invoke("settings:load"),
  saveSettings: (settings) => ipcRenderer.invoke("settings:save", settings),
  testDatabase: () => ipcRenderer.invoke("db:test"),
  testApi: () => ipcRenderer.invoke("api:test"),
  loadAttackKnowledge: () => ipcRenderer.invoke("attack:knowledge"),
  loadAttackPhases: () => ipcRenderer.invoke("attack:phases"),
  loadReconTools: () => ipcRenderer.invoke("recon:tools"),
  loadEmptyNetwork: () => ipcRenderer.invoke("network:empty"),
  loadStartupDependencies: () => ipcRenderer.invoke("startup:dependencies"),
  runScan: (payload) => ipcRenderer.invoke("scan:run", payload),
  sendChat: (payload) => ipcRenderer.invoke("chat:send", payload),
  streamChat: (payload, onEvent) => {
    const listener = (_event, message) => {
      if (message?.requestId === payload.requestId) onEvent(message);
    };
    ipcRenderer.on("chat:stream:event", listener);
    ipcRenderer.send("chat:stream:start", payload);
    return () => ipcRenderer.removeListener("chat:stream:event", listener);
  },
  confirmAction: (payload) => ipcRenderer.invoke("operator:confirm", payload)
});
