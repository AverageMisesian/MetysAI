const { app, BrowserWindow, Menu } = require('electron');
const path = require('path');

function createWindow() {
  const win = new BrowserWindow({
    width: 1000,
    height: 800,
    icon: path.join(__dirname, 'icon.png'),
    title: 'MetysAI - Disassembler',
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
    },
  });
  
  // Remove the default menu (including Help)
  Menu.setApplicationMenu(null);
  
  win.loadFile('index.html');
}

app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
}); 