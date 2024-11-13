import { app, BrowserWindow } from "electron";
import path from "path";

let mainWindow: BrowserWindow | null;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, "preload.js"),
            nodeIntegration: true,
            contextIsolation: false,
        },
    });

    // Load the frontend URL, and provide feedback if it fails
    mainWindow.loadURL("http://localhost:3000").catch(() => {
        console.error("Failed to load http://localhost:3000. Is the server running?");
    });

    mainWindow.on("closed", () => {
        mainWindow = null;
    });
}

// Ensure app reopens correctly on macOS
app.whenReady().then(() => {
    createWindow();

    app.on("activate", () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

// Quit the app when all windows are closed (except on macOS)
app.on("window-all-closed", () => {
    if (process.platform !== "darwin") app.quit();
});
