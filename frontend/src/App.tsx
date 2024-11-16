import axios from "axios";
import { useEffect, useState } from "react";
import "./App.css"; // Import the CSS file

function App() {
  const [status, setStatus] = useState("Stopped");
  const [summary, setSummary] = useState<string[]>([]);
  const [message, setMessage] = useState("");

  useEffect(() => {
    getStatus();
  }, []);

  const startCapture = async () => {
    try {
      await axios.get("http://localhost:8000/start_capture");
      setStatus("Capturing");
      setMessage("Packet capture started.");
    } catch (error) {
      console.error("Failed to start capture:", error);
    }
  };

  const stopCapture = async () => {
    try {
      await axios.get("http://localhost:8000/stop_capture");
      setStatus("Stopped");
      setMessage("Packet capture stopped.");
    } catch (error) {
      console.error("Failed to stop capture:", error);
    }
  };

  const getStatus = async () => {
    try {
      const response = await axios.get("http://localhost:8000/status");
      setStatus(response.data.status);
    } catch (error) {
      console.error("Failed to fetch status:", error);
    }
  };

  const getSummary = async () => {
    try {
      const response = await axios.get("http://localhost:8000/summary");
      setSummary(response.data.summary);
      setMessage("Capture summary fetched.");
    } catch (error) {
      console.error("Failed to fetch summary:", error);
    }
  };

  const saveCapture = async () => {
    try {
      const response = await axios.post("http://localhost:8000/save_capture", {
        filename: "captured_packets.json",
      });
      setMessage(response.data.status);
    } catch (error) {
      console.error("Failed to save capture:", error);
    }
  };

  const loadCapture = async () => {
    try {
      const response = await axios.post("http://localhost:8000/load_capture", {
        filename: "captured_packets.json",
      });
      setSummary(response.data.packets);
      setMessage("Packets loaded from file.");
    } catch (error) {
      console.error("Failed to load capture:", error);
    }
  };

  const resetCapture = async () => {
    try {
      const response = await axios.post("http://localhost:8000/reset_capture");
      setSummary([]);
      setMessage(response.data.status);
    } catch (error) {
      console.error("Failed to reset capture:", error);
    }
  };

  return (
    <div className="container">
      <h1 className="header">Netcapx - Packet Capture</h1>
      <p className="status">
        Status: <strong>{status}</strong>
      </p>
      <div className="button-container">
        <button className="button" onClick={startCapture}>
          Start Capture
        </button>
        <button className="button" onClick={stopCapture}>
          Stop Capture
        </button>
        <button className="button" onClick={getSummary}>
          Get Summary
        </button>
        <button className="button" onClick={saveCapture}>
          Save Capture
        </button>
        <button className="button" onClick={loadCapture}>
          Load Capture
        </button>
        <button className="button" onClick={resetCapture}>
          Reset Capture
        </button>
      </div>

      <div className="message-box">
        <h2 className="section-header">Message</h2>
        <p>{message}</p>
      </div>

      <div className="summary-box">
        <h2 className="section-header">Capture Summary</h2>
        <ul>
          {summary.length > 0 ? (
            summary.map((item, index) => <li key={index}>{item}</li>)
          ) : (
            <p>No packets captured.</p>
          )}
        </ul>
      </div>
    </div>
  );
}

export default App;
